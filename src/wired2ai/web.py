"""Small GET-only web collector with explicit origins and bounded redirects."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from . import __version__
from .report import Report
from .runner import Runner

SECRET_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate"}


def validate_url(url: str) -> str:
    if len(url) > 4096 or any(ord(char) <= 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise ValueError("URL contains whitespace/control characters, backslashes, or exceeds 4096 characters")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL authority or port") from exc
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("Only explicit http:// and https:// URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are rejected")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to servers; remove the fragment")
    if port == 0:
        raise ValueError("Port 0 is not supported")
    if "%" in parsed.netloc or any(char in parsed.netloc for char in "{}[]") and ":" not in host:
        raise ValueError("Ambiguous URL authority")
    decoded = unquote(parsed.path)
    if re.search(r"%[0-9a-fA-F]{2}", decoded):
        raise ValueError("Nested percent-encoded paths are not supported")
    if "\\" in decoded or any(part in {".", ".."} for part in decoded.split("/")) or any(ord(c) < 32 for c in decoded):
        raise ValueError("Dot segments or encoded control characters in URL paths are rejected")
    host = host.encode("idna").decode("ascii").lower()
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="%/:?@!$&'()*+,;=-._~")
    return urlunsplit((parsed.scheme.lower(), authority, path, query, ""))


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def display_url(url: str) -> str:
    parsed = urlsplit(url)
    # Query values often carry tokens without recognizable parameter names.
    query = "&".join(part.split("=", 1)[0] + "=[REDACTED]" for part in parsed.query.split("&")) if parsed.query else ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def parse_http(raw: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    for _ in range(6):
        boundary = raw.find(b"\r\n\r\n")
        if boundary < 0:
            raise ValueError("Incomplete HTTP response headers")
        lines = raw[:boundary].decode("iso-8859-1").split("\r\n")
        match = re.fullmatch(r"HTTP/\S+\s+(\d{3})(?:\s+.*)?", lines[0])
        if not match:
            raise ValueError("Invalid HTTP status line")
        status = int(match.group(1))
        headers = []
        for line in lines[1:]:
            if ":" not in line or line.startswith((" ", "\t")):
                raise ValueError("Malformed or folded response header")
            name, value = line.split(":", 1)
            headers.append((name.lower(), value.strip()))
        raw = raw[boundary + 4:]
        if 100 <= status < 200 and status != 101:
            continue
        return status, headers, raw
    raise ValueError("Too many interim HTTP responses")


@dataclass
class Response:
    url: str
    status: str
    http_status: int | None
    headers: list[tuple[str, str]]
    body: bytes
    refs: list[str]
    note: str = ""

    def header(self, name: str) -> str:
        return next((value for key, value in self.headers if key == name.lower()), "")


class WebClient:
    def __init__(self, target: str, report: Report, runner: Runner, workdir: Path, max_requests=10):
        self.target = validate_url(target)
        self.origin = origin(self.target)
        parsed = urlsplit(self.target)
        self.base_path = parsed.path.rsplit("/", 1)[0] + "/"
        self.base = urlunsplit((parsed.scheme, parsed.netloc, self.base_path, "", ""))
        self.report, self.runner, self.workdir = report, runner, workdir
        self.max_requests = max_requests
        self.requests = 0

    def allowed(self, url: str) -> bool:
        return origin(url) == self.origin and unquote(urlsplit(url).path).startswith(unquote(self.base_path))

    def get(self, url: str, follow=True) -> Response:
        refs = []
        for hop in range(4):
            try:
                url = validate_url(url)
            except ValueError as exc:
                return Response(url, "skipped", None, [], b"", refs, str(exc))
            if not self.allowed(url):
                return Response(url, "skipped", None, [], b"", refs, "Redirect/request left the original origin or directory scope")
            if self.requests >= self.max_requests:
                return Response(url, "skipped", None, [], b"", refs, "Run request budget exhausted")
            self.requests += 1
            version = self.runner.version("curl", self.workdir)
            args = ["curl", "--disable", "--silent", "--show-error", "--include", "--globoff",
                    "--proto", "=http,https", "--noproxy", "*", "--max-time", str(self.runner.timeout),
                    "--connect-timeout", str(min(5, self.runner.timeout)), "--max-filesize", str(self.runner.max_output),
                    "--header", "Accept-Encoding: identity", "--user-agent", f"wired2ai/{__version__}", "--", url]
            result = self.runner.run(args, self.workdir)
            try:
                code, headers, body = parse_http(result.stdout_bytes)
            except ValueError as exc:
                code, headers, body = None, [], b""
                error = str(exc)
            else:
                error = ""
            status = result.status
            if result.returncode == 28:
                status = "timeout"
            elif result.returncode == 63:  # curl's body-size guard
                status = "partial"
            if code is None and status == "complete":
                status = "failed"
            safe_headers = []
            for name, value in headers:
                if name in SECRET_HEADERS:
                    value = "[REDACTED]"
                elif name == "location":
                    value = display_url(urljoin(url, value))
                safe_headers.append([name, value])
            ref = self.report.observation("http_response", {
                "method": "GET", "url": display_url(url), "tool_version": version,
                "status": status, "http_status": code, "headers": safe_headers,
                "body_excerpt_bytes": len(body), "body_excerpt_sha256": hashlib.sha256(body).hexdigest(),
                "body_complete": status == "complete", "duration_ms": result.duration_ms,
                "returncode": result.returncode, "error": error,
                "stderr": result.stderr.replace(url, display_url(url)),
                "body_retention": "Raw body not exported. Only selected structural observations are retained.",
            })
            refs.append(ref)
            response = Response(url, status, code, headers, body, refs, error)
            if follow and code in {301, 302, 303, 307, 308} and response.header("location"):
                if status != "complete":
                    return response
                if hop == 3:
                    response.status, response.note = "partial", "Redirect limit reached"
                    return response
                url = urljoin(url, response.header("location"))
                continue
            return response
        raise AssertionError("Redirect loop should always terminate")


class HTMLSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.scripts, self.comments = [], [], []
        self.title = ""
        self.in_title = False
        self.comment_count = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "form" and len(self.forms) < 30:
            self.forms.append({"method": values.get("method", "get"),
                               "action": display_url(values.get("action") or "")})
        elif tag == "script" and values.get("src") and len(self.scripts) < 40:
            self.scripts.append(display_url(values["src"]))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:200]

    def handle_comment(self, data):
        self.comment_count += 1
        # Comments can contain secrets; count them without copying their contents.


def exposure_assessment(response: Response, baseline: Response, kind: str) -> dict:
    data = {"http_status": response.http_status, "classification": "not_confirmed"}
    if response.status != "complete":
        data["reason"] = "Incomplete or failed response cannot validate exposure"
        return data
    if response.http_status != 200:
        data["reason"] = "Expected content was not returned with HTTP 200; this does not prove absence"
        return data
    if baseline.status != "complete" or baseline.http_status is None:
        data["classification"] = "inconclusive"
        data["reason"] = "Negative-control request did not complete"
        return data
    if response.body == baseline.body:
        data["classification"] = "inconclusive"
        data["reason"] = "Body matches the random missing-path response (possible soft 404)"
        return data
    text = response.body.decode("utf-8", "replace")
    if "html" in response.header("content-type").lower() or re.search(r"<\s*(?:html|!doctype)", text, re.I):
        data["reason"] = "HTML response is not the expected artifact"
        return data
    if kind == "git":
        if re.fullmatch(r"(?:ref: refs/[A-Za-z0-9._/-]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s*", text):
            data.update(classification="content_consistent_with_git_head", head_reference=text.strip())
        else:
            data["reason"] = "Body does not match a Git HEAD representation"
    else:
        entries = re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=([^\r\n]*)$", text)
        # Never include any environment values, even if their names look harmless.
        if entries:
            data.update(classification="content_consistent_with_env", variable_names=[key for key, _ in entries][:50],
                        assignment_count=len(entries), values="all omitted")
        else:
            data["reason"] = "No conventional environment assignments found"
    return data


def collect_web(report: Report, target: str, runner: Runner, workdir: Path, probe_paths: bool, max_requests: int) -> None:
    client = WebClient(target, report, runner, workdir, max_requests)
    report.target.update(url=display_url(client.target), scope_origin=list(client.origin),
                         scope_directory=client.base_path, probe_paths_enabled=probe_paths)
    entry = client.get(client.target)
    report.add("W001", "HTTP response and bounded redirect chain", entry.status,
               {"final_url": display_url(entry.url), "http_status": entry.http_status, "note": entry.note}, refs=entry.refs)
    names = {name for name, _ in entry.headers}
    interesting = {name: entry.header(name) for name in ("content-type", "server", "x-powered-by", "content-security-policy",
                  "strict-transport-security", "x-content-type-options", "x-frame-options") if name in names}
    report.add("W002", "Response header observations", entry.status if entry.http_status is not None else "skipped",
               {"selected_headers": interesting,
                "unobserved_headers": [name for name in ("content-security-policy", "x-content-type-options") if name not in names]},
               refs=entry.refs, notes=["Header presence/absence alone is not a vulnerability verdict; headers may differ across endpoints."])
    if entry.http_status is not None and "html" in entry.header("content-type").lower():
        parser = HTMLSignals()
        try:
            parser.feed(entry.body.decode("utf-8", "replace"))
            report.add("W003", "HTML structure", entry.status,
                       {"title": parser.title, "forms": parser.forms, "script_sources": parser.scripts,
                        "comment_count": parser.comment_count, "charset_assumption": "UTF-8 with replacement"}, refs=entry.refs,
                       notes=["Bounded initial HTML only. JavaScript is not executed; forms and links are not followed."])
        except ValueError as exc:
            report.add("W003", "HTML structure", "failed", {"error": str(exc)}, refs=entry.refs)
    else:
        report.add("W003", "HTML structure", "not_applicable", notes=["No HTML content type observed."])
    if not probe_paths:
        report.add("W004", "Directory-relative robots.txt", "skipped", notes=["Enable --probe-paths to make additional scoped GET requests."])
        report.add("W005", "Git/environment exposure indicators", "skipped", notes=["Enable --probe-paths; no automatic repository download or secret export."])
    else:
        robots = client.get(urljoin(client.base, "robots.txt"), follow=False)
        directives = []
        if robots.http_status == 200 and "html" not in robots.header("content-type").lower():
            for line in robots.body.decode("utf-8", "replace").splitlines():
                if re.match(r"(?i)^\s*(user-agent|allow|disallow|sitemap)\s*:", line):
                    directives.append(line[:300])
                    if len(directives) == 50:
                        break
        report.add("W004", "Directory-relative robots.txt", robots.status,
                   {"http_status": robots.http_status, "directives": directives, "note": robots.note}, refs=robots.refs,
                   notes=["Only /robots.txt at the origin root has standard robots semantics; a scoped subdirectory file is just an artifact. Paths are not crawled."])
        baseline = client.get(urljoin(client.base, ".wired2ai-missing-" + secrets.token_hex(8)), follow=False)
        git = client.get(urljoin(client.base, ".git/HEAD"), follow=False)
        env = client.get(urljoin(client.base, ".env"), follow=False)
        status = "complete" if all(item.status == "complete" for item in (baseline, git, env)) else "partial"
        report.add("W005", "Git/environment exposure indicators", status,
                   {"git_head": exposure_assessment(git, baseline, "git"), "environment": exposure_assessment(env, baseline, "env")},
                   refs=baseline.refs + git.refs + env.refs,
                   notes=["HTTP 200 alone is never called a leak. A content match remains an indicator for manual verification, not proof of a readable repository or sensitive secrets."])
    report.limits["http_requests_made"] = client.requests
