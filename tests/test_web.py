import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from wired2ai.report import Report
from wired2ai.runner import Runner
from wired2ai.web import Response, WebClient, collect_web, display_url, exposure_assessment, parse_http, validate_url


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.seen.append(self.path)
        status, content_type, payload, headers = 200, "text/plain", b"not found", {}
        if self.path == "/app/":
            content_type = "text/html"
            payload = b'<title>Local fixture</title><form action="/app/login?session=private" method="post"></form><script src="/app/client.js"></script><!-- hidden -->'
            headers["Set-Cookie"] = "session=SHOULDNOTEXPORT"
        elif self.path == "/app/.git/HEAD":
            payload = b"ref: refs/heads/main\n"
        elif self.path == "/app/.env":
            payload = b"DB_PASSWORD=DB_SECRET_VALUE\nCONNECTION=ANOTHER_SECRET_VALUE\n"
        elif self.path == "/app/robots.txt":
            payload = b"User-agent: *\nDisallow: /app/private\n"
        elif self.path == "/app/escape":
            status, headers["Location"] = 302, "/outside"
        elif self.path == "/app/cross":
            status, headers["Location"] = 302, "http://localhost:1/never"
        elif self.path == "/app/loop":
            status, headers["Location"] = 302, "/app/loop"
        elif self.path == "/app/huge":
            payload = b"A" * 200000
        elif self.path == "/app/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"4\r\nDATA\r\n0\r\n\r\n")
            return
        else:
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass


class URLTests(unittest.TestCase):
    def test_invalid_urls(self):
        for url in ("file:///etc/passwd", "https://user:pass@example.com/", "https://example.com/a\nB", "http://example.com:0/",
                    "https://example.com/../admin", "https://example.com/%2e%2e/admin", "https://example.com/%252e%252e/admin",
                    "http://example.com\\evil/", "http://example.com/#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)

    def test_query_values_redacted(self):
        self.assertEqual(display_url("https://example.com/a?x=secret&name=other"),
                         "https://example.com/a?x=[REDACTED]&name=[REDACTED]")

    def test_parse_interim_response(self):
        status, headers, body = parse_http(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-A: b\r\n\r\nDATA")
        self.assertEqual((status, body), (200, b"DATA"))

    def test_200_is_not_enough(self):
        response = Response("http://fixture/.git/HEAD", "complete", 200, [("content-type", "text/plain")], b"hello world", [])
        baseline = Response("http://fixture/missing", "complete", 404, [], b"missing", [])
        self.assertEqual(exposure_assessment(response, baseline, "git")["classification"], "not_confirmed")

    def test_soft_404(self):
        response = Response("http://fixture/.env", "complete", 200, [], b"A=dynamic", [])
        self.assertEqual(exposure_assessment(response, response, "env")["classification"], "inconclusive")


@unittest.skipUnless(shutil.which("curl"), "curl is not installed")
class WebIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server.daemon_threads = True
        cls.server.seen = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/app/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.server.seen.clear()

    def test_scoped_probes_and_secret_omission(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Report("web", {}, {})
            collect_web(report, self.base, Runner(), Path(directory), True, 10)
            checks = {check["id"]: check for check in report.checks}
            self.assertEqual(checks["W005"]["data"]["git_head"]["classification"], "content_consistent_with_git_head")
            self.assertEqual(checks["W005"]["data"]["environment"]["variable_names"], ["DB_PASSWORD", "CONNECTION"])
            self.assertEqual(checks["W003"]["data"]["comment_count"], 1)
            self.assertEqual(report.limits["http_requests_made"], 5)
            export = json.dumps(report.to_dict())
            for secret in ("DB_SECRET_VALUE", "ANOTHER_SECRET_VALUE", "SHOULDNOTEXPORT", "session=private"):
                self.assertNotIn(secret, export)
            self.assertTrue(all(path.startswith("/app/") for path in self.server.seen))

    def test_default_makes_no_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Report("web", {}, {})
            collect_web(report, self.base, Runner(), Path(directory), False, 10)
            self.assertEqual(self.server.seen, ["/app/"])
            self.assertEqual(next(c for c in report.checks if c["id"] == "W005")["status"], "skipped")

    def test_redirect_cannot_leave_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Report("web", {}, {})
            client = WebClient(self.base, report, Runner(), Path(directory))
            response = client.get(self.base + "escape")
            self.assertEqual(response.status, "skipped")
            self.assertNotIn("/outside", self.server.seen)

    def test_redirect_cannot_change_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            client = WebClient(self.base, Report("web", {}, {}), Runner(), Path(directory))
            self.assertEqual(client.get(self.base + "cross").status, "skipped")
            self.assertEqual(client.requests, 1)

    def test_redirect_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            client = WebClient(self.base, Report("web", {}, {}), Runner(), Path(directory), max_requests=2)
            self.assertEqual(client.get(self.base + "loop").status, "skipped")
            self.assertEqual(client.requests, 2)

    def test_body_size_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            client = WebClient(self.base, Report("web", {}, {}), Runner(max_output=16384), Path(directory))
            response = client.get(self.base + "huge")
            self.assertEqual(response.status, "partial")
            self.assertLessEqual(len(response.body), 16384)

    def test_chunked_transfer_is_decoded_by_curl(self):
        with tempfile.TemporaryDirectory() as directory:
            client = WebClient(self.base, Report("web", {}, {}), Runner(), Path(directory))
            response = client.get(self.base + "chunked")
            self.assertEqual(response.body, b"DATA")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is not installed")
    def test_untrusted_tls_certificate_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, cert = root / "key.pem", root / "cert.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
            server.seen = []
            server.daemon_threads = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"https://127.0.0.1:{server.server_port}/app/"
                report = Report("web", {}, {})
                response = WebClient(url, report, Runner(), root).get(url)
                self.assertEqual(response.status, "failed")
                self.assertEqual(report.evidence[-1]["returncode"], 60)
                self.assertEqual(server.seen, [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
