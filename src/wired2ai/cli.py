"""Command-line interface for the first wired2ai release."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .binary import collect_binary
from .crypto import collect_crypto
from .files import common_file, snapshot_input
from .forensics import collect_forensics
from .report import Report, clean_text
from .runner import Runner, TOOLS
from .web import collect_web, display_url, validate_url


def bounded_int(low: int, high: int):
    def parse(value: str) -> int:
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number
    return parse


def timeout_value(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError("timeout must be finite and between 0.1 and 60 seconds")
    return number


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Local CTF triage: traceable evidence for analysts and LLMs.")
    root.add_argument("--version", action="version", version=f"wired2ai {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Show the host and optional native tools")
    doctor.add_argument("--json", action="store_true", help="Emit machine-readable diagnostics")
    triage = commands.add_parser("triage", help="Inspect a regular file without executing it")
    triage.add_argument("target", type=Path)
    triage.add_argument("--category", choices=["auto", "pwn", "re", "crypto", "forensics"], default="auto")
    triage.add_argument("--max-file-mib", type=bounded_int(1, 256), default=32, help="Maximum complete snapshot size (default: 32)")
    web = commands.add_parser("web", help="Make bounded GET requests to an explicit HTTP(S) target")
    web.add_argument("target")
    web.add_argument("--probe-paths", action="store_true", help="Also check robots.txt, .git/HEAD, .env and a missing-path control relative to the URL's directory")
    web.add_argument("--max-requests", type=bounded_int(1, 20), default=10, help="Total GET budget, including redirects (default: 10)")
    for command in (triage, web):
        command.add_argument("--out", type=Path, help="New output directory; an existing path is never overwritten")
        command.add_argument("--timeout", type=timeout_value, default=10, help="Seconds per native process/request (default: 10)")
        command.add_argument("--max-output-kib", type=bounded_int(16, 1024), default=64, help="Combined stdout/stderr cap per command (default: 64)")
        command.add_argument("--markdown-kib", type=bounded_int(8, 256), default=32, help="Markdown export budget; JSON retains collected evidence (default: 32)")
        command.add_argument("--strict", action="store_true", help="Exit 1 if a check failed, timed out, or a required collector tool was unavailable")
    return root


def diagnose(as_json: bool) -> int:
    runner = Runner(timeout=3, max_output=8192)
    with tempfile.TemporaryDirectory(prefix="wired2ai-doctor-") as directory:
        tools = {tool: {"path": runner.locate(tool), "version": runner.version(tool, Path(directory))} for tool in TOOLS}
    result = {"wired2ai": __version__, "python": platform.python_version(), "platform": platform.platform(),
              "tools": tools, "requirements": {"file": "optional format description", "readelf": "ELF detail",
              "openssl": "PEM public components and certificate metadata", "exiftool": "optional forensic metadata",
              "curl": "web collection"}}
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"wired2ai {__version__} | Python {platform.python_version()} | {platform.system()}")
        for tool, info in tools.items():
            print(f"{tool:10} {info['version'] if info['path'] else 'unavailable'}")
        print("Missing optional tools reduce coverage and are recorded in each report.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if platform.system() != "Linux":
        print("wired2ai currently targets Linux (Kali); other operating systems are not supported.", file=sys.stderr)
        return 2
    old_umask = os.umask(0o077)
    try:
        if args.command == "doctor":
            return diagnose(args.json)
        output = args.out or Path("wired2ai-runs") / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4))
        if output.exists() or output.is_symlink():
            raise ValueError("Output path already exists; choose a new directory")
        limits = {"timeout_seconds_per_process": args.timeout, "output_bytes_per_command": args.max_output_kib * 1024,
                  "markdown_bytes": args.markdown_kib * 1024, "target_execution": False,
                  "isolation": "private snapshot and bounded subprocesses; not a sandbox"}
        runner = Runner(timeout=args.timeout, max_output=args.max_output_kib * 1024)
        if args.command == "web":
            target = validate_url(args.target)
            limits["max_http_requests"] = args.max_requests
            report = Report("web", {"kind": "url", "url": display_url(target)}, limits)
            with tempfile.TemporaryDirectory(prefix="wired2ai-web-") as directory:
                collect_web(report, target, runner, Path(directory), args.probe_paths, args.max_requests)
        else:
            limits["max_file_bytes"] = args.max_file_mib * 1024 * 1024
            with snapshot_input(args.target, limits["max_file_bytes"]) as source:
                category = args.category
                if category == "auto":
                    category = "re" if source.profile["format_hint"] in {"elf", "pe_candidate"} else (
                        "crypto" if source.profile["format_hint"] == "text" else "forensics")
                target = {**source.profile, "category_selection": "heuristic; override with --category" if args.category == "auto" else "explicit"}
                report = Report(category, target, limits)
                strings = common_file(report, source, runner)
                if category in {"pwn", "re"}:
                    collect_binary(report, source, runner, strings)
                elif category == "crypto":
                    collect_crypto(report, source, runner)
                else:
                    collect_forensics(report, source, runner)
        report.write(output, args.markdown_kib * 1024)
        counts = {}
        for check in report.checks:
            counts[check["status"]] = counts.get(check["status"], 0) + 1
        print(f"Report: {clean_text(str(output.absolute() / 'context.md'))}")
        print("Checks: " + ", ".join(f"{name}={count}" for name, count in sorted(counts.items())))
        print("Review redactions and check statuses before sharing. No LLM request was made.")
        return 1 if args.strict and any(counts.get(status) for status in ("failed", "timeout", "unavailable")) else 0
    except (OSError, ValueError) as exc:
        print(f"wired2ai: {clean_text(str(exc))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("wired2ai: interrupted", file=sys.stderr)
        return 130
    finally:
        os.umask(old_umask)
