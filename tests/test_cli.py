import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wired2ai import __version__
from wired2ai.cli import main
from wired2ai.report import STATUSES
from wired2ai.runner import Runner


class CLITests(unittest.TestCase):
    def run_cli(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main(args)
        return code, output.getvalue()

    def test_doctor_json(self):
        code, output = self.run_cli(["doctor", "--json"])
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertEqual(result["wired2ai"], __version__)
        self.assertIn("readelf", result["tools"])

    def test_file_run_report_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "- file; $(false).txt"
            source.write_text("n=3233\ne=17\nc=855\nZmxhZ3tmaXh0dXJlfQ==\n")
            code, _ = self.run_cli(["triage", str(source), "--category", "crypto", "--out", str(root / "run")])
            self.assertEqual(code, 0)
            report = json.loads((root / "run/report.json").read_text())
            self.assertEqual(report["category"], "crypto")
            self.assertEqual(report["target"]["size_bytes"], source.stat().st_size)
            ids = {item["id"] for item in report["evidence"]}
            self.assertEqual(len(report["checks"]), 8)
            for check in report["checks"]:
                self.assertIn(check["status"], STATUSES)
                self.assertTrue(set(check["evidence_ids"]).issubset(ids))
            self.assertLessEqual((root / "run/context.md").stat().st_size, report["limits"]["markdown_bytes"])

    def test_does_not_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_text("original")
            code, output = self.run_cli(["triage", str(source), "--out", str(source)])
            self.assertEqual(code, 2)
            self.assertEqual(source.read_text(), "original")
            self.assertIn("already exists", output)

    def test_missing_input(self):
        code, _ = self.run_cli(["triage", "/this-path-does-not-exist-wired2ai"])
        self.assertEqual(code, 2)

    def test_unsupported_format_has_explicit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(b"not an ELF")
            code, _ = self.run_cli(["triage", str(root / "input"), "--category", "pwn", "--out", str(root / "run")])
            self.assertEqual(code, 0)
            report = json.loads((root / "run/report.json").read_text())
            self.assertEqual(next(c for c in report["checks"] if c["id"] == "P001")["status"], "unsupported")

    def test_strict_missing_dependency_still_writes_report(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Runner, "locate", return_value=None):
            root = Path(directory)
            (root / "input").write_bytes(b"n=49\ne=3\n")
            code, _ = self.run_cli(["triage", str(root / "input"), "--category", "crypto", "--strict", "--out", str(root / "run")])
            self.assertEqual(code, 1)
            report = json.loads((root / "run/report.json").read_text())
            self.assertEqual(next(c for c in report["checks"] if c["id"] == "C002")["status"], "unavailable")

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf"), "gcc/readelf are not installed")
    def test_real_elf_both_binary_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "EXECUTED"
            c_source = root / "fixture.c"
            c_source.write_text('#include <stdio.h>\nint main(void){ FILE *f=fopen(' + json.dumps(str(sentinel)) + ',"w"); if(f)fclose(f); return 0;}\n')
            binary = root / "fixture"
            subprocess.run(["gcc", "-fPIE", "-pie", "-Wl,-z,relro,-z,now", "-o", str(binary), str(c_source)],
                           check=True, capture_output=True, timeout=15)
            for category in ("pwn", "re"):
                code, _ = self.run_cli(["triage", str(binary), "--category", category, "--strict", "--out", str(root / category)])
                self.assertEqual(code, 0)
                report = json.loads((root / category / "report.json").read_text())
                mitigations = next(c for c in report["checks"] if c["id"].endswith("002") and c["id"].startswith(("P", "R")))
                self.assertEqual(mitigations["data"]["relro"], "full RELRO indicators")
                self.assertEqual(mitigations["data"]["pie"], "PIE indicators present")
                self.assertFalse(sentinel.exists(), "A supplied target was executed")
