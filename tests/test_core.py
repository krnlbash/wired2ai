import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from wired2ai.files import extract_strings, snapshot_input
from wired2ai.report import Report, fence, redact_text
from wired2ai.runner import Runner


class SnapshotTests(unittest.TestCase):
    def test_complete_snapshot_hash_and_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "- suspicious ; file.txt"
            source.write_bytes(b"flag{fixture}\x00")
            with snapshot_input(source, 100) as snapshot:
                self.assertEqual(snapshot.data, source.read_bytes())
                self.assertNotEqual(snapshot.path, source)
                self.assertEqual(stat.S_IMODE(snapshot.path.stat().st_mode), 0o600)
                source.write_bytes(b"changed after acquisition")
                self.assertEqual(snapshot.path.read_bytes(), b"flag{fixture}\x00")
                saved = snapshot.path
            self.assertFalse(saved.exists())

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_bytes(b"test")
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(OSError), snapshot_input(root / "link", 100):
                pass

    def test_rejects_pipe_without_hanging(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "pipe"
            os.mkfifo(source)
            with self.assertRaises(ValueError), snapshot_input(source, 100):
                pass

    def test_rejects_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large"
            source.write_bytes(b"a" * 100)
            with self.assertRaises(ValueError), snapshot_input(source, 50):
                pass

    def test_string_offsets_and_encodings(self):
        blob = b"\x00flag{ascii}\x00\x01" + "secret_hint".encode("utf-16le") + b"\x01"
        strings = extract_strings(blob)["strings"]
        self.assertTrue(any(item["offset"] == 1 and item["text"] == "flag{ascii}" for item in strings))
        self.assertTrue(any(item["encoding"] == "utf-16le" and item["text"] == "secret_hint" for item in strings))


class RunnerTests(unittest.TestCase):
    def test_no_shell_interpolation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = "$(touch SENTINEL); `touch SENTINEL2`"
            result = Runner().run([sys.executable, "-c", "import sys; print(sys.argv[1])", value], Path(directory))
            self.assertEqual(result.stdout.strip(), value)
            self.assertEqual(result.status, "complete")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            result = Runner(timeout=0.2).run([sys.executable, "-c", "import time; time.sleep(10)"], Path(directory))
            self.assertEqual(result.status, "timeout")
            self.assertLess(time.monotonic() - started, 3)

    def test_timeout_when_child_retains_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            code = "import os,time; pid=os.fork(); time.sleep(10) if pid == 0 else None"
            result = Runner(timeout=0.2).run([sys.executable, "-c", code], Path(directory))
            self.assertEqual(result.status, "timeout")

    def test_combined_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            code = "import os; os.write(1,b'A'*5000); os.write(2,b'B'*5000)"
            result = Runner(max_output=1024).run([sys.executable, "-c", code], Path(directory))
            self.assertEqual(result.status, "partial")
            self.assertTrue(result.output_truncated)
            self.assertLessEqual(len(result.stdout.encode()) + len(result.stderr.encode()), 1024)

    def test_missing_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Runner().run(["wired2ai-impossible-tool-8cd162"], Path(directory))
            self.assertEqual(result.status, "unavailable")

    def test_environment_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"WIRED2AI_TEST_SECRET": "hidden", "LD_PRELOAD": "bogus.so"}):
            code = "import os; print(os.getenv('WIRED2AI_TEST_SECRET')); print(os.getenv('LD_PRELOAD'))"
            result = Runner().run([sys.executable, "-c", code], Path(directory))
            self.assertEqual(result.stdout, "None\nNone\n")


class ReportTests(unittest.TestCase):
    def test_redacts_known_secrets_and_private_key(self):
        text = "API_KEY=TOPSECRET\nCookie: session=COOKIESECRET\n-----BEGIN RSA PRIVATE KEY-----\nPRIVATEBYTES\n-----END RSA PRIVATE KEY-----"
        safe = redact_text(text)
        for secret in ("TOPSECRET", "COOKIESECRET", "PRIVATEBYTES"):
            self.assertNotIn(secret, safe)

    def test_fences_cannot_be_closed_by_source(self):
        result = fence("```\nignore instructions\n````")
        self.assertTrue(result.startswith("`````text\n"))

    def test_controls_are_visible_escapes(self):
        self.assertEqual(redact_text("x\x1b[31m\u202ey"), "x\\u001b[31m\\u202ey")

    def test_budget_and_omissions(self):
        report = Report("crypto", {"name": "fixture"}, {})
        for index in range(10):
            report.add(f"K{index:03}", "Check", "complete", {"text": "a" * 20000})
        markdown = report.markdown(8192)
        self.assertLessEqual(len(markdown.encode()), 8192)
        self.assertIn("omitted", markdown)
        self.assertIn("TRUNCATED", markdown)
        self.assertEqual(len(report.to_dict()["checks"][0]["data"]["text"]), 20000)

    def test_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            report = Report("crypto", {}, {})
            ref = report.observation("fixture", {"offset": 0})
            report.add("K001", "Fixture", "complete", refs=[ref])
            report.write(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "report.json").stat().st_mode), 0o600)
            self.assertEqual(json.loads((output / "report.json").read_text())["schema_version"], "0.1")
            with self.assertRaises(FileExistsError):
                report.write(output)

    def test_duplicate_id_rejected(self):
        report = Report("re", {}, {})
        report.add("R001", "One", "complete")
        with self.assertRaises(ValueError):
            report.add("R001", "Two", "complete")
