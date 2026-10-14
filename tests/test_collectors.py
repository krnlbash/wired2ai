import base64
import io
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from wired2ai.binary import elf_mitigations, inspect_pe, parse_symbols
from wired2ai.crypto import byte_statistics, encoding_candidates, rsa_parameters, collect_crypto
from wired2ai.files import common_file, snapshot_input
from wired2ai.forensics import collect_forensics, inspect_pcap, inspect_png, inspect_zip
from wired2ai.report import Report
from wired2ai.runner import Runner


def png_chunk(kind, payload=b""):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)


def png_fixture():
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + png_chunk(b"IDAT", b"one") + png_chunk(b"IDAT", b"two") + png_chunk(b"IEND"))


class BinaryTests(unittest.TestCase):
    def test_exact_symbol_matching_and_versions(self):
        symbols = "\n".join(f"{i}: 00000000 0 FUNC GLOBAL DEFAULT UND {name}" for i, name in enumerate(
            ["fgets@GLIBC_2.2.5", "gets@GLIBC_2.2.5", "system_info", "__stack_chk_fail@GLIBC_2.4"]))
        names = [row["name"] for row in parse_symbols(symbols)]
        self.assertEqual(names, ["gets", "__stack_chk_fail"])

    def test_mitigation_evidence(self):
        layout = "GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\nGNU_RELRO 0x0\nINTERP\n (FLAGS_1) Flags: NOW PIE"
        result = elf_mitigations(" Type: DYN (Position-Independent Executable file)", layout, "", True, True)
        self.assertIn("non-executable", result["stack_execution"])
        self.assertEqual(result["relro"], "full RELRO indicators")
        self.assertEqual(result["pie"], "PIE indicators present")
        self.assertIn("does not prove", result["stack_canary"])

    def test_incomplete_layout_is_unknown(self):
        result = elf_mitigations("", "GNU_RELRO", "", False, False)
        self.assertIn("unknown", result["relro"])
        self.assertIn("unknown", result["stack_canary"])

    def test_invalid_pe_offset_is_rejected(self):
        data = bytearray(80)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0xffffffff)
        with self.assertRaises(ValueError):
            inspect_pe(data)

    def test_pe_header_flags(self):
        data = bytearray(64 + 24 + 224 + 40)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", data, 68, 0x14c, 1, 0, 0, 0, 224, 2)
        struct.pack_into("<H", data, 88, 0x10b)
        struct.pack_into("<H", data, 88 + 70, 0x140)
        data[312:317] = b".text"
        result = inspect_pe(data)
        self.assertEqual(result["sections"], [".text"])
        self.assertTrue(result["nx_compat_flag"])


class CryptoTests(unittest.TestCase):
    def test_empty_entropy(self):
        self.assertEqual(byte_statistics(b"")["shannon_entropy_bits_per_byte"], 0)

    def test_encoding_derivation_offsets(self):
        encoded = base64.b64encode(b"flag{fixture}")
        result = encoding_candidates(b"data: " + encoded)
        candidate = next(item for item in result["candidates"] if item["encoding"] == "base64")
        self.assertEqual(candidate["source_offset"], 6)
        self.assertEqual(candidate["decoded_preview"], "flag{fixture}")

    def test_bad_base64_padding_not_accepted(self):
        result = encoding_candidates(b"YWJjZA===")
        self.assertFalse(result["candidates"])

    def test_encoding_selection_boundary_and_omitted_counts(self):
        for count in (12, 13, 30):
            with self.subTest(count=count):
                data = b"\n".join(base64.b64encode(f"fixture-{i:02}".encode()) for i in range(count))
                result = encoding_candidates(data)
                self.assertEqual(len(result["candidates"]), min(12, count))
                self.assertEqual(result["candidates_seen"], count)
                self.assertEqual(result["selection_truncated"], count > 12)
                self.assertFalse(result["sample_truncated"])

    def test_encoding_partial_notes_distinguish_selection_and_sample(self):
        cases = [(b"Zml4dHVyZQ==\n" * 13, "Kept 12 of 13"), (b"!" * 65537, "Scanned 65536 of 65537")]
        for data, explanation in cases:
            with self.subTest(explanation=explanation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "fixture.txt"
                path.write_bytes(data)
                with snapshot_input(path, len(data)) as source:
                    report = Report("crypto", source.profile, {})
                    collect_crypto(report, source, Runner())
                check = next(c for c in report.checks if c["id"] == "K002")
                self.assertEqual(check["status"], "partial")
                self.assertIn(explanation, " ".join(check["notes"]))

    def test_parameters_not_executed(self):
        result = rsa_parameters(b"n=49\ne=3\nc=80\n__import__('os').system('false')")
        self.assertEqual(result["parameters"]["n"]["decimal"], "49")
        self.assertTrue(any("perfect square" in line for line in result["observations"]))
        self.assertTrue(any("range" in line for line in result["observations"]))

    def test_json_boolean_not_integer(self):
        result = rsa_parameters(b'{"n": true, "e": 65537}')
        self.assertNotIn("n", result["parameters"])

    def test_duplicate_json_parameters_are_rejected(self):
        result = rsa_parameters(b'{"n": 49, "n": 3233, "e": 3}')
        self.assertEqual(result["parameters"], {})
        self.assertEqual(result["duplicate_json_keys"], ["n"])

    def test_deep_json_is_bounded_failure(self):
        result = rsa_parameters(b"[" * 2000 + b"]" * 2000)
        self.assertEqual(result["parameters"], {})

    def test_parameter_digit_cap(self):
        result = rsa_parameters(("n=" + "9" * 5000).encode())
        self.assertEqual(result["parameters"], {})

    def test_encrypted_key_is_skipped_without_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "encrypted.pem"
            path.write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC_PAYLOAD\n-----END ENCRYPTED PRIVATE KEY-----")
            with snapshot_input(path, 10000) as source:
                report = Report("crypto", source.profile, {})
                common_file(report, source, Runner())
                collect_crypto(report, source, Runner())
            self.assertEqual(next(c for c in report.checks if c["id"] == "K004")["status"], "skipped")
            self.assertNotIn("SYNTHETIC_PAYLOAD", json.dumps(report.to_dict()))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is not installed")
    def test_private_key_public_only_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            with snapshot_input(path, 10000) as source:
                report = Report("crypto", source.profile, {})
                runner = Runner()
                common_file(report, source, runner)
                collect_crypto(report, source, runner)
            encoded = json.dumps(report.to_dict())
            self.assertNotIn("privateExponent", encoded)
            self.assertNotIn("prime1", encoded)
            self.assertNotIn("BEGIN PRIVATE KEY", encoded)
            self.assertEqual(next(c for c in report.checks if c["id"] == "K004")["status"], "complete")
            self.assertIn("Public-Key", encoded)


class ForensicsTests(unittest.TestCase):
    def test_png_consecutive_idat_and_trailing_data(self):
        data = png_fixture()
        self.assertEqual(inspect_png(data)["anomalies"], [])
        result = inspect_png(data + b"TRAILER")
        self.assertTrue(any("7 bytes after IEND" in item for item in result["anomalies"]))
        self.assertFalse(any("Non-consecutive" in item for item in result["anomalies"]))
        self.assertEqual(result["trailing_bytes"], 7)
        self.assertEqual(result["trailing_offset"], len(data))

    def test_png_invalid_chunk_type_is_lossless(self):
        for kind in (b"bKG\xff", b"bK\x00\x1b", b"bK\\G"):
            with self.subTest(kind=kind):
                fixture = png_fixture()
                data = fixture[:-12] + png_chunk(kind, b"fixture") + fixture[-12:]
                result = inspect_png(data)
                chunk = next(c for c in result["chunks"] if c.get("type_hex") == kind.hex())
                self.assertNotIn("\ufffd", chunk["type"])
                self.assertNotIn("\x1b", chunk["type"])
                self.assertIn("\\x", chunk["type"])
                self.assertTrue(any("Invalid PNG chunk type" in value for value in result["anomalies"]))

    def test_png_trailer_survives_markdown_check_truncation(self):
        fixture = png_fixture()
        # Force a large chunk list before IEND so the detail excerpt is truncated.
        data = fixture[:-12] + png_chunk(b"tEXt", b"x") * 260 + fixture[-12:] + b"TRAILER"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.png"
            path.write_bytes(data)
            with snapshot_input(path, len(data)) as source:
                report = Report("forensics", source.profile, {})
                common_file(report, source, Runner())
                collect_forensics(report, source, Runner())
            check = next(c for c in report.checks if c["id"] == "F002")
            self.assertEqual(check["status"], "partial")
            self.assertIn("Kept 256 of 264", " ".join(check["notes"]))
            markdown = report.markdown(8192)
            self.assertLessEqual(len(markdown.encode()), 8192)
            self.assertIn("7 bytes after IEND", markdown)
            self.assertIn(f"offset {len(data)-7}", markdown)
            self.assertIn("F002", markdown)
            self.assertIn("E001", markdown)

    def test_png_bad_crc(self):
        data = bytearray(png_fixture())
        data[29] ^= 1
        result = inspect_png(data)
        self.assertTrue(any("CRC mismatch" in value for value in result["anomalies"]))

    def test_png_anomaly_cap_preserves_trailing_lead(self):
        fixture = png_fixture()
        data = fixture[:-12] + png_chunk(b"bKG\xff") * 90 + fixture[-12:] + b"TRAILER"
        result = inspect_png(data)
        self.assertEqual(result["anomalies_seen"], 91)
        self.assertEqual(len(result["anomalies"]), 80)
        self.assertTrue(result["selection_truncated"])
        self.assertIn("7 bytes after IEND", result["anomalies"][0])

    def test_png_out_of_bounds(self):
        with self.assertRaises(ValueError):
            inspect_png(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 0xffffffff) + b"IDATxxxx")

    def test_zip_paths_and_no_extraction(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escaped.txt", "fixture")
            archive.writestr("safe.txt", "safe")
        result = inspect_zip(stream.getvalue())
        self.assertEqual(result["entry_count"], 2)
        self.assertIn("unsafe extraction path", result["entries"][0]["risks"])

    def test_zip_directory_count_is_validated(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("safe", "data")
        data = bytearray(stream.getvalue())
        offset = data.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", data, offset + 8, 0, 0)
        with self.assertRaises(ValueError):
            inspect_zip(data)

    def test_pcap_header_and_record(self):
        data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1)
        data += struct.pack("<IIII", 42, 100, 4, 4) + b"DATA"
        result = inspect_pcap(data)
        self.assertEqual(result["packet_records"], 1)
        self.assertEqual(result["first_record_timestamp"]["seconds"], 42)

    def test_pcap_truncation(self):
        data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiII", 2, 4, 0, 0, 65535, 1)
        data += struct.pack("<IIII", 42, 100, 500, 500)
        with self.assertRaises(ValueError):
            inspect_pcap(data)
