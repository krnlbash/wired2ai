import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wired2ai.cli import main
from wired2ai.pcapng import UnsupportedPcapng, inspect_pcapng
from wired2ai.report import Report
from wired2ai.runner import Runner


def pad(value):
    return value + b"\0" * (-len(value) % 4)


def block(kind, body=b"", endian="<"):
    length = 12 + len(pad(body))
    return struct.pack(endian + "II", kind, length) + pad(body) + struct.pack(endian + "I", length)


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + pad(value)


def section(endian="<", length=-1, version=(1, 0), options=b""):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, *version, length) + options, endian)


def interface(endian="<", snaplen=65535, link_type=1, options=b""):
    return block(1, struct.pack(endian + "HHI", link_type, 0, snaplen) + options, endian)


def packet(endian="<", identifier=0, ticks=1500000, payload=b"abc", original=None, options=b"", obsolete=False):
    lengths = (ticks >> 32, ticks & 0xFFFFFFFF, len(payload), len(payload) if original is None else original)
    header = (struct.pack(endian + "HHIIII", identifier, 0xFFFF, *lengths) if obsolete else
              struct.pack(endian + "IIIII", identifier, *lengths))
    return block(2 if obsolete else 6, header + pad(payload) + options, endian)


class PcapngTests(unittest.TestCase):
    def test_literal_empty_section(self):
        data = bytes.fromhex("0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000")
        result = inspect_pcapng(data)
        self.assertEqual(result["section_count"], 1)
        self.assertEqual(result["packet_records"], 0)
        self.assertEqual(result["inspected_bytes"], 28)
        self.assertFalse(result["selection_truncated"])

    def test_endianness_and_exact_timestamp(self):
        for endian in ("<", ">"):
            with self.subTest(endian=endian):
                # Timestamp example in the format draft, expressed as two words.
                ticks = (0x0004C396 << 32) | 0x656A8973
                result = inspect_pcapng(section(endian) + interface(endian) + packet(endian, ticks=ticks))
                stamp = result["packet_sample"][0]["timestamp"]
                self.assertEqual(stamp, {"raw_ticks": ticks, "seconds": 1340950620,
                                         "fraction_numerator": 834163, "fraction_denominator": 1000000})
                self.assertEqual(result["captured_packet_bytes"], 3)
                self.assertEqual(result["packet_sample"][0]["payload_offset"], 76)

    def test_mixed_sections_reset_interface_ids(self):
        data = (section() + interface(link_type=1) + packet() +
                section(">") + interface(">", link_type=276) + packet(">", ticks=2500000))
        result = inspect_pcapng(data)
        self.assertEqual([i["interface_id"] for i in result["interfaces"]], [0, 0])
        self.assertEqual([p["section_index"] for p in result["packet_sample"]], [0, 1])
        self.assertEqual([i["link_type"] for i in result["interfaces"]], [1, 276])
        with self.assertRaisesRegex(ValueError, "undeclared interface"):
            inspect_pcapng(section() + interface() + section(">") + packet(">"))

    def test_multiple_interfaces_resolution_and_signed_offset(self):
        binary_options = option(9, b"\x8a") + option(14, struct.pack("<q", -2)) + option(0, b"")
        data = (section() + interface(options=option(9, b"\x09")) + interface(options=binary_options) +
                packet(ticks=1234567890) + packet(identifier=1, ticks=1536))
        result = inspect_pcapng(data)
        first, second = [p["timestamp"] for p in result["packet_sample"]]
        self.assertEqual((first["seconds"], first["fraction_numerator"], first["fraction_denominator"]),
                         (1, 234567890, 1000000000))
        self.assertEqual((second["seconds"], second["fraction_numerator"], second["fraction_denominator"]),
                         (-1, 512, 1024))
        self.assertEqual([i["packet_records"] for i in result["interfaces"]], [1, 1])

    def test_extreme_resolution_and_ticks_keep_integer_precision(self):
        for resolution, denominator in ((127, 10 ** 127), (255, 2 ** 127), (0, 1)):
            result = inspect_pcapng(section() + interface(options=option(9, bytes([resolution]))) + packet(ticks=2 ** 64 - 1))
            stamp = result["packet_sample"][0]["timestamp"]
            self.assertEqual(stamp["raw_ticks"], 2 ** 64 - 1)
            self.assertEqual(stamp["seconds"] * denominator + stamp["fraction_numerator"], 2 ** 64 - 1)
            self.assertEqual(stamp["fraction_denominator"], denominator)

    def test_simple_packet_snaplen_unlimited_and_missing_timestamp(self):
        for snaplen, original, payload in ((3, 20, b"abc"), (0, 5, b"abcde")):
            result = inspect_pcapng(section() + interface(snaplen=snaplen) + block(3, struct.pack("<I", original) + pad(payload)))
            item = result["packet_sample"][0]
            self.assertEqual(item["captured_bytes"], len(payload))
            self.assertIsNone(item["timestamp"])
            self.assertEqual(result["timestamped_packet_records"], 0)
            self.assertIsNone(result["first_timestamped_packet"])
        with self.assertRaisesRegex(ValueError, "simple packet length"):
            inspect_pcapng(section() + interface() + block(3, struct.pack("<I", 5) + b"abcd"))

    def test_obsolete_packet_block_is_counted(self):
        for endian in ("<", ">"):
            result = inspect_pcapng(section(endian) + interface(endian) + packet(endian, obsolete=True))
            self.assertEqual(result["packet_records"], 1)
            self.assertEqual(result["packet_sample"][0]["block_type"], "obsolete_packet")

    def test_first_and_last_are_file_order_not_time_extrema(self):
        data = section() + interface() + packet(ticks=3000000) + packet(ticks=1000000)
        result = inspect_pcapng(data)
        self.assertEqual(result["first_timestamped_packet"]["timestamp"]["seconds"], 3)
        self.assertEqual(result["last_timestamped_packet"]["timestamp"]["seconds"], 1)

    def test_declared_section_boundaries(self):
        body = interface() + packet()
        self.assertEqual(inspect_pcapng(section(length=len(body)) + body + section(">", length=0))["section_count"], 2)
        for length in (-2, 1, len(body) - 4, len(body) + 4):
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, "section"):
                inspect_pcapng(section(length=length) + body)
        with self.assertRaisesRegex(ValueError, "boundary"):
            inspect_pcapng(section(length=28) + section())

    def test_every_truncated_prefix_and_bad_framing(self):
        data = section() + interface() + packet()
        for cut in range(1, len(data)):
            with self.subTest(cut=cut):
                if cut in (28, 48):
                    self.assertEqual(inspect_pcapng(data[:cut])["packet_records"], 0)
                else:
                    with self.assertRaises(ValueError):
                        inspect_pcapng(data[:cut])
        for offset, value in ((4, 0), (4, 13), (4, 0xFFFFFFFC), (24, 24), (8, 0)):
            broken = bytearray(data)
            struct.pack_into("<I", broken, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(ValueError, "offset"):
                inspect_pcapng(bytes(broken))

    def test_packet_bounds_and_missing_interface(self):
        with self.assertRaisesRegex(ValueError, "undeclared interface"):
            inspect_pcapng(section() + packet())
        broken = bytearray(section() + interface() + packet())
        struct.pack_into("<I", broken, 48 + 20, 0xFFFFFFFF)
        with self.assertRaisesRegex(ValueError, "exceeds block"):
            inspect_pcapng(bytes(broken))

    def test_inconsistent_lengths_are_observations(self):
        result = inspect_pcapng(section() + interface(snaplen=1) + packet(payload=b"abc", original=2))
        self.assertEqual(result["packet_records"], 1)
        self.assertEqual(result["anomalies_seen"], 2)
        self.assertFalse(result["selection_truncated"])

    def test_option_framing_and_ambiguous_timestamps(self):
        invalid = [struct.pack("<HH", 9, 100), option(9, b"xx"), option(14, b"x"),
                   option(9, b"\x06") * 2, option(14, b"\0" * 8) * 2,
                   option(0, b"x"), option(0, b"") + option(1, b"text")]
        for options in invalid:
            with self.subTest(options=options.hex()), self.assertRaisesRegex(ValueError, "option"):
                inspect_pcapng(section() + interface(options=options))
        result = inspect_pcapng(section(options=option(1, b"private comment")) +
                                interface(options=option(123, b"unknown value")))
        self.assertEqual(result["interface_count"], 1)
        self.assertNotIn("private comment", json.dumps(result))
        self.assertNotIn("unknown value", json.dumps(result))

    def test_opaque_and_secrets_blocks_omit_bodies(self):
        secret = b"arbitrary unrecognized key material"
        data = (section() + block(0x80000001, b"private opaque value") +
                block(10, struct.pack("<II", 0x544C534B, len(secret)) + pad(secret)))
        result = inspect_pcapng(data)
        self.assertEqual(result["opaque_blocks"], 1)
        self.assertEqual(result["decryption_secrets"]["blocks"], 1)
        self.assertEqual(result["decryption_secrets"]["declared_bytes"], len(secret))
        self.assertNotIn(secret.decode(), json.dumps(result))
        self.assertNotIn("private opaque value", json.dumps(result))
        self.assertFalse(result["selection_truncated"])
        with self.assertRaisesRegex(ValueError, "secrets length"):
            inspect_pcapng(section() + block(10, struct.pack("<II", 0, 0xFFFFFFFF)))

    def test_selection_caps_keep_aggregates_and_notes(self):
        data = section() + interface(snaplen=1) + packet(payload=b"abc", original=2) * 50
        result = inspect_pcapng(data)
        self.assertEqual(result["packet_records"], 50)
        self.assertEqual(len(result["packet_sample"]), 32)
        self.assertEqual(result["anomalies_seen"], 100)
        self.assertEqual(len(result["anomalies"]), 40)
        self.assertEqual(result["inspected_bytes"], len(data))
        self.assertFalse(result["scan_limited"])
        self.assertIn("Kept 32 of 50", " ".join(result["notes"]))
        self.assertIn("Kept 40 of 100", " ".join(result["notes"]))
        self.assertEqual(result["last_timestamped_packet"]["record_index"], 49)

    def test_block_scan_limit_and_unbounded_type_diversity(self):
        # Exercise the real cap with many distinct attacker-chosen type codes.
        data = section() + b"".join(block(0x80000000 + index) for index in range(100000))
        result = inspect_pcapng(data)
        self.assertEqual(result["blocks_inspected"], 100000)
        self.assertEqual(result["block_counts"]["other"], 99999)
        self.assertEqual(len(result["opaque_block_details"]), 16)
        self.assertTrue(result["scan_limited"])
        self.assertLess(result["inspected_bytes"], len(data))
        self.assertIn("remaining counts are unknown", " ".join(result["notes"]))

    def test_section_and_interface_caps(self):
        for data, key, expected in ((section() * 65, "section_count", 64),
                                    (section() + interface() * 257, "interface_count", 256)):
            result = inspect_pcapng(data)
            self.assertTrue(result["scan_limited"])
            self.assertEqual(result[key], expected)

    def test_per_block_and_global_option_caps_stop_before_current_block(self):
        data = section() + interface(options=option(1, b"") * 257)
        result = inspect_pcapng(data)
        self.assertEqual(result["interface_count"], 0)
        self.assertEqual(result["inspected_bytes"], 28)
        self.assertTrue(result["scan_limited"])
        with patch("wired2ai.pcapng.MAX_OPTIONS_TOTAL", 3):
            result = inspect_pcapng(section() + interface(options=option(1, b"") * 2) * 2)
            self.assertEqual(result["interface_count"], 1)
            self.assertTrue(result["scan_limited"])

    def test_unsupported_version_is_distinct(self):
        with self.assertRaises(UnsupportedPcapng):
            inspect_pcapng(section(version=(2, 0)))

    def test_capture_summary_survives_markdown_budget(self):
        data = section() + interface() * 200 + packet()
        report = Report("forensics", {"name": "example.pcapng"}, {})
        report.observation("file_snapshot", {})
        structure = inspect_pcapng(data)
        report.add("F002", "Container structure", "complete", structure, refs=["E001"])
        markdown = report.markdown(8192)
        self.assertIn("observed 1 supported packet records across 200 interfaces", markdown)
        self.assertIn("E001", markdown)
        self.assertLessEqual(len(markdown.encode()), 8192)


class PcapngCLITests(unittest.TestCase):
    def run_capture(self, root, data, category="auto"):
        source = root / "fixture.pcapng"
        source.write_bytes(data)
        output = root / category
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["triage", str(source), "--category", category, "--strict", "--out", str(output)])
        return code, json.loads((output / "report.json").read_text()), output

    def test_cli_is_metadata_only_across_category_overrides(self):
        sentinels = (b"PAYLOAD_MUST_STAY_PRIVATE_91827", b"COMMENT_MUST_STAY_PRIVATE_18279",
                     b"KEYLOG_MUST_STAY_PRIVATE_71289")
        data = (section(options=option(1, sentinels[1])) + interface() + packet(payload=sentinels[0]) +
                block(10, struct.pack("<II", 0x544C534B, len(sentinels[2])) + pad(sentinels[2])))
        with tempfile.TemporaryDirectory() as directory, patch.object(Runner, "run", side_effect=AssertionError("native collector invoked")):
            root = Path(directory)
            for category in ("auto", "forensics", "crypto", "re", "pwn"):
                code, report, output = self.run_capture(root, data, category)
                self.assertEqual(code, 0)
                self.assertTrue(all(c["status"] == "skipped" for c in report["checks"] if c["id"] in ("C003", "C004", "F003", "K002", "K003", "K004")))
                for path in output.rglob("*"):
                    if path.is_file():
                        for sentinel in sentinels:
                            self.assertNotIn(sentinel, path.read_bytes())
                            self.assertNotIn(sentinel.hex().encode(), path.read_bytes())
                if category in ("auto", "forensics"):
                    check = next(c for c in report["checks"] if c["id"] == "F002")
                    self.assertEqual(check["status"], "complete")
                    self.assertEqual(check["data"]["packet_records"], 1)
                    self.assertEqual(check["evidence_ids"], ["E001"])

    def test_cli_malformed_unsupported_and_partial_statuses(self):
        for data, expected, code in ((section() + b"junk", "failed", 1),
                                     (section(version=(2, 0)), "unsupported", 0),
                                     (section() + interface() + packet() * 33, "partial", 0)):
            with self.subTest(status=expected), tempfile.TemporaryDirectory() as directory:
                actual, report, _ = self.run_capture(Path(directory), data)
                check = next(c for c in report["checks"] if c["id"] == "F002")
                self.assertEqual(actual, code)
                self.assertEqual(check["status"], expected)
                if expected == "partial":
                    self.assertTrue(check["notes"])


if __name__ == "__main__":
    unittest.main()
