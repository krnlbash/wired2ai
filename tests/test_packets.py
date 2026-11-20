import contextlib
import io
import json
import runpy
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wired2ai.cli import main
from wired2ai.forensics import inspect_pcap
from wired2ai.packets import PacketSummary
from wired2ai.pcapng import inspect_pcapng
from wired2ai.report import Report
from wired2ai.runner import Runner

FIXTURE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "examples/make_packet_demo.py"))
eth, ip4, ip6, udp, tcp = (FIXTURE[name] for name in ("ethernet", "ipv4", "ipv6", "udp", "tcp"))


def pcap(packets, link=1, endian="<", nano=False):
    header = struct.pack(endian + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    return header + b"".join(struct.pack(endian + "IIII", i, 1, len(p), len(p)) + p for i, p in enumerate(packets))


def ng_block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    return struct.pack(endian + "II", kind, len(body) + 12) + body + struct.pack(endian + "I", len(body) + 12)


def ng(packets, link=1, endian="<", kind=6):
    head = ng_block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    head += ng_block(1, struct.pack(endian + "HHI", link, 0, 65535), endian)
    for packet in packets:
        fields = (struct.pack(endian + "I", len(packet)) if kind == 3 else
                  struct.pack(endian + ("IIIII" if kind == 6 else "HHIIII"),
                              *([0, 0, 0, len(packet), len(packet)] if kind == 6 else [0, 0, 0, 0, len(packet), len(packet)])))
        head += ng_block(kind, fields + packet, endian)
    return head


def summary(data, kind="pcap"):
    collector = PacketSummary(data)
    structure = (inspect_pcap if kind == "pcap" else inspect_pcapng)(data, on_packet=collector.observe)
    return collector.finish(structure)


def detail(packet, link=1):
    return summary(pcap([packet], link))[1]["packet_sample"][0]


class PacketHeaderTests(unittest.TestCase):
    def test_literal_udp_wire_fixture_offsets(self):
        # Literal independent packet, IPv4 total length 32, UDP length 12.
        packet = bytes.fromhex("0000000000020000000000010800450000200001000040110000c0000201c6336402c3500035000c000074657374")
        item = detail(packet)
        self.assertEqual(item["outcome"], "decoded")
        self.assertEqual((item["source_port"], item["destination_port"]), (50000, 53))
        self.assertEqual((item["payload_offset"], item["network_offset"], item["transport_offset"]), (40, 54, 74))
        self.assertEqual(item["udp_declared_bytes"], 12)

    def test_classic_endian_and_timestamp_variants(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    status, result, _ = summary(pcap([eth(ip4(udp()))], endian=endian, nano=nano))
                    self.assertEqual(status, "complete")
                    self.assertEqual(result["transport_counts"], {"UDP": 1})

    def test_all_supported_link_types(self):
        v4, v6 = ip4(udp()), ip6(tcp(), 6)
        sll = struct.pack("!HHH8sH", 0, 1, 6, b"MACBYTES", 0x0800)
        sll2 = struct.pack("!HHIHBB8s", 0x86DD, 0, 4, 1, 0, 6, b"MACBYTES")
        for link, packet, proto in ((1, eth(v4), "UDP"), (101, v4, "UDP"), (101, v6, "TCP"),
                                    (228, v4, "UDP"), (229, v6, "TCP"), (113, sll + v4, "UDP"), (276, sll2 + v6, "TCP")):
            with self.subTest(link=link):
                item = detail(packet, link)
                self.assertEqual(item["outcome"], "decoded")
                self.assertEqual(item["transport"], proto)

    def test_wrong_explicit_ip_version(self):
        for link, packet in ((228, ip6(udp())), (229, ip4(udp()))):
            self.assertEqual(detail(packet, link)["outcome"], "malformed")

    def test_vlan_boundaries(self):
        body = ip4(udp())
        for count in (1, 2, 3):
            tags = b"".join(struct.pack("!HH", 123, 0x8100 if i < count - 1 else 0x0800) for i in range(count))
            item = detail(eth(tags + body, 0x88A8))
            self.assertEqual(item["outcome"], "decoded" if count <= 2 else "limited")
            if count <= 2: self.assertEqual(item["vlan_tags"], count)

    def test_ethernet_padding_cannot_complete_short_ip_header(self):
        packet = bytearray(ip4(tcp(), 6))
        packet[2:4] = struct.pack("!H", 30)
        item = detail(eth(bytes(packet) + b"\0" * 60))
        self.assertEqual(item["outcome"], "malformed")
        self.assertNotIn("source_port", item)

    def test_truncated_prefixes_never_read_out_of_bounds(self):
        for packet, link in ((eth(ip4(tcp(), 6)), 1), (ip6(udp()), 229)):
            for end in range(len(packet)):
                with self.subTest(link=link, end=end):
                    item = detail(packet[:end], link)
                    self.assertIn(item["outcome"], ("truncated", "malformed"))

    def test_ipv4_options_and_invalid_lengths(self):
        packet = bytearray(ip4(b"\0" * 4 + tcp(), 6)); packet[0] = 0x46
        self.assertEqual(detail(eth(bytes(packet)))["transport_offset"], 78)
        for ihl, total in ((4, 40), (6, 20)):
            broken = bytearray(packet); broken[0] = 0x40 | ihl; broken[2:4] = struct.pack("!H", total)
            self.assertEqual(detail(eth(bytes(broken)))["outcome"], "malformed")

    def test_ipv4_fragments_do_not_invent_transport_ports(self):
        for flags in (0x2000, 1, 0x2001):
            item = detail(eth(ip4(udp(), fragment=flags)))
            self.assertEqual(item["outcome"], "fragmented")
            self.assertNotIn("source_port", item)
        self.assertEqual(detail(eth(ip4(udp(), fragment=0x4000)))["outcome"], "decoded")

    def test_captured_payload_shorter_than_declared_still_keeps_header_evidence(self):
        item = detail(eth(ip4(udp()))[:-2])
        self.assertEqual(item["outcome"], "truncated")
        self.assertTrue(item["headers_decoded"])
        self.assertEqual(item["destination_port"], 4242)

    def test_udp_length_and_extra_ip_bytes(self):
        for length in (0, 7, 500):
            packet = struct.pack("!HHHH", 1, 2, length, 0) + b"X" * 4
            self.assertEqual(detail(eth(ip4(packet)))["outcome"], "malformed")
        packet = struct.pack("!HHHH", 1, 2, 8, 0) + b"extra"
        self.assertEqual(detail(eth(ip4(packet)))["outcome"], "decoded")

    def test_tcp_data_offset_and_flags(self):
        packet = bytearray(tcp(flags=0x12))
        self.assertEqual(detail(eth(ip4(bytes(packet), 6)))["tcp_flags"], 0x12)
        for offset in (4, 15):
            packet[12] = offset << 4
            self.assertEqual(detail(eth(ip4(bytes(packet), 6)))["outcome"], "malformed")

    def test_ipv6_extensions_and_atomic_fragment(self):
        fragment = bytes([17, 0]) + b"\0" * 6
        hop = bytes([44, 0]) + b"\0" * 6
        item = detail(eth(ip6(hop + fragment + udp(), 0), 0x86DD))
        self.assertEqual(item["transport"], "UDP")
        self.assertTrue(item["atomic_fragment"])
        self.assertEqual([x["type"] for x in item["ipv6_extensions"]], [0, 44])
        self.assertEqual(item["transport_offset"], 110)

    def test_ipv6_fragmented_packets_and_duplicate_fragment_headers(self):
        for field in (1, 8, 9):
            fragment = struct.pack("!BBHI", 17, 0, field, 1)
            item = detail(eth(ip6(fragment + udp(), 44), 0x86DD))
            self.assertEqual(item["outcome"], "fragmented")
            self.assertNotIn("source_port", item)
        fragment = bytes([44, 0]) + b"\0" * 6
        self.assertEqual(detail(eth(ip6(fragment * 2, 44), 0x86DD))["outcome"], "malformed")

    def test_ipv6_extension_count_and_byte_limits(self):
        for count in (8, 9):
            chain = b"".join(bytes([60 if i < count - 1 else 17, 0]) + b"\0" * 6 for i in range(count))
            self.assertEqual(detail(eth(ip6(chain + udp(), 60), 0x86DD))["outcome"], "decoded" if count == 8 else "limited")
        huge = bytes([17, 255]) + b"\0" * 2046
        self.assertEqual(detail(eth(ip6(huge + udp(), 60), 0x86DD))["outcome"], "limited")

    def test_ipv6_unimplemented_headers_and_no_next_header(self):
        for proto in (50, 51, 135):
            self.assertEqual(detail(eth(ip6(b"\0" * 12, proto), 0x86DD))["outcome"], "unsupported")
        self.assertEqual(detail(eth(ip6(b"", 59), 0x86DD))["transport"], "no next header")
        self.assertEqual(detail(eth(ip6(b"", 0), 0x86DD))["outcome"], "unsupported")

    def test_arp_and_icmp_prefixes(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + b"\0" * 20
        self.assertEqual(detail(eth(arp, 0x0806))["arp_operation"], 1)
        self.assertEqual(detail(eth(arp[:-1], 0x0806))["outcome"], "truncated")
        for version, proto, typ in ((4, 1, 8), (6, 58, 128)):
            body = bytes([typ, 0, 0, 0])
            item = detail(eth((ip4 if version == 4 else ip6)(body, proto), 0x0800 if version == 4 else 0x86DD))
            self.assertEqual((item["icmp_type"], item["icmp_code"]), (typ, 0))

    def test_unknown_link_ethertype_and_raw_version(self):
        for packet, link in ((b"secret", 999), (eth(b"secret", 0x88B5), 1), (b"\x70secret", 101)):
            self.assertEqual(detail(packet, link)["outcome"], "unsupported")


class PacketCollectionTests(unittest.TestCase):
    def test_pcapng_endian_sections_and_packet_block_forms(self):
        for kind in (2, 3, 6):
            data = ng([eth(ip4(udp()))], kind=kind) + ng([ip6(tcp(), 6)], link=229, endian=">", kind=kind)
            status, result, _ = summary(data, "pcapng")
            self.assertEqual(status, "complete")
            self.assertEqual(result["transport_counts"], {"UDP": 1, "TCP": 1})
            self.assertEqual([i["section_index"] for i in result["packet_sample"]], [0, 1])
            for item in result["packet_sample"]:
                self.assertEqual(data[item["network_offset"]] >> 4, 4 if item["section_index"] == 0 else 6)

    def test_summary_is_not_limited_to_container_packet_sample(self):
        status, result, notes = summary(ng([eth(ip4(udp()))] * 40), "pcapng")
        self.assertEqual(status, "partial")
        self.assertEqual(result["transport_counts"], {"UDP": 40})
        self.assertEqual(len(result["packet_sample"]), 32)
        self.assertIn("Kept 32 of 40", " ".join(notes))

    def test_packet_scan_limit_is_exact(self):
        for count in (10000, 10001):
            with self.subTest(count=count):
                _, result, notes = summary(pcap([eth(ip4(udp()))] * count))
                self.assertEqual(result["packets_inspected"], 10000)
                self.assertEqual(result["packet_records_available"], count)
                self.assertEqual(result["scan_limited"], count > 10000)
                self.assertEqual(result["transport_counts"], {"UDP": 10000})
                if count > 10000: self.assertIn("10000 of 10001", " ".join(notes))

    def test_container_scan_limit_propagates(self):
        with patch("wired2ai.pcapng.MAX_BLOCKS", 3):
            status, result, notes = summary(ng([eth(ip4(udp()))] * 2), "pcapng")
        self.assertEqual(status, "partial")
        self.assertTrue(result["container_scan_limited"])
        self.assertEqual(result["packet_records_available"], 1)
        self.assertIn("unknown", " ".join(notes))

    def test_port_pair_table_caps_occurrences_and_retains_existing_counts(self):
        packets = [eth(ip4(udp(source=i))) for i in range(65)] + [eth(ip4(udp(source=0)))]
        _, result, notes = summary(pcap(packets))
        self.assertEqual(len(result["port_pairs"]), 64)
        self.assertEqual(result["port_pair_occurrences_omitted"], 1)
        self.assertEqual(result["port_pairs"][0]["packets"], 2)
        self.assertIn("Unique omitted pair count is unknown", " ".join(notes))

    def test_link_and_issue_tables_are_bounded(self):
        data = b"".join(ng([b"x"], link=1000 + i) for i in range(40))
        status, result, notes = summary(data, "pcapng")
        self.assertEqual(status, "unsupported")
        self.assertEqual(len(result["link_types"]), 32)
        self.assertEqual(result["link_type_occurrences_omitted"], 8)
        self.assertEqual(len(result["packet_issues"]), 16)
        self.assertEqual(result["packet_issues_seen"], 40)
        self.assertIn("Kept 16 of 40", " ".join(notes))

    def test_classic_link_additional_bits_and_rejected_reserved_bits(self):
        _, result, _ = summary(pcap([eth(ip4(udp())) + b"\0" * 4], link=0x24000001))
        self.assertEqual(result["link_types"][0]["link_type"], 1)
        for field in (0x10001, 0x08000001):
            with self.assertRaisesRegex(ValueError, "reserved"):
                inspect_pcap(pcap([], link=field))
        with self.assertRaisesRegex(ValueError, "magic"):
            inspect_pcap(b"X" * 24)

    def test_empty_capture_and_malformed_packet_are_distinct(self):
        self.assertEqual(summary(pcap([]))[0], "no_match")
        status, result, _ = summary(pcap([eth(ip4(b"\0" * 4))]))
        self.assertEqual(status, "partial")
        self.assertEqual(result["outcome_counts"]["malformed"], 1)

    def test_short_original_length_is_not_decoded(self):
        capture = bytearray(pcap([eth(ip4(udp()))])); capture[36:40] = struct.pack("<I", 1)
        _, result, _ = summary(bytes(capture))
        self.assertEqual(result["outcome_counts"]["malformed"], 1)
        self.assertEqual(result["port_pairs"], [])

    def test_late_issue_keeps_its_original_offset(self):
        data = pcap([eth(ip4(udp()))] * 40 + [b"\0"])
        _, result, _ = summary(data)
        issue = result["packet_issues"][0]
        self.assertEqual(issue["record_index"], 40)
        self.assertEqual(issue["payload_offset"], len(data) - 1)

    def test_compact_markdown_keeps_packet_counts(self):
        status, data, notes = summary(pcap([eth(ip4(udp()))] * 40))
        report = Report("forensics", {}, {})
        report.observation("file_snapshot", {})
        report.add("F004", "Packet protocol summary", status, data, refs=["E001"], notes=notes)
        brief = report.markdown(8192)
        self.assertIn("UDP=40", brief)
        self.assertIn("40 of 40 admitted records", brief)
        self.assertLessEqual(len(brief.encode()), 8192)


class PacketCLITests(unittest.TestCase):
    def run_capture(self, data, root, category="auto"):
        source, out = root / "fixture.bin", root / category
        source.write_bytes(data)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["triage", str(source), "--category", category, "--strict", "--out", str(out)])
        return code, json.loads((out / "report.json").read_text()), out

    def test_capture_omission_policy_across_categories(self):
        sentinel = b"CAPTURE_BODY_DO_NOT_EXPORT_839472"
        # Deliberately unknown EtherType: bodies must stay private even when unsupported.
        packet = eth(sentinel, 0x88B5)
        for capture in (pcap([packet]), ng([packet])):
            with tempfile.TemporaryDirectory() as directory, patch.object(Runner, "run", side_effect=AssertionError("native capture collector invoked")):
                for category in ("auto", "forensics", "crypto", "pwn", "re"):
                    code, report, output = self.run_capture(capture, Path(directory), category)
                    self.assertEqual(code, 0)
                    for file in output.rglob("*"):
                        if file.is_file():
                            self.assertNotIn(sentinel, file.read_bytes())
                            self.assertNotIn(sentinel.hex().encode(), file.read_bytes())

    def test_addresses_and_payloads_are_not_serialized(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report, output = self.run_capture(FIXTURE["capture_bytes"](), Path(directory))
            self.assertEqual(code, 0)
            check = next(c for c in report["checks"] if c["id"] == "F004")
            self.assertEqual(check["status"], "partial")
            self.assertEqual(check["data"]["packets_inspected"], 8)
            for file in output.rglob("*"):
                if file.is_file():
                    text = file.read_text()
                    for value in ("192.0.2.1", "198.51.100.2", "2001:db8", "c0000201", "SYNTHETIC_PAYLOAD_NOT_FOR_EXPORT", "UNSUPPORTED_BODY_PRIVATE"):
                        self.assertNotIn(value, text)

    def test_container_failure_discards_previous_packet_results(self):
        for capture in (pcap([eth(ip4(udp()))]) + b"x", ng([eth(ip4(udp()))]) + b"x"):
            with tempfile.TemporaryDirectory() as directory:
                code, report, _ = self.run_capture(capture, Path(directory))
                self.assertEqual(code, 1)
                check = next(c for c in report["checks"] if c["id"] == "F004")
                self.assertEqual(check["status"], "skipped")
                self.assertEqual(check["data"], {})
                self.assertIn("discarded", " ".join(check["notes"]))


if __name__ == "__main__":
    unittest.main()
