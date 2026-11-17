import contextlib
import io
import json
import runpy
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wired2ai.cli import main
from wired2ai.pe import PEImage, UnsupportedPE
from wired2ai.report import Report


ROOT = Path(__file__).resolve().parents[1]
image_bytes = runpy.run_path(str(ROOT / "examples/make_pe_demo.py"))["image_bytes"]
OPTIONAL = 0x58


def directory(data, index, address, size):
    fixed = 112 if struct.unpack_from("<H", data, OPTIONAL)[0] == 0x20B else 96
    struct.pack_into("<II", data, OPTIONAL + fixed + 8 * index, address, size)


def section_table(data):
    return OPTIONAL + struct.unpack_from("<H", data, 0x54)[0]


def roomy_fixture(size=65536):
    data = bytearray(image_bytes()[:0xC00])
    data.extend(b"\0" * (0x400 + size - len(data)))
    directory(data, 4, 0, 0)
    table = section_table(data)
    struct.pack_into("<I", data, table + 40 + 8, size)
    struct.pack_into("<I", data, table + 40 + 16, size)
    struct.pack_into("<I", data, OPTIONAL + 56, (0x2000 + size + 4095) & ~4095)
    return data


class PETests(unittest.TestCase):
    def test_pe32_and_pe32plus_names_ordinals_and_forwarders(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = PEImage(image_bytes(bits))
                header = image.header()
                self.assertEqual(header["optional_header"], "PE32" if bits == 32 else "PE32+")
                self.assertEqual(header["sections"], [".text", ".rdata"])
                self.assertEqual(image.layout()["entry_point"]["file_offset"], 0x200)
                imports = image.imports()
                self.assertEqual(imports["symbols_observed"], 2)
                self.assertEqual(imports["modules"][0]["dll"]["text"], "KERNEL32.dll")
                named, ordinal = imports["symbol_sample"]
                self.assertEqual(named["name"]["text"], "VirtualProtect")
                self.assertTrue(named["analysis_lead"])
                self.assertEqual(ordinal["ordinal"], 7)
                self.assertIsNone(ordinal["name"])
                exports = image.exports()["exports"]
                self.assertEqual([e["ordinal"] for e in exports], [1, 2, 3])
                self.assertEqual(exports[0]["names"][0]["text"], "DemoEntry")
                self.assertEqual(exports[1]["forwarder"]["text"], "KERNEL32.Sleep")
                self.assertEqual(exports[2]["names"], [])

    def test_every_truncated_core_prefix_and_hostile_declarations(self):
        original = image_bytes()
        for cut in range(0xC00):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                PEImage(original[:cut])
        for offset, fmt, value in ((0x3C, "I", 0xFFFFFFFF), (0x54, "H", 71),
                                   (OPTIONAL + 108, "I", 0xFFFFFFFF), (OPTIONAL + 60, "I", 0),
                                   (section_table(original) + 20, "I", 0xFFFFFFFF)):
            data = bytearray(original)
            struct.pack_into("<" + fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                PEImage(bytes(data))

    def test_unsupported_header_and_section_cap(self):
        for offset, value in ((OPTIONAL, 0x107), (0x46, 97)):
            data = bytearray(image_bytes())
            struct.pack_into("<H", data, offset, value)
            with self.assertRaises(UnsupportedPE):
                PEImage(bytes(data))

    def test_directory_count_and_optional_header_control_section_offset(self):
        data = bytearray(image_bytes())
        table = section_table(data)
        data[table + 8:table + 88] = data[table:table + 80]
        data[table:table + 8] = b"\0" * 8
        struct.pack_into("<H", data, 0x54, 248)
        struct.pack_into("<I", data, OPTIONAL + 108, 17)
        image = PEImage(bytes(data))
        self.assertEqual(image.header()["sections"], [".text", ".rdata"])
        self.assertTrue(image.header()["selection_truncated"])
        self.assertEqual(len(image.header()["data_directories"]), 16)

    def test_rva_mapping_does_not_confuse_virtual_tail_with_file_bytes(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, section_table(data) + 8, 0x800)
        image = PEImage(bytes(data))
        self.assertEqual(image.resolve(0x1000)[0], 0x200)
        self.assertEqual(image.resolve(0x80)[0], 0x80)
        with self.assertRaisesRegex(ValueError, "virtual-only"):
            image.resolve(0x1300)
        with self.assertRaisesRegex(ValueError, "32 bits|invalid RVA"):
            image.resolve(0xFFFFFFFF, 2)

    def test_ambiguous_sections_and_partial_overlap_are_rejected(self):
        data = bytearray(image_bytes())
        table = section_table(data)
        struct.pack_into("<I", data, table + 8, 0x2000)
        image = PEImage(bytes(data))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            image.imports()
        self.assertTrue(any("overlapping virtual" in note for note in image.layout()["anomalies"]))
        struct.pack_into("<I", data, table + 40 + 12, 0x1100)
        image = PEImage(bytes(data))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            image.resolve(0x10F0, 32)

    def test_raw_overlap_and_write_execute_are_observations(self):
        data = bytearray(image_bytes())
        table = section_table(data)
        struct.pack_into("<I", data, table + 40 + 20, 0x200)
        struct.pack_into("<I", data, table + 36, 0xE0000020)
        result = PEImage(bytes(data)).layout()
        self.assertTrue(any("overlapping raw" in a for a in result["anomalies"]))
        self.assertTrue(any("write and execute" in a for a in result["anomalies"]))
        self.assertEqual(result["mitigation_declarations"]["runtime_enforcement"], "unknown")

    def test_section_names_preserve_invalid_bytes(self):
        data = bytearray(image_bytes())
        raw = b".a\xff\x1b\\\0\0\0"
        table = section_table(data)
        data[table:table + 8] = raw
        section = PEImage(bytes(data)).layout()["sections"][0]
        self.assertEqual(section["name_hex"], raw.hex())
        self.assertEqual(section["name"], ".a\\xff\\x1b\\x5c")

    def test_entrypoint_absence_and_unmapped_entry_are_explicit(self):
        for rva in (0, 0xFFFFFFFF):
            data = bytearray(image_bytes())
            struct.pack_into("<I", data, OPTIONAL + 16, rva)
            result = PEImage(bytes(data)).layout()
            self.assertIsNone(result["entry_point"]["file_offset"])
            if rva:
                self.assertIn("mapping_error", result["entry_point"])
                self.assertTrue(result["anomalies"])
            else:
                self.assertIsNone(result["entry_point"]["preferred_va"])

    def test_section_entropy_limit_has_sample_provenance(self):
        result = PEImage(bytes(roomy_fixture(65537))).layout()
        sample = result["sections"][1]["entropy"]
        self.assertEqual((sample["sample_offset"], sample["sample_bytes"], sample["total_raw_bytes"]), (0x400, 65536, 65537))
        self.assertTrue(result["selection_truncated"])
        self.assertTrue(result["notes"])

    def test_certificate_offset_is_not_an_rva_or_proof_of_trust(self):
        image = PEImage(image_bytes())
        with self.assertRaises(ValueError):
            image.resolve(0xC00)
        result = image.layout()
        certificate = result["certificate_table"]
        self.assertEqual(certificate["entries"][0]["offset"], 0xC00)
        self.assertIn("not verified", certificate["verification"])
        self.assertEqual(result["trailing_data"]["bytes_after_sections"], 33)
        self.assertEqual(result["trailing_data"]["unclassified_ranges"], [{"offset": 0xC10, "length": 17}])

    def test_invalid_certificate_ranges_and_entry_lengths_fail(self):
        for offset, size, entry_length in ((0xC01, 16, 12), (0x200, 16, 12), (0xC00, 100, 12),
                                           (0xC00, 16, 7), (0xC00, 16, 0xFFFFFFFF)):
            data = bytearray(image_bytes())
            directory(data, 4, offset, size)
            struct.pack_into("<I", data, 0xC00, entry_length)
            with self.subTest(offset=offset, size=size, length=entry_length), self.assertRaisesRegex(ValueError, "certificate"):
                PEImage(bytes(data)).layout()

    def test_certificate_cap_does_not_hide_an_unchecked_tail(self):
        data = bytearray(image_bytes()[:0xC00])
        data.extend(struct.pack("<IHH", 8, 0x200, 2) * 65)
        directory(data, 4, 0xC00, 65 * 8)
        result = PEImage(bytes(data)).layout()
        self.assertFalse(result["certificate_table"]["framing_complete"])
        self.assertEqual(len(result["certificate_table"]["entries"]), 64)
        self.assertEqual(result["trailing_data"]["unclassified_bytes"], 65 * 8)
        self.assertTrue(result["selection_truncated"])

    def test_absent_and_inconsistent_import_export_directories(self):
        for index, method in ((1, "imports"), (0, "exports")):
            data = bytearray(image_bytes())
            directory(data, index, 0, 0)
            self.assertFalse(getattr(PEImage(bytes(data)), method)()["present"])
            directory(data, index, 0x2000, 0)
            with self.assertRaisesRegex(ValueError, "address/size"):
                getattr(PEImage(bytes(data)), method)()

    def test_import_lookup_fallback_and_bound_iat_ambiguity(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, 0x400, 0)
        result = PEImage(bytes(data)).imports()
        self.assertEqual(result["symbols_observed"], 2)
        self.assertEqual(result["modules"][0]["lookup_source"], "import_address_table")
        struct.pack_into("<I", data, 0x404, 0x1234)
        result = PEImage(bytes(data)).imports()
        self.assertEqual(result["symbols_observed"], 0)
        self.assertTrue(result["selection_truncated"])
        self.assertIn("unknown", " ".join(result["notes"]))

    def test_import_terminators_and_reserved_thunk_bits(self):
        data = bytearray(image_bytes())
        directory(data, 1, 0x2000, 20)
        with self.assertRaisesRegex(ValueError, "null terminator"):
            PEImage(bytes(data)).imports()
        for value in ((1 << 63) | (1 << 32) | 7, 1 << 32):
            data = bytearray(image_bytes())
            struct.pack_into("<Q", data, 0x480, value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "bits"):
                PEImage(bytes(data)).imports()

    def test_names_do_not_cross_file_backed_regions_and_long_names_are_partial(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, 0x40C, 0x27FC)
        data[0xBFC:0xC00] = b"ABCD"
        with self.assertRaisesRegex(ValueError, "terminator"):
            PEImage(bytes(data)).imports()
        struct.pack_into("<I", data, 0x40C, 0x2400)
        data[0x800:0x800 + 301] = b"A" * 300 + b"\0"
        result = PEImage(bytes(data)).imports()
        self.assertEqual(result["modules"][0]["dll"]["bytes_kept"], 256)
        self.assertTrue(result["selection_truncated"])

    def test_import_selection_boundary_and_late_analysis_lead(self):
        for count in (128, 129):
            data = roomy_fixture()
            struct.pack_into("<I", data, 0x400, 0x3000)
            values = [0x8000000000000007] * (count - 1) + [0x20C0, 0]
            struct.pack_into("<" + "Q" * len(values), data, 0x1400, *values)
            result = PEImage(bytes(data)).imports()
            self.assertEqual(result["symbols_observed"], count)
            self.assertEqual(len(result["symbol_sample"]), 128)
            self.assertTrue(any(s["analysis_lead"] for s in result["symbol_sample"]))
            self.assertEqual(result["selection_truncated"], count > 128)
            self.assertFalse(result["scan_limited"])

    def test_import_scan_cap_is_global_across_dlls(self):
        data = roomy_fixture()
        directory(data, 1, 0x2000, 60)
        struct.pack_into("<IIIII", data, 0x400, 0x3000, 0, 0, 0x2060, 0x20A0)
        struct.pack_into("<IIIII", data, 0x414, 0x9000, 0, 0, 0x2060, 0x20A0)
        values = [0x8000000000000007] * 2049 + [0]
        for offset in (0x1400, 0x7400):
            struct.pack_into("<" + "Q" * len(values), data, offset, *values)
        result = PEImage(bytes(data)).imports()
        self.assertEqual(result["symbols_observed"], 4096)
        self.assertEqual([m["imports_observed"] for m in result["modules"]], [2049, 2047])
        self.assertTrue(result["scan_limited"])

    def test_descriptor_cap_accepts_exact_limit_with_terminator(self):
        for count in (128, 129):
            data = roomy_fixture()
            directory(data, 1, 0x3000, (count + 1) * 20)
            struct.pack_into("<Q", data, 0x480, 0)
            descriptor = struct.pack("<IIIII", 0x2080, 0, 0, 0x2060, 0x20A0)
            data[0x1400:0x1400 + count * 20] = descriptor * count
            result = PEImage(bytes(data)).imports()
            self.assertEqual(len(result["modules"]), 128)
            self.assertEqual(result["descriptors_complete"], count == 128)
            self.assertEqual(result["scan_limited"], count > 128)

    def test_deferred_import_tables_are_disclosed(self):
        data = bytearray(image_bytes())
        directory(data, 13, 0x2400, 32)
        directory(data, 11, 0x2440, 8)
        result = PEImage(bytes(data)).imports()
        self.assertIn("delay-import", " ".join(result["notes"]))
        self.assertIn("bound-import", " ".join(result["notes"]))
        self.assertFalse(result["selection_truncated"])

    def test_export_ordinals_and_hostile_counts(self):
        for offset, fmt, value in ((0x658, "H", 3), (0x614, "I", 0xFFFFFFFF), (0x618, "I", 0xFFFFFFFF),
                                   (0x610, "I", 0xFFFFFFFF), (0x61C, "I", 0), (0x620, "I", 0), (0x624, "I", 0)):
            data = bytearray(image_bytes())
            struct.pack_into("<" + fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                PEImage(bytes(data)).exports()

    def test_export_forwarder_stops_at_directory_end(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, 0x644, 0x23FC)
        data[0x7FC:0x800] = b"A.BC"
        with self.assertRaisesRegex(ValueError, "terminator"):
            PEImage(bytes(data)).exports()

    def test_empty_export_slots_do_not_invent_functions(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, 0x648, 0)
        result = PEImage(bytes(data)).exports()
        self.assertEqual(result["empty_slots_observed"], 1)
        self.assertEqual(result["nonempty_slots_observed"], 2)
        struct.pack_into("<I", data, 0x640, 0)
        with self.assertRaisesRegex(ValueError, "empty address slot"):
            PEImage(bytes(data)).exports()

    def test_export_scan_and_selection_caps_keep_declared_counts(self):
        data = roomy_fixture()
        struct.pack_into("<II", data, 0x614, 4097, 0)
        struct.pack_into("<I", data, 0x61C, 0x3000)
        data[0x1400:0x1400 + 4097 * 4] = struct.pack("<I", 0x1000) * 4097
        result = PEImage(bytes(data)).exports()
        self.assertEqual(result["declared_address_slots"], 4097)
        self.assertEqual(result["address_slots_inspected"], 4096)
        self.assertEqual(len(result["exports"]), 128)
        self.assertIn("4096 of 4097", " ".join(result["notes"]))

    def test_export_aliases_are_bounded_and_report_omissions(self):
        data = bytearray(image_bytes())
        struct.pack_into("<I", data, 0x618, 9)
        struct.pack_into("<II", data, 0x620, 0x2300, 0x2340)
        for i in range(9):
            struct.pack_into("<I", data, 0x700 + 4 * i, 0x2500 + 32 * i)
            struct.pack_into("<H", data, 0x740 + 2 * i, 0)
            name = f"Alias{i}".encode() + b"\0"
            data[0x900 + 32 * i:0x900 + 32 * i + len(name)] = name
        result = PEImage(bytes(data)).exports()
        self.assertEqual(result["exports"][0]["names_observed"], 9)
        self.assertEqual(len(result["exports"][0]["names"]), 8)
        self.assertIn("Omitted 1", " ".join(result["notes"]))

    def test_compact_pe_observations_survive_small_brief(self):
        image = PEImage(image_bytes())
        report = Report("re", {"name": "fixture.bin"}, {})
        report.observation("file_snapshot", {})
        for suffix, method in (("001", image.header), ("002", image.layout), ("003", image.imports), ("004", image.exports)):
            report.add("R" + suffix, "PE observations", "complete", method(), refs=["E001"])
        text = report.markdown(8192)
        self.assertLessEqual(len(text.encode()), 8192)
        self.assertIn("PE32+", text)
        self.assertIn("17 remain unclassified", text)
        self.assertIn("2 ordinary import symbols observed", text)
        self.assertIn("3 nonempty exports", text)
        self.assertIn("Certificate trust is unverified", text)


class PEIntegrationTests(unittest.TestCase):
    def run_image(self, directory_path, data, category="re"):
        root = Path(directory_path)
        source, output = root / "fixture.bin", root / category
        source.write_bytes(data)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["triage", str(source), "--category", category, "--out", str(output), "--strict"])
        return code, json.loads((output / "report.json").read_text()), output

    def test_cli_both_categories_and_auto_include_pe_checks(self):
        with tempfile.TemporaryDirectory() as directory_path:
            for category in ("pwn", "re", "auto"):
                code, report, output = self.run_image(directory_path, image_bytes(), category)
                self.assertEqual(code, 0)
                checks = [c for c in report["checks"] if c["id"][0] in "PR" and c["id"][-1] in "1234"]
                self.assertEqual(len(checks), 4)
                self.assertTrue(all(c["status"] == "complete" and c["evidence_ids"] == ["E001"] for c in checks))
                self.assertTrue(all(e.get("argv", ["file"])[0] == "file" for e in report["evidence"]))
                self.assertLessEqual((output / "context.md").stat().st_size, 32768)

    def test_failed_import_does_not_hide_header_layout_or_exports(self):
        data = bytearray(image_bytes())
        directory(data, 1, 0xFFFFFFFF, 40)
        with tempfile.TemporaryDirectory() as directory_path:
            code, report, _ = self.run_image(directory_path, bytes(data))
        statuses = {c["id"]: c["status"] for c in report["checks"]}
        self.assertEqual(code, 1)
        self.assertEqual(statuses["R003"], "failed")
        self.assertTrue(all(statuses[c] == "complete" for c in ("R001", "R002", "R004")))

    def test_bad_headers_skip_dependents_and_unsupported_is_distinct(self):
        for offset, fmt, value, expected, exit_code in ((0x3C, "I", 0xFFFFFFFF, "failed", 1),
                                                       (OPTIONAL, "H", 0x107, "unsupported", 0)):
            data = bytearray(image_bytes())
            struct.pack_into("<" + fmt, data, offset, value)
            with tempfile.TemporaryDirectory() as directory_path:
                code, report, _ = self.run_image(directory_path, bytes(data))
            statuses = {c["id"]: c["status"] for c in report["checks"]}
            self.assertEqual(code, exit_code)
            self.assertEqual(statuses["R001"], expected)
            self.assertTrue(all(statuses[c] == "skipped" for c in ("R002", "R003", "R004")))

    @unittest.skipUnless(shutil.which("objdump"), "objdump is unavailable for an independent fixture comparison")
    def test_objdump_independently_reads_both_synthetic_formats(self):
        with tempfile.TemporaryDirectory() as directory_path:
            source = Path(directory_path) / "fixture.bin"
            for bits in (32, 64):
                source.write_bytes(image_bytes(bits))
                result = subprocess.run(["objdump", "-p", str(source)], capture_output=True, text=True, timeout=10, check=True)
                for expected in ("KERNEL32.dll", "VirtualProtect", "DemoEntry", "ForwardedSleep", "KERNEL32.Sleep", "NX_COMPAT", "DYNAMIC_BASE"):
                    self.assertIn(expected, result.stdout)
                self.assertIn("pei-x86-64" if bits == 64 else "pei-i386", result.stdout)

    @unittest.skipUnless(all(shutil.which(name) for name in ("as", "objcopy", "ld")), "GNU PE fixture build tools unavailable")
    def test_independent_linker_generated_pe_images_without_execution(self):
        emulations = subprocess.run(["ld", "-V"], capture_output=True, text=True, timeout=5, check=True).stdout
        if "i386pep" not in emulations or "i386pe" not in emulations:
            self.skipTest("linker lacks PE emulations")
        with tempfile.TemporaryDirectory() as directory_path:
            root = Path(directory_path)
            for bits, target, emulation, symbol in ((32, "pe-i386", "i386pe", "_entry"), (64, "pe-x86-64", "i386pep", "entry")):
                source = root / "fixture.s"
                source.write_text(f".text\n.globl {symbol}\n{symbol}:\n xorl %eax, %eax\n ret\n")
                elf, coff, binary = root / "fixture.o", root / "fixture.obj", root / "fixture.bin"
                for args in (["as", "--" + str(bits), "-o", str(elf), str(source)],
                             ["objcopy", "-O", target, str(elf), str(coff)],
                             ["ld", "-m", emulation, "--entry", symbol, "--subsystem", "console", "--export-all-symbols", "-o", str(binary), str(coff)]):
                    subprocess.run(args, capture_output=True, timeout=15, check=True)
                image = PEImage(binary.read_bytes())
                self.assertEqual(image.bits, bits)
                self.assertIsNotNone(image.layout()["entry_point"]["file_offset"])
                self.assertTrue(image.imports()["descriptors_complete"])
                names = [name["text"] for item in image.exports()["exports"] for name in item["names"]]
                self.assertIn("entry", names)


if __name__ == "__main__":
    unittest.main()
