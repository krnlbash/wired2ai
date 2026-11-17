"""Bounded static PE32/PE32+ metadata; never load an image or resolve a DLL.

Layout reference: Microsoft's PE/COFF specification. This is a triage subset,
not a Windows loader, disassembler, Authenticode verifier or conformance checker.
"""

from __future__ import annotations

import math
import struct
from collections import Counter

MAX_SECTIONS = 96
MAX_DESCRIPTORS = 128
MAX_THUNKS = 4096
MAX_EXPORT_SLOTS = 4096
MAX_EXPORT_NAMES = 4096
SYMBOL_SAMPLE = 128
MAX_ALIASES = 8
MAX_NAME_BYTES = 256
ENTROPY_SAMPLE = 65536
MAX_CERTIFICATES = 64
MAX_ANOMALIES = 80
MACHINES = {0x14C: "i386", 0x8664: "amd64", 0x1C4: "arm_thumb2", 0xAA64: "arm64"}
DIRECTORIES = ("exports", "imports", "resources", "exceptions", "certificates", "base_relocations",
               "debug", "architecture", "global_pointer", "tls", "load_configuration", "bound_imports",
               "import_address_table", "delay_imports", "clr", "reserved")
IMPORT_LEADS = {"gets", "strcpy", "strcat", "sprintf", "system", "WinExec", "ShellExecuteA",
                "ShellExecuteW", "CreateProcessA", "CreateProcessW", "VirtualAlloc", "VirtualProtect",
                "LoadLibraryA", "LoadLibraryW", "GetProcAddress"}


class UnsupportedPE(ValueError):
    pass


def escaped(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 and value != 92 else f"\\x{value:02x}" for value in raw)


class PEImage:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("PE: missing or truncated DOS header")
        self.pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if self.pe_offset < 64 or self.pe_offset + 24 > len(data) or data[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise ValueError("PE: invalid or out-of-bounds PE signature offset")
        (self.machine, count, self.timestamp, self.symbol_pointer, self.symbol_count,
         size, self.characteristics) = struct.unpack_from("<HHIIIHH", data, self.pe_offset + 4)
        if count > MAX_SECTIONS:
            raise UnsupportedPE(f"PE: {count} sections exceed the supported limit {MAX_SECTIONS}")
        self.optional_offset = self.pe_offset + 24
        optional = self.optional_offset
        if size < 2 or optional + size > len(data):
            raise ValueError("PE: truncated optional header")
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in (0x10B, 0x20B):
            raise UnsupportedPE(f"PE: optional-header magic 0x{magic:04x} is unsupported")
        self.bits = 64 if magic == 0x20B else 32
        fixed_size = 112 if self.bits == 64 else 96
        if size < fixed_size:
            raise ValueError("PE: optional header is shorter than its fixed fields")
        self.directory_count = struct.unpack_from("<I", data, optional + fixed_size - 4)[0]
        if self.directory_count > (size - fixed_size) // 8:
            raise ValueError("PE: data-directory count exceeds optional-header bounds")
        self.entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
        self.image_base = struct.unpack_from("<Q" if self.bits == 64 else "<I", data, optional + (24 if self.bits == 64 else 28))[0]
        self.section_alignment, self.file_alignment = struct.unpack_from("<II", data, optional + 32)
        self.image_size, self.header_size = struct.unpack_from("<II", data, optional + 56)
        self.subsystem, self.dll_flags = struct.unpack_from("<HH", data, optional + 68)
        section_table = optional + size
        if section_table + count * 40 > len(data):
            raise ValueError("PE: section table exceeds input length")
        if not section_table + count * 40 <= self.header_size <= len(data):
            raise ValueError("PE: SizeOfHeaders does not cover the table or exceeds input length")
        self.sections = []
        for index in range(count):
            offset = section_table + index * 40
            name = data[offset:offset + 8]
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
            flags = struct.unpack_from("<I", data, offset + 36)[0]
            if raw_size and raw_offset + raw_size > len(data):
                raise ValueError(f"PE: section {index} raw range exceeds input at header offset {offset}")
            if rva + max(virtual_size, raw_size) > 0x100000000:
                raise ValueError(f"PE: section {index} RVA range exceeds 32 bits at header offset {offset}")
            self.sections.append({"index": index, "header_offset": offset, "name": escaped(name.rstrip(b"\0")),
                                  "name_hex": name.hex(), "rva": rva, "virtual_bytes": virtual_size,
                                  "raw_offset": raw_offset, "raw_bytes": raw_size, "characteristics": hex(flags),
                                  "read": bool(flags & 0x40000000), "write": bool(flags & 0x80000000),
                                  "execute": bool(flags & 0x20000000)})
        self.directories = []
        for index in range(min(self.directory_count, len(DIRECTORIES))):
            offset = optional + fixed_size + index * 8
            address, length = struct.unpack_from("<II", data, offset)
            self.directories.append({"index": index, "name": DIRECTORIES[index], "entry_offset": offset,
                                     "address": address, "size": length,
                                     "address_kind": "file_offset" if index == 4 else "rva"})

    def directory(self, index: int) -> dict:
        if index >= len(self.directories):
            return {"address": 0, "size": 0, "name": DIRECTORIES[index]}
        return self.directories[index]

    def declared(self, index: int) -> bool:
        item = self.directory(index)
        return bool(item["address"] or item["size"])

    def directory_range(self, index: int) -> tuple[int, int] | None:
        item = self.directory(index)
        start, size = item["address"], item["size"]
        if start == size == 0:
            return None
        if not start or not size:
            raise ValueError(f"PE: inconsistent {item['name']} directory address/size")
        offset, _, _ = self.resolve(start, size)
        return offset, offset + size

    def resolve(self, rva: int, length: int = 1) -> tuple[int, int, int | None]:
        """Map a wholly file-backed, unambiguous span in one region.

        Returned availability stops before another virtual region begins, so
        bounded string scans cannot cross into an ambiguous mapping unnoticed.
        """
        if rva < 0 or length < 1 or rva + length > 0x100000000:
            raise ValueError(f"PE: invalid RVA range 0x{rva:x} + {length}")
        regions = [(0, self.header_size, 0, self.header_size, None)]
        regions.extend((s["rva"], s["rva"] + max(s["virtual_bytes"], s["raw_bytes"]),
                        s["raw_offset"], s["raw_bytes"], s["index"]) for s in self.sections
                       if max(s["virtual_bytes"], s["raw_bytes"]))
        matches = [region for region in regions if rva < region[1] and rva + length > region[0]]
        if len(matches) != 1:
            raise ValueError(f"PE: RVA 0x{rva:x} is unmapped, crosses regions or has ambiguous overlapping mappings")
        start, end, raw_offset, raw_size, index = matches[0]
        if rva < start or rva + length > end or rva - start + length > raw_size:
            raise ValueError(f"PE: RVA 0x{rva:x} reaches virtual-only bytes or crosses a raw region")
        offset = raw_offset + rva - start
        if offset + length > len(self.data):
            raise ValueError(f"PE: RVA 0x{rva:x} maps beyond input")
        available = min(raw_size - (rva - start), len(self.data) - offset)
        for other_start, _, _, _, _ in regions:
            if other_start > rva:
                available = min(available, other_start - rva)
        return offset, available, index

    def name(self, rva: int, *, end_rva: int | None = None) -> dict:
        if not rva:
            raise ValueError("PE: null RVA for required name")
        offset, available, _ = self.resolve(rva)
        if end_rva is not None:
            available = min(available, end_rva - rva)
        stop = offset + min(available, MAX_NAME_BYTES + 1)
        terminator = self.data.find(b"\0", offset, stop)
        if terminator >= 0:
            raw, truncated = self.data[offset:terminator], False
        elif available > MAX_NAME_BYTES:
            raw, truncated = self.data[offset:offset + MAX_NAME_BYTES], True
        else:
            raise ValueError(f"PE: name at RVA 0x{rva:x}, file offset {offset}, has no terminator within its region")
        if not raw:
            raise ValueError(f"PE: empty name at RVA 0x{rva:x}, file offset {offset}")
        return {"text": escaped(raw), "rva": rva, "offset": offset, "bytes_kept": len(raw), "truncated": truncated}

    def header(self) -> dict:
        extra = max(0, self.directory_count - len(DIRECTORIES))
        return {"format": "pe", "pe_header_offset": self.pe_offset, "machine_code": hex(self.machine),
                "machine": MACHINES.get(self.machine, "unrecognized; retain machine_code"),
                "optional_header": "PE32+" if self.bits == 64 else "PE32", "image_base": hex(self.image_base),
                "entry_point_rva": self.entry_rva, "subsystem_code": self.subsystem,
                "size_of_image": self.image_size, "size_of_headers": self.header_size,
                "section_alignment": self.section_alignment, "file_alignment": self.file_alignment,
                "sections": [s["name"] for s in self.sections], "section_count": len(self.sections),
                "coff_timestamp_untrusted": self.timestamp, "characteristics": hex(self.characteristics),
                "dll_flag": bool(self.characteristics & 0x2000), "dll_characteristics": hex(self.dll_flags),
                "dynamic_base_flag": bool(self.dll_flags & 0x40), "nx_compat_flag": bool(self.dll_flags & 0x100),
                "cfg_flag": bool(self.dll_flags & 0x4000), "data_directories": self.directories,
                "coff_symbol_table": {"file_offset": self.symbol_pointer, "declared_entries": self.symbol_count,
                                      "decoded": False},
                "selection_truncated": bool(extra),
                "limits": {"sections": MAX_SECTIONS, "recognized_directories": len(DIRECTORIES)},
                "notes": [f"{extra} directory entries beyond the 16 recognized slots were not interpreted."] if extra else [],
                "scope": "Static header declarations. COFF timestamps are untrusted; directories are not all validated. "
                         "Header flags do not prove runtime protection or exploitability."}

    def certificates(self) -> dict:
        directory = self.directory(4)
        start, size = directory["address"], directory["size"]
        result = {"declared": bool(start or size), "offset": start, "declared_bytes": size,
                  "entries": [], "framing_complete": True, "verification": "Authenticode and certificate trust not verified"}
        if start == size == 0:
            return result
        if not start or not size or start % 8 or start + size > len(self.data):
            raise ValueError("PE: certificate table has invalid alignment or file bounds (address is a file offset)")
        ranges = [(0, self.header_size)] + [(s["raw_offset"], s["raw_offset"] + s["raw_bytes"])
                                          for s in self.sections if s["raw_bytes"]]
        if any(start < end and start + size > begin for begin, end in ranges):
            raise ValueError("PE: certificate table overlaps headers or section raw data")
        cursor, end = start, start + size
        while cursor < end:
            if len(result["entries"]) >= MAX_CERTIFICATES:
                result["framing_complete"] = False
                break
            if cursor + 8 > end:
                raise ValueError(f"PE: truncated certificate entry at file offset {cursor}")
            length, revision, kind = struct.unpack_from("<IHH", self.data, cursor)
            padded = (length + 7) & ~7
            if length < 8 or cursor + padded > end:
                raise ValueError(f"PE: invalid certificate entry length at file offset {cursor}")
            result["entries"].append({"offset": cursor, "length": length, "revision": hex(revision), "type": hex(kind)})
            cursor += padded
        result["inspected_bytes"] = cursor - start
        return result

    def layout(self) -> dict:
        anomalies, observed = [], 0

        def anomaly(message: str) -> None:
            nonlocal observed
            observed += 1
            if len(anomalies) < MAX_ANOMALIES:
                anomalies.append(message)

        sections = []
        sampled = 0
        for section in self.sections:
            start, size = section["raw_offset"], section["raw_bytes"]
            sample = self.data[start:start + min(size, ENTROPY_SAMPLE)]
            counts = Counter(sample)
            entropy = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts.values()) if sample else None
            sampled += size > len(sample)
            sections.append({**section, "entropy": {"sample_offset": start, "sample_bytes": len(sample),
                                                     "total_raw_bytes": size, "sample_truncated": size > len(sample),
                                                     "bits_per_byte": round(entropy, 5) if entropy is not None else None}})
            if size and start < self.header_size:
                anomaly(f"Section {section['index']} raw data overlaps headers")
            if section["execute"] and section["write"]:
                anomaly(f"Section {section['index']} declares both write and execute permissions")
            if max(section["virtual_bytes"], size) and section["rva"] < self.header_size:
                anomaly(f"Section {section['index']} virtual range overlaps headers")
        for i, left in enumerate(self.sections):
            for right in self.sections[i + 1:]:
                for label, start_key, size_key in (("raw", "raw_offset", "raw_bytes"), ("virtual", "rva", "virtual_bytes")):
                    left_size = left[size_key] if label == "raw" else max(left["virtual_bytes"], left["raw_bytes"])
                    right_size = right[size_key] if label == "raw" else max(right["virtual_bytes"], right["raw_bytes"])
                    if left_size and right_size and max(left[start_key], right[start_key]) < min(left[start_key] + left_size, right[start_key] + right_size):
                        anomaly(f"Sections {left['index']} and {right['index']} have overlapping {label} ranges")
        entry = {"rva": self.entry_rva, "preferred_va": hex(self.image_base + self.entry_rva) if self.entry_rva else None,
                 "file_offset": None, "section_index": None}
        if self.entry_rva:
            try:
                entry["file_offset"], _, entry["section_index"] = self.resolve(self.entry_rva)
                if entry["section_index"] is None:
                    anomaly("Entry point maps to headers")
                elif not self.sections[entry["section_index"]]["execute"]:
                    anomaly("Entry point maps to a section without execute permission")
            except ValueError as exc:
                entry["mapping_error"] = str(exc)
                anomaly("Entry point has no unambiguous file-backed byte mapping")
        certs = self.certificates()
        end = max([self.header_size] + [s["raw_offset"] + s["raw_bytes"] for s in self.sections if s["raw_bytes"]])
        tail = []
        if end < len(self.data):
            if certs["declared"] and certs["framing_complete"] and certs["offset"] >= end:
                if certs["offset"] > end:
                    tail.append({"offset": end, "length": certs["offset"] - end})
                after = certs["offset"] + certs["declared_bytes"]
                if after < len(self.data):
                    tail.append({"offset": after, "length": len(self.data) - after})
            else:
                tail.append({"offset": end, "length": len(self.data) - end})
        notes = []
        if sampled:
            notes.append(f"Entropy sampled the first {ENTROPY_SAMPLE} bytes of {sampled} larger sections; per-section sample counts are included.")
        if observed > len(anomalies):
            notes.append(f"Kept {len(anomalies)} of {observed} layout observations.")
        if not certs["framing_complete"]:
            notes.append(f"Certificate framing stopped after {MAX_CERTIFICATES} entries; its declared range was not excluded from trailing data.")
        return {"format": "pe", "entry_point": entry,
                "mitigation_declarations": {"dynamic_base": bool(self.dll_flags & 0x40), "nx_compat": bool(self.dll_flags & 0x100),
                    "high_entropy_va": bool(self.dll_flags & 0x20), "guard_cf": bool(self.dll_flags & 0x4000),
                    "no_seh": bool(self.dll_flags & 0x400), "relocations_stripped": bool(self.characteristics & 1),
                    "base_relocation_directory_declared": self.declared(5), "load_config_directory_declared": self.declared(10),
                    "runtime_enforcement": "unknown", "canary_and_safe_seh": "not determined"},
                "trailing_data": {"after_sections_offset": end, "bytes_after_sections": len(self.data) - end,
                                  "unclassified_ranges": tail, "unclassified_bytes": sum(r["length"] for r in tail),
                                  "note": "Excludes only fully framed certificate tables. Padding, debug/COFF data and other legitimate data may remain; not a hidden-content verdict."},
                "certificate_table": certs, "anomalies": anomalies, "anomalies_seen": observed, "sections": sections,
                "selection_truncated": bool(notes), "notes": notes,
                "limits": {"entropy_bytes_per_section": ENTROPY_SAMPLE, "certificate_entries": MAX_CERTIFICATES,
                           "anomalies": MAX_ANOMALIES},
                "scope": "Static layout and flag observations only. Entropy does not identify packing/encryption. "
                         "Relocations, load configuration, TLS, resources and certificate payloads are not decoded."}

    def imports(self) -> dict:
        bounds = self.directory_range(1)
        modules, symbols, notes = [], [], []
        total, truncated_names, incomplete_lookups = 0, 0, 0
        terminated, scan_limited = bounds is None, False
        if bounds:
            cursor, end = bounds
            while cursor + 20 <= end:
                lookup, stamp, chain, name_rva, iat = struct.unpack_from("<IIIII", self.data, cursor)
                if (lookup, stamp, chain, name_rva, iat) == (0, 0, 0, 0, 0):
                    terminated = True
                    break
                if len(modules) >= MAX_DESCRIPTORS:
                    scan_limited = True
                    notes.append(f"Stopped before another import descriptor at limit {MAX_DESCRIPTORS}; remaining DLL/import counts are unknown.")
                    break
                dll = self.name(name_rva)
                truncated_names += dll["truncated"]
                module = {"index": len(modules), "descriptor_offset": cursor, "dll": dll, "lookup_rva": lookup or iat,
                          "lookup_source": "original_lookup_table" if lookup else "import_address_table",
                          "iat_rva": iat, "timestamp_untrusted": stamp, "imports_observed": 0, "lookup_complete": False}
                modules.append(module)
                cursor += 20
                if not lookup and stamp:
                    module["lookup_note"] = "Bound IAT without an original lookup table; addresses are not interpreted as symbol names."
                    incomplete_lookups += 1
                    continue
                if not (lookup or iat):
                    raise ValueError(f"PE: import descriptor at offset {cursor - 20} has no lookup table")
                width = self.bits // 8
                table = lookup or iat
                index = 0
                while True:
                    offset, _, _ = self.resolve(table + index * width, width)
                    value = struct.unpack_from("<Q" if width == 8 else "<I", self.data, offset)[0]
                    if value == 0:
                        module["lookup_complete"] = True
                        break
                    if total >= MAX_THUNKS:
                        scan_limited = True
                        notes.append(f"Stopped at {MAX_THUNKS} import thunks across all DLLs; remaining counts are unknown.")
                        break
                    item = {"module_index": module["index"], "thunk_offset": offset, "thunk_rva": table + index * width,
                            "ordinal": None, "name": None, "analysis_lead": False}
                    ordinal_bit = 1 << (self.bits - 1)
                    if value & ordinal_bit:
                        if value & ~(ordinal_bit | 0xFFFF):
                            raise ValueError(f"PE: reserved ordinal-thunk bits set at file offset {offset}")
                        item["ordinal"] = value & 0xFFFF
                    else:
                        if value > 0x7FFFFFFF:
                            raise ValueError(f"PE: invalid name-thunk RVA bits at file offset {offset}")
                        hint_offset, _, _ = self.resolve(value, 2)
                        item["hint"] = struct.unpack_from("<H", self.data, hint_offset)[0]
                        item["name"] = self.name(value + 2)
                        truncated_names += item["name"]["truncated"]
                        item["analysis_lead"] = not item["name"]["truncated"] and item["name"]["text"] in IMPORT_LEADS
                    if len(symbols) < SYMBOL_SAMPLE:
                        symbols.append(item)
                    elif item["analysis_lead"]:
                        replace = next((i for i in range(len(symbols) - 1, -1, -1) if not symbols[i]["analysis_lead"]), None)
                        if replace is not None:
                            symbols[replace] = item
                    module["imports_observed"] += 1
                    total += 1
                    index += 1
                if scan_limited:
                    break
            if not terminated and not scan_limited:
                raise ValueError("PE: import descriptors lack a null terminator within the declared directory")
        if total > len(symbols):
            notes.append(f"Kept {len(symbols)} of {total} observed import symbols; exact analysis leads are prioritized.")
        if truncated_names:
            notes.append(f"{truncated_names} names exceed the {MAX_NAME_BYTES}-byte preview limit; only prefixes are retained.")
        if incomplete_lookups:
            notes.append(f"{incomplete_lookups} bound IATs lacked original lookup tables; their symbol counts are unknown.")
        partial = bool(notes)
        if self.declared(13):
            notes.append("A delay-import directory is declared but not decoded; this check covers ordinary imports only.")
        if self.declared(11):
            notes.append("A bound-import directory is declared but not decoded.")
        return {"format": "pe", "present": bounds is not None, "directory": self.directory(1), "modules": modules,
                "descriptors_complete": terminated, "symbols_observed": total, "symbol_sample": symbols,
                "scan_limited": scan_limited, "selection_truncated": partial, "notes": notes,
                "limits": {"descriptors": MAX_DESCRIPTORS, "thunks_total": MAX_THUNKS,
                           "symbol_sample": SYMBOL_SAMPLE, "name_bytes": MAX_NAME_BYTES},
                "scope": "Ordinary disk import declarations, not resolved dependencies or vulnerability findings. "
                         "No DLLs are loaded. Ordinals are retained without inventing names."}

    def exports(self) -> dict:
        bounds = self.directory_range(0)
        if bounds is None:
            return {"format": "pe", "present": False, "exports": [], "selection_truncated": False, "notes": []}
        start, end = bounds
        if end - start < 40:
            raise ValueError("PE: export directory is shorter than 40 bytes")
        (_, stamp, _, _, dll_rva, base, function_count, name_count,
         addresses_rva, names_rva, ordinals_rva) = struct.unpack_from("<IIHHIIIIIII", self.data, start)
        if name_count and not function_count:
            raise ValueError("PE: export names exist without address slots")
        if (function_count and not addresses_rva) or (name_count and (not names_rva or not ordinals_rva)):
            raise ValueError("PE: required export array has a null RVA")
        if function_count and base + function_count - 1 > 0xFFFFFFFF:
            raise ValueError("PE: export ordinal range exceeds 32 bits")
        address_offset = self.resolve(addresses_rva, function_count * 4)[0] if function_count else 0
        names_offset = self.resolve(names_rva, name_count * 4)[0] if name_count else 0
        ordinals_offset = self.resolve(ordinals_rva, name_count * 2)[0] if name_count else 0
        dll = self.name(dll_rva) if dll_rva else None
        truncated_names = int(bool(dll and dll["truncated"]))
        aliases, alias_seen = {}, Counter()
        names_inspected = min(name_count, MAX_EXPORT_NAMES)
        for i in range(names_inspected):
            ordinal_index = struct.unpack_from("<H", self.data, ordinals_offset + 2 * i)[0]
            if ordinal_index >= function_count:
                raise ValueError(f"PE: export name ordinal index {ordinal_index} exceeds address-slot count")
            name_rva = struct.unpack_from("<I", self.data, names_offset + 4 * i)[0]
            name = self.name(name_rva)
            truncated_names += name["truncated"]
            alias_seen[ordinal_index] += 1
            values = aliases.setdefault(ordinal_index, [])
            if len(values) < MAX_ALIASES:
                values.append({**name, "name_pointer_offset": names_offset + 4 * i,
                               "ordinal_index_offset": ordinals_offset + 2 * i})
        exports, active, holes, omitted_aliases = [], 0, 0, 0
        slots_inspected = min(function_count, MAX_EXPORT_SLOTS)
        directory = self.directory(0)
        for index in range(slots_inspected):
            slot_offset = address_offset + 4 * index
            rva = struct.unpack_from("<I", self.data, slot_offset)[0]
            if not rva:
                holes += 1
                if alias_seen[index]:
                    raise ValueError(f"PE: export name references an empty address slot at offset {slot_offset}")
                continue
            active += 1
            item = {"ordinal": base + index, "address_slot_offset": slot_offset, "rva": rva,
                    "names": aliases.get(index, []), "names_observed": alias_seen[index], "forwarder": None}
            omitted_aliases += max(0, alias_seen[index] - len(item["names"]))
            if directory["address"] <= rva < directory["address"] + directory["size"]:
                item["forwarder"] = self.name(rva, end_rva=directory["address"] + directory["size"])
                truncated_names += item["forwarder"]["truncated"]
            if len(exports) < SYMBOL_SAMPLE:
                exports.append(item)
        notes = []
        if slots_inspected < function_count or names_inspected < name_count:
            notes.append(f"Inspected {slots_inspected} of {function_count} declared address slots and {names_inspected} of {name_count} declared name entries; unseen contents are unknown.")
        if active > len(exports):
            notes.append(f"Kept {len(exports)} of {active} nonempty exports in inspected slots.")
        if omitted_aliases:
            notes.append(f"Omitted {omitted_aliases} name aliases beyond {MAX_ALIASES} per inspected export.")
        if truncated_names:
            notes.append(f"{truncated_names} names/forwarders exceed the {MAX_NAME_BYTES}-byte preview limit.")
        return {"format": "pe", "present": True, "directory": directory, "dll": dll, "timestamp_untrusted": stamp,
                "ordinal_base": base, "declared_address_slots": function_count, "declared_name_entries": name_count,
                "address_slots_inspected": slots_inspected, "name_entries_inspected": names_inspected,
                "names_scan_complete": names_inspected == name_count, "nonempty_slots_observed": active,
                "empty_slots_observed": holes, "exports": exports, "selection_truncated": bool(notes), "notes": notes,
                "scan_limited": slots_inspected < function_count or names_inspected < name_count,
                "limits": {"address_slots": MAX_EXPORT_SLOTS, "name_entries": MAX_EXPORT_NAMES,
                           "export_sample": SYMBOL_SAMPLE, "aliases_per_export": MAX_ALIASES, "name_bytes": MAX_NAME_BYTES},
                "scope": "Export names, ordinals and forwarder declarations only. Unnamed exports are retained. "
                         "Export RVAs can denote code or data, including virtual-only data; no function or DLL is resolved."}


def inspect_pe(data: bytes) -> dict:
    """Compatibility entry point for callers of the earlier header inspector."""
    return PEImage(data).header()


def collect_pe(report, source) -> None:
    prefix = "P" if report.category == "pwn" else "R"
    try:
        image = PEImage(source.data)
    except ValueError as exc:
        report.add(prefix + "001", "PE header and declared flags", "unsupported" if isinstance(exc, UnsupportedPE) else "failed",
                   {"error": str(exc)}, refs=["E001"])
        for suffix, title in (("002", "PE layout and mitigation declarations"), ("003", "PE import declarations"), ("004", "PE export declarations")):
            report.add(prefix + suffix, title, "skipped", refs=["E001"], notes=["PE header/section admission failed; dependent collection was not attempted."])
        return
    for suffix, title, method in (("001", "PE header and declared flags", image.header),
                                  ("002", "PE layout and mitigation declarations", image.layout),
                                  ("003", "PE import declarations", image.imports),
                                  ("004", "PE export declarations", image.exports)):
        try:
            data = method()
            status = "partial" if data["selection_truncated"] else ("no_match" if data.get("present") is False else "complete")
            report.add(prefix + suffix, title, status, data, refs=["E001"], notes=data["notes"])
        except ValueError as exc:
            report.add(prefix + suffix, title, "failed", {"error": str(exc)}, refs=["E001"])
