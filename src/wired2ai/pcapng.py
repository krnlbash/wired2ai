"""Bounded PCAPNG 1.0 metadata inspection; no packet or option-text export.

Layout reference: draft-ietf-opsawg-pcapng-06 (work in progress).
This is deliberately not a full conformance validator or packet dissector.
"""

from __future__ import annotations

import struct
from collections.abc import Callable


SHB = 0x0A0D0D0A
MAX_BLOCKS = 100000
MAX_SECTIONS = 64
MAX_INTERFACES = 256  # Across all sections, not per section.
MAX_OPTIONS_PER_BLOCK = 256
MAX_OPTIONS_TOTAL = 100000
PACKET_LIMIT = 32
ANOMALY_LIMIT = 40
DETAIL_LIMIT = 16
BLOCK_NAMES = {SHB: "section_header", 1: "interface_description", 2: "obsolete_packet",
               3: "simple_packet", 4: "name_resolution", 5: "interface_statistics",
               6: "enhanced_packet", 10: "decryption_secrets",
               0xBAD: "custom", 0x40000BAD: "custom_noncopyable"}


class UnsupportedPcapng(ValueError):
    """A recognized section uses a version outside the implemented subset."""


class _ScanLimit(Exception):
    pass


def _padded(length: int) -> int:
    return (length + 3) & ~3


def _timestamp(ticks: int, interface: dict) -> dict:
    units = interface["timestamp_units_per_second"]
    seconds, fraction = divmod(ticks, units)
    return {"raw_ticks": ticks, "seconds": seconds + interface["timestamp_offset_seconds"],
            "fraction_numerator": fraction, "fraction_denominator": units}


class _Inspector:
    def __init__(self, data: bytes, on_packet: Callable[[dict, int], None] | None = None):
        self.data = data
        self.on_packet = on_packet
        self.sections = []
        self.interfaces = []
        self.current_interfaces = []
        self.section_end = None
        self.endian = "<"
        self.offset = 0
        self.blocks = 0
        self.options_seen = 0
        self.block_counts = {}
        self.packets = []
        self.packet_count = 0
        self.timestamped_count = 0
        self.captured_bytes = 0
        self.original_bytes = 0
        self.first_timestamped = None
        self.last_timestamped = None
        self.anomalies = []
        self.anomalies_seen = 0
        self.opaque_blocks = 0
        self.opaque_samples = []
        self.secret_blocks = 0
        self.secret_bytes = 0
        self.secret_samples = []

    def fail(self, message: str, offset: int | None = None) -> None:
        raise ValueError(f"PCAPNG {message} at offset {self.offset if offset is None else offset}")

    def anomaly(self, message: str) -> None:
        self.anomalies_seen += 1
        if len(self.anomalies) < ANOMALY_LIMIT:
            self.anomalies.append({"offset": self.offset, "message": message})

    def options(self, start: int, end: int, *, interface: bool = False) -> dict:
        # Only two numeric IDB options are retained. Strings and unknown values
        # never enter a report, including comments, names and custom options.
        selected = {}
        count = 0
        while start < end:
            if end - start < 4:
                self.fail("truncated option header", start)
            code, length = struct.unpack_from(self.endian + "HH", self.data, start)
            value_start = start + 4
            next_offset = value_start + _padded(length)
            if next_offset > end:
                self.fail("option length exceeds block", start)
            if code == 0:
                if length != 0 or next_offset != end:
                    self.fail("invalid end-of-options marker or bytes after it", start)
                return selected
            if count >= MAX_OPTIONS_PER_BLOCK or self.options_seen >= MAX_OPTIONS_TOTAL:
                raise _ScanLimit("Option scan limit reached; the current block was not included in counts.")
            count += 1
            self.options_seen += 1
            if interface and code in (9, 14):
                if code in selected:
                    self.fail(f"duplicate timestamp option {code} is ambiguous", start)
                if length != (1 if code == 9 else 8):
                    self.fail(f"invalid timestamp option {code} length", start)
                selected[code] = (self.data[value_start] if code == 9 else
                                  struct.unpack_from(self.endian + "q", self.data, value_start)[0])
            start = next_offset
        # Readers must accept a clean block end without opt_endofopt.
        return selected

    def interface(self, identifier: int) -> dict:
        if identifier >= len(self.current_interfaces):
            self.fail(f"packet references undeclared interface {identifier}")
        return self.current_interfaces[identifier]

    def section(self, end: int) -> None:
        if end - self.offset < 28:
            self.fail("section header shorter than 28 bytes")
        if self.section_end is not None and self.offset != self.section_end:
            self.fail("section boundary disagrees with declared section length")
        major, minor, length = struct.unpack_from(self.endian + "HHq", self.data, self.offset + 12)
        if (major, minor) != (1, 0):
            raise UnsupportedPcapng(f"PCAPNG version {major}.{minor} at offset {self.offset}; only 1.0 is supported")
        if length < -1 or (length >= 0 and (length % 4 or end + length > len(self.data))):
            self.fail("invalid or out-of-bounds declared section length")
        if len(self.sections) >= MAX_SECTIONS:
            raise _ScanLimit(f"Section scan limit {MAX_SECTIONS} reached.")
        self.options(self.offset + 24, end - 4)
        self.sections.append({"section_index": len(self.sections), "offset": self.offset,
                              "version": "1.0", "byte_order": "little" if self.endian == "<" else "big",
                              "declared_section_bytes": None if length == -1 else length})
        self.current_interfaces = []
        self.section_end = None if length == -1 else end + length

    def description(self, end: int) -> None:
        if end - self.offset < 20:
            self.fail("interface description shorter than 20 bytes")
        if len(self.interfaces) >= MAX_INTERFACES:
            raise _ScanLimit(f"Interface scan limit {MAX_INTERFACES} across all sections reached.")
        link_type, reserved, snaplen = struct.unpack_from(self.endian + "HHI", self.data, self.offset + 8)
        options = self.options(self.offset + 16, end - 4, interface=True)
        resolution = options.get(9, 6)
        base, exponent = (2 if resolution & 128 else 10), resolution & 127
        item = {"section_index": len(self.sections) - 1, "interface_id": len(self.current_interfaces),
                "offset": self.offset, "link_type": link_type, "snaplen": snaplen,
                "timestamp_resolution": {"base": base, "exponent": exponent},
                "timestamp_units_per_second": base ** exponent,
                "timestamp_offset_seconds": options.get(14, 0),
                "packet_records": 0, "captured_bytes": 0, "original_bytes": 0}
        if reserved:
            self.anomaly("Nonzero reserved interface field")
        self.interfaces.append(item)
        self.current_interfaces.append(item)

    def packet(self, kind: int, end: int) -> None:
        if end - self.offset < (16 if kind == 3 else 32):
            self.fail("packet block shorter than its fixed header")
        stamp = None
        if kind == 3:
            interface_id = 0
            interface = self.interface(interface_id)
            original = struct.unpack_from(self.endian + "I", self.data, self.offset + 8)[0]
            captured = min(original, interface["snaplen"]) if interface["snaplen"] else original
            payload_start = self.offset + 12
            if payload_start + _padded(captured) != end - 4:
                self.fail("simple packet length disagrees with original length and interface snaplen")
        else:
            if kind == 6:
                interface_id, high, low, captured, original = struct.unpack_from(
                    self.endian + "IIIII", self.data, self.offset + 8)
            else:
                interface_id, _drops, high, low, captured, original = struct.unpack_from(
                    self.endian + "HHIIII", self.data, self.offset + 8)
            interface = self.interface(interface_id)
            payload_start = self.offset + 28
            options_start = payload_start + _padded(captured)
            if options_start > end - 4:
                self.fail("captured packet length exceeds block")
            self.options(options_start, end - 4)
            stamp = _timestamp((high << 32) | low, interface)
        if captured > original:
            self.anomaly("Captured length exceeds original packet length")
        if interface["snaplen"] and captured > interface["snaplen"]:
            self.anomaly("Captured length exceeds interface snaplen")
        self.packet_count += 1
        self.captured_bytes += captured
        self.original_bytes += original
        interface["packet_records"] += 1
        interface["captured_bytes"] += captured
        interface["original_bytes"] += original
        item = {"record_index": self.packet_count - 1, "block_type": BLOCK_NAMES[kind],
                "section_index": len(self.sections) - 1, "interface_id": interface_id,
                "offset": self.offset, "payload_offset": payload_start,
                "captured_bytes": captured, "original_bytes": original, "timestamp": stamp}
        if self.on_packet is not None:
            self.on_packet(item, interface["link_type"])
        if len(self.packets) < PACKET_LIMIT:
            self.packets.append(item)
        if stamp is not None:
            self.timestamped_count += 1
            # These are first/last in file order, not minimum/maximum time.
            endpoint = {key: item[key] for key in ("record_index", "section_index", "interface_id", "offset", "timestamp")}
            if self.first_timestamped is None:
                self.first_timestamped = endpoint
            self.last_timestamped = endpoint

    def secrets(self, end: int) -> None:
        if end - self.offset < 20:
            self.fail("decryption secrets block shorter than 20 bytes")
        secret_type, length = struct.unpack_from(self.endian + "II", self.data, self.offset + 8)
        options_start = self.offset + 16 + _padded(length)
        if options_start > end - 4:
            self.fail("decryption secrets length exceeds block")
        self.options(options_start, end - 4)
        self.secret_blocks += 1
        self.secret_bytes += length
        if len(self.secret_samples) < DETAIL_LIMIT:
            self.secret_samples.append({"offset": self.offset, "section_index": len(self.sections) - 1,
                                        "secrets_type_hex": f"0x{secret_type:08x}", "declared_bytes": length})

    def scan(self) -> dict:
        if self.data[:4] != b"\x0a\x0d\x0d\x0a":
            self.fail("section-header signature missing", 0)
        stop_reason = None
        while self.offset < len(self.data):
            try:
                if self.blocks >= MAX_BLOCKS:
                    raise _ScanLimit(f"Block scan limit {MAX_BLOCKS} reached.")
                if len(self.data) - self.offset < 12:
                    self.fail("truncated block header")
                is_section = self.data[self.offset:self.offset + 4] == b"\x0a\x0d\x0d\x0a"
                if is_section:
                    bom = self.data[self.offset + 8:self.offset + 12]
                    if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                        self.fail("invalid byte-order magic")
                    self.endian = "<" if bom[0] == 0x4D else ">"
                kind, length = struct.unpack_from(self.endian + "II", self.data, self.offset)
                end = self.offset + length
                if length < 12 or length % 4 or end > len(self.data):
                    self.fail("invalid, unaligned or out-of-bounds block length")
                if struct.unpack_from(self.endian + "I", self.data, end - 4)[0] != length:
                    self.fail("leading/trailing block length mismatch")
                if not is_section and self.section_end is not None and end > self.section_end:
                    self.fail("block exceeds declared section boundary")
                if kind == SHB:
                    self.section(end)
                elif kind == 1:
                    self.description(end)
                elif kind in (2, 3, 6):
                    self.packet(kind, end)
                elif kind == 10:
                    self.secrets(end)
                else:
                    # Validate framing only. In particular NRB/ISB/custom bodies
                    # are neither decoded nor treated as absent observations.
                    self.opaque_blocks += 1
                    if len(self.opaque_samples) < DETAIL_LIMIT:
                        self.opaque_samples.append({"offset": self.offset, "type_hex": f"0x{kind:08x}",
                                                    "block_bytes": length})
                label = BLOCK_NAMES.get(kind, "other")
                self.block_counts[label] = self.block_counts.get(label, 0) + 1
                self.blocks += 1
                self.offset = end
            except _ScanLimit as exc:
                stop_reason = str(exc)
                break
        if stop_reason is None and self.section_end is not None and self.offset != self.section_end:
            self.fail("end of file disagrees with declared section length")
        notes = []
        if stop_reason:
            notes.append(f"{stop_reason} Inspected {self.offset} of {len(self.data)} bytes; remaining counts are unknown.")
        for label, kept, seen in (("packet records", len(self.packets), self.packet_count),
                                  ("anomalies", len(self.anomalies), self.anomalies_seen),
                                  ("opaque block details", len(self.opaque_samples), self.opaque_blocks),
                                  ("decryption-secrets block details", len(self.secret_samples), self.secret_blocks)):
            if kept < seen:
                notes.append(f"Kept {kept} of {seen} observed {label}; aggregate counts cover the inspected prefix.")
        limited = bool(notes)
        if self.opaque_blocks:
            notes.append(f"{self.opaque_blocks} block bodies were not interpreted; only their framing was checked.")
        if self.secret_blocks:
            notes.append(f"{self.secret_blocks} decryption-secrets blocks observed; values are omitted. Keep the original capture private.")
        return {"format": "pcapng", "packet_records": self.packet_count,
                "timestamped_packet_records": self.timestamped_count,
                "section_count": len(self.sections), "interface_count": len(self.interfaces),
                "blocks_inspected": self.blocks, "block_counts": self.block_counts,
                "captured_packet_bytes": self.captured_bytes, "original_packet_bytes": self.original_bytes,
                "inspected_bytes": self.offset, "total_bytes": len(self.data),
                "scan_limited": stop_reason is not None, "selection_truncated": limited,
                "anomalies": self.anomalies, "anomalies_seen": self.anomalies_seen,
                "decryption_secrets": {"blocks": self.secret_blocks, "declared_bytes": self.secret_bytes,
                                       "values_exported": False, "details": self.secret_samples},
                "opaque_blocks": self.opaque_blocks, "opaque_block_details": self.opaque_samples,
                "first_timestamped_packet": self.first_timestamped, "last_timestamped_packet": self.last_timestamped,
                "sections": self.sections, "interfaces": self.interfaces, "packet_sample": self.packets,
                "notes": notes,
                "limits": {"blocks": MAX_BLOCKS, "sections": MAX_SECTIONS, "interfaces_total": MAX_INTERFACES,
                           "options_per_block": MAX_OPTIONS_PER_BLOCK, "options_total": MAX_OPTIONS_TOTAL,
                           "packet_sample": PACKET_LIMIT, "anomalies": ANOMALY_LIMIT, "block_details": DETAIL_LIMIT},
                "scope": "PCAPNG 1.0 SHB/IDB/EPB/SPB/obsolete PB metadata and DSB lengths. Other bodies are opaque. "
                         "No payloads, text options, names, addresses, secrets, replay or packet dissection. "
                         "Timestamps are exact seconds plus a rational fraction, in file order; clocks are not verified."}


def inspect_pcapng(data: bytes, *, on_packet: Callable[[dict, int], None] | None = None) -> dict:
    return _Inspector(data, on_packet).scan()
