"""Read-only bounded container and metadata inspection."""

from __future__ import annotations

import io
import re
import stat
import struct
import zipfile
import zlib
from pathlib import PurePosixPath

from .crypto import byte_statistics
from .files import FileInput
from .report import Report
from .runner import Runner


def inspect_png(data: bytes) -> dict:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("PNG signature missing")
    offset, chunks, anomalies = 8, [], []
    dimensions = None
    idat_seen = False
    idat_closed = False
    ended = False
    count = 0
    while offset < len(data):
        count += 1
        if count > 4096:
            anomalies.append("Stopped after 4096 chunks")
            break
        if offset + 12 > len(data):
            raise ValueError(f"Truncated PNG chunk header at offset {offset}")
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError(f"Chunk at offset {offset} exceeds input length")
        expected = struct.unpack_from(">I", data, offset + 8 + length)[0]
        actual = zlib.crc32(memoryview(data)[offset + 4:offset + 8 + length]) & 0xffffffff
        valid_crc = expected == actual
        label = kind.decode("ascii", "replace")
        if len(chunks) < 256:
            chunks.append({"type": label, "offset": offset, "length": length, "crc_valid": valid_crc})
        if not valid_crc and len(anomalies) < 80:
            anomalies.append(f"CRC mismatch for {label} at offset {offset}")
        if count == 1 and kind != b"IHDR":
            anomalies.append("First chunk is not IHDR")
        if kind == b"IHDR":
            if length != 13:
                anomalies.append("IHDR length is not 13")
            else:
                w, h, depth, colour, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", data, offset + 8)
                dimensions = {"width": w, "height": h, "bit_depth": depth, "colour_type": colour,
                              "compression": compression, "filter": filtering, "interlace": interlace}
                if w == 0 or h == 0:
                    anomalies.append("Zero PNG dimension")
        if kind == b"IDAT":
            if idat_closed:
                anomalies.append("Non-consecutive IDAT chunks observed")
            idat_seen = True
        elif idat_seen:
            idat_closed = True
        offset = end
        if kind == b"IEND":
            ended = True
            if length != 0:
                anomalies.append("IEND payload is not empty")
            break
    if not idat_seen:
        anomalies.append("No IDAT chunk observed")
    if not ended:
        anomalies.append("IEND not reached")
    return {"dimensions": dimensions, "chunks": chunks, "chunks_seen": min(count, 4096),
            "iend_reached": ended, "trailing_offset": offset if ended else None,
            "trailing_bytes": len(data) - offset if ended else None,
            "anomalies": anomalies[:80], "selection_truncated": count > 256,
            "limit": "Chunk and CRC inspection only; image data is never decompressed. Multiple consecutive IDAT chunks are valid."}


def inspect_zip(data: bytes) -> dict:
    # Preflight the EOCD before ZipFile materializes an attacker-controlled directory.
    tail_start = max(0, len(data) - 65557)
    eocd = data.rfind(b"PK\x05\x06", tail_start)
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("ZIP end-of-central-directory record missing or truncated")
    _, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack_from("<4s4H2IH", data, eocd)
    if eocd + 22 + comment != len(data):
        raise ValueError("ZIP trailing bytes or inconsistent comment; this bounded parser cannot resolve the directory confidently")
    if disk or cd_disk or disk_count != count:
        raise ValueError("Multi-disk ZIP archives are unsupported")
    if count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise ValueError("ZIP64 is deferred in this alpha")
    if count > 2000 or cd_size > 4 * 1024 * 1024 or cd_offset + cd_size > eocd:
        raise ValueError("ZIP directory exceeds limits or points outside the archive")
    # Validate actual entry count instead of trusting the EOCD count alone.
    cursor = cd_offset
    actual_count = 0
    while cursor < cd_offset + cd_size:
        if cursor + 46 > cd_offset + cd_size or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("Invalid ZIP central-directory entry")
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, cursor + 28)
        cursor += 46 + name_len + extra_len + comment_len
        actual_count += 1
        if actual_count > 2000:
            raise ValueError("ZIP directory has too many entries")
    if cursor != cd_offset + cd_size or actual_count != count:
        raise ValueError("ZIP directory size/count mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = []
        names = set()
        for info in archive.infolist():
            name = info.filename
            normalized = name.replace("\\", "/")
            mode = (info.external_attr >> 16) & 0xffff
            risks = []
            if normalized.startswith("/") or ".." in PurePosixPath(normalized).parts or re.match(r"^[A-Za-z]:", normalized):
                risks.append("unsafe extraction path")
            if stat.S_ISLNK(mode):
                risks.append("symbolic link")
            if name in names:
                risks.append("duplicate name")
            if info.file_size > max(1, info.compress_size) * 100:
                risks.append("high declared expansion ratio")
            names.add(name)
            entries.append({"name": name, "compressed_bytes": info.compress_size, "declared_bytes": info.file_size,
                            "encrypted": bool(info.flag_bits & 1), "risks": risks})
        risky = [entry for entry in entries if entry["risks"]]
        selected = (risky + [entry for entry in entries if not entry["risks"]])[:100]
        return {"entries": selected, "entry_count": len(entries), "risk_entry_count": len(risky),
                "declared_total_bytes": sum(entry["declared_bytes"] for entry in entries),
                "selection_truncated": len(entries) > 100,
                "limit": "Directory metadata only; no extraction, decompression, member CRC check, or password attempts."}


def inspect_pcap(data: bytes) -> dict:
    magic = data[:4]
    if len(data) < 24:
        raise ValueError("Truncated classic PCAP global header")
    endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    nano = magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHiiII", data, 4)
    if (major, minor) != (2, 4):
        raise ValueError("Unsupported classic PCAP version")
    cursor, packets, anomalies = 24, 0, []
    first, last = None, None
    while cursor < len(data) and packets < 100000:
        if cursor + 16 > len(data):
            raise ValueError(f"Truncated PCAP packet header at offset {cursor}")
        secs, fraction, captured, original = struct.unpack_from(endian + "IIII", data, cursor)
        if captured > len(data) - cursor - 16:
            raise ValueError(f"PCAP packet at offset {cursor} exceeds capture length")
        if captured > snaplen or captured > original or fraction >= (1000000000 if nano else 1000000):
            if len(anomalies) < 20:
                anomalies.append(f"Inconsistent packet length or timestamp at offset {cursor}")
        stamp = {"seconds": secs, "fraction": fraction}
        first = stamp if first is None else first
        last = stamp
        packets += 1
        cursor += 16 + captured
    return {"version": f"{major}.{minor}", "byte_order": "little" if endian == "<" else "big",
            "timestamp_resolution": "nanoseconds" if nano else "microseconds", "snaplen": snaplen,
            "link_type_field": network, "packet_records": packets, "first_record_timestamp": first,
            "last_record_timestamp": last, "anomalies": anomalies, "selection_truncated": cursor < len(data),
            "limit": "Record metadata only; packets are not replayed, resolved, or dissected."}


def collect_forensics(report: Report, source: FileInput, runner: Runner) -> None:
    stats = byte_statistics(source.data)
    report.add("F001", "Byte distribution", "partial" if stats["sample_truncated"] else "complete", stats, refs=["E001"])
    kind = source.profile["format_hint"]
    parsers = {"png": inspect_png, "zip": inspect_zip, "pcap": inspect_pcap}
    if kind in parsers:
        try:
            structure = parsers[kind](source.data)
            report.add("F002", "Container structure", "partial" if structure["selection_truncated"] else "complete", structure, refs=["E001"])
        except (ValueError, struct.error, zipfile.BadZipFile, NotImplementedError) as exc:
            report.add("F002", "Container structure", "failed", {"error": str(exc)}, refs=["E001"])
    else:
        report.add("F002", "Container structure", "unsupported", {"format_hint": kind},
                   notes=["Built-in structural parsers cover PNG, bounded non-ZIP64 ZIP directories, and classic PCAP. PCAPNG and disk/memory images are deferred."])
    if source.profile["private_key_marker"]:
        report.add("F003", "Metadata fields", "skipped", notes=["Private-key marker: generic metadata extraction suppressed."])
    else:
        result, ref = report.command(runner, ["exiftool", "-j", "-G", "-s", str(source.path)], source.workdir)
        report.add("F003", "Metadata fields", result.status, {"metadata_excerpt": result.stdout}, refs=[ref],
                   notes=["Metadata may contain personal information; inspect before sharing. ExifTool reads the temporary snapshot: filesystem timestamps there are not evidence timestamps; see C001."])
