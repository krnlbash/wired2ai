"""Input snapshotting and collectors shared by file categories."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .report import Report
from .runner import Runner


@dataclass
class FileInput:
    path: Path
    workdir: Path
    data: bytes
    profile: dict


def identify(data: bytes) -> str:
    for magic, kind in ((b"\x7fELF", "elf"), (b"MZ", "pe_candidate"),
                        (b"\x89PNG\r\n\x1a\n", "png"), (b"PK\x03\x04", "zip"),
                        (b"PK\x05\x06", "zip"), (b"%PDF-", "pdf"), (b"\xff\xd8\xff", "jpeg")):
        if data.startswith(magic):
            return kind
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng"
    if not data:
        return "empty"
    sample = data[:8192]
    try:
        text = sample.decode("utf-8")
        if all(char.isprintable() or char in "\r\n\t" for char in text):
            return "text"
    except UnicodeDecodeError:
        pass
    return "unknown"


def contains_private_key(data: bytes) -> bool:
    return re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", data) is not None


@contextmanager
def snapshot_input(source: Path, max_bytes: int):
    # O_NONBLOCK avoids hanging on named pipes; O_NOFOLLOW rejects the final symlink.
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Input must be a regular file; devices, directories and pipes are rejected")
        if before.st_size > max_bytes:
            raise ValueError(f"Input exceeds the {max_bytes}-byte limit; use --max-file-mib if appropriate")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        if len(data) > max_bytes:
            raise ValueError("Input grew beyond the configured byte limit")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Input changed during acquisition; retry on a stable copy")
    finally:
        os.close(fd)
    profile = {
        "kind": "file", "name": source.name, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "hash_scope": "complete snapshot",
        "format_hint": identify(data), "source_mtime_ns": before.st_mtime_ns,
        "source_ctime_ns": before.st_ctime_ns,
        "ctime_meaning": "inode change time, not creation time",
        "private_key_marker": contains_private_key(data),
    }
    with tempfile.TemporaryDirectory(prefix="wired2ai-") as temp:
        workdir = Path(temp)
        suffix = source.suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", source.suffix) else ".bin"
        snapshot = workdir / ("target" + suffix)
        snapshot.write_bytes(data)
        snapshot.chmod(0o600)
        yield FileInput(snapshot, workdir, data, profile)


def extract_strings(data: bytes, maximum: int = 80) -> dict:
    patterns = [
        ("ascii", rb"[\x20-\x7e]{6,256}"),
        ("utf-16le", rb"(?:[\x20-\x7e]\x00){6,256}"),
        ("utf-16be", rb"(?:\x00[\x20-\x7e]){6,256}"),
    ]
    candidates = []
    scan_limited = False
    for encoding, pattern in patterns:
        for index, match in enumerate(re.finditer(pattern, data)):
            if index >= 2000:
                scan_limited = True
                break
            text = match.group().decode(encoding)
            relevant = bool(re.search(r"flag|ctf|https?://|pass|secret|token|/bin/|GLIBC|UPX|rust|python", text, re.I))
            candidates.append({"offset": match.start(), "encoding": encoding, "text": text,
                               "priority_hint": relevant})
    candidates.sort(key=lambda item: (not item["priority_hint"], item["offset"], item["encoding"]))
    return {"strings": candidates[:maximum], "candidates_seen": len(candidates),
            "selection_limit": maximum,
            "selection_truncated": len(candidates) > maximum or scan_limited,
            "scan_limited": scan_limited, "max_characters_per_string": 256,
            "note": "Offsets refer to the complete input snapshot. Selection is heuristic; long strings are split into bounded segments."}


def string_selection_notes(strings: dict) -> list[str]:
    if not strings.get("selection_truncated"):
        return []
    notes = [f"Kept {len(strings['strings'])} of {strings['candidates_seen']} considered string candidates "
             f"(selection limit {strings['selection_limit']})."]
    if strings["scan_limited"]:
        notes.append("At least one encoding reached the 2000-candidate scan limit; the total candidate count is unknown.")
    else:
        notes.append("All input bytes were searched; only the selected result list was capped.")
    return notes


def common_file(report: Report, source: FileInput, runner: Runner) -> dict:
    ref = report.observation("file_snapshot", {"sha256": source.profile["sha256"],
                             "size_bytes": len(source.data), "method": "complete private snapshot; hashlib.sha256"})
    report.add("C001", "File identity and snapshot", "complete", source.profile, refs=[ref])
    result, ref = report.command(runner, ["file", "--brief", "--", str(source.path)], source.workdir)
    report.add("C002", "Native format identification", result.status,
               {"description": result.stdout.strip(), "signature_hint": source.profile["format_hint"]}, refs=[ref],
               notes=["Format labels are parser observations, not proof that a file is well formed."])
    if source.profile["private_key_marker"]:
        report.add("C003", "Header bytes", "skipped", notes=["Suppressed for input containing a private-key PEM marker."])
        report.add("C004", "Selected strings and offsets", "skipped", notes=["Suppressed to avoid copying private-key material into the report."])
        return {"strings": []}
    report.add("C003", "Header bytes", "complete", {"offset": 0, "length": min(64, len(source.data)),
               "hex": source.data[:64].hex(" ")}, refs=["E001"])
    strings = extract_strings(source.data)
    report.add("C004", "Selected strings and offsets", "partial" if strings["selection_truncated"] else "complete",
               strings, refs=["E001"], notes=string_selection_notes(strings))
    return strings
