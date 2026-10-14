"""Static ELF triage. No ldd, loading, debugging, or target execution."""

from __future__ import annotations

import re
import struct

from .files import FileInput, string_selection_notes
from .report import Report
from .runner import Runner

DANGEROUS = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf", "system", "popen", "execve"}


def parse_symbols(text: str) -> list[dict]:
    symbols = []
    # Exact normalized names avoid treating fgets as gets or system_info as system.
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and re.fullmatch(r"\d+:", fields[0]):
            full_name = fields[7]
            name = full_name.split("@", 1)[0]
            if name in DANGEROUS or name in {"win", "flag", "vuln", "__stack_chk_fail"}:
                symbols.append({"name": name, "value": fields[1], "type": fields[3],
                                "binding": fields[4], "section_index": fields[6],
                                "role": "import" if fields[6] == "UND" else "definition"})
    unique = {(row["name"], row["value"], row["section_index"]): row for row in symbols}
    return list(unique.values())[:80]


def elf_mitigations(header: str, layout: str, symbols: str, reliable_layout: bool, reliable_symbols: bool) -> dict:
    stack_line = next((line.strip() for line in layout.splitlines() if line.lstrip().startswith("GNU_STACK ")), None)
    if reliable_layout and stack_line:
        # GNU readelf -W: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align.
        flags = "".join(stack_line.split()[6:-1])
        nx = "executable stack requested" if "E" in flags else "non-executable stack requested"
    else:
        nx = "unknown; GNU_STACK absent or layout incomplete"
    bind_now = bool(re.search(r"\(BIND_NOW\)|\(FLAGS\).*\bNOW\b|\(FLAGS_1\).*\bNOW\b", layout))
    relro_segment = "GNU_RELRO" in layout
    relro = ("full RELRO indicators" if relro_segment and bind_now else
             "partial RELRO indicators" if relro_segment else "GNU_RELRO not observed") if reliable_layout else "unknown; incomplete layout"
    kind = re.search(r"^\s*Type:\s+(\S+)", header, re.M)
    if kind and kind.group(1) == "EXEC":
        pie = "ET_EXEC; PIE not indicated"
    elif kind and kind.group(1) == "DYN":
        pie = "PIE indicators present" if "INTERP" in layout or re.search(r"\(FLAGS_1\).*\bPIE\b", layout) else "ET_DYN; shared object or PIE, unresolved"
    else:
        pie = "unknown"
    canary = ("__stack_chk_fail symbol observed; protection of individual functions is unverified"
              if any(s["name"] == "__stack_chk_fail" for s in parse_symbols(symbols)) else
              "not observed; absence does not prove canaries are absent") if reliable_symbols else "unknown; symbol scan incomplete"
    return {"stack_execution": nx, "relro": relro, "pie": pie, "stack_canary": canary,
            "aslr": "runtime property; not determined by static file inspection",
            "gnu_stack_evidence": stack_line}


def inspect_pe(data: bytes) -> dict:
    if len(data) < 64:
        raise ValueError("Truncated DOS header")
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset > len(data) - 24 or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("MZ marker without a valid bounded PE signature")
    machine, sections, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, offset + 4)
    optional = offset + 24
    if opt_size < 72 or optional + opt_size > len(data):
        raise ValueError("Truncated or unsupported PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in {0x10b, 0x20b}:
        raise ValueError("Unsupported PE optional-header magic")
    dll_flags = struct.unpack_from("<H", data, optional + 70)[0]
    section_offset = optional + opt_size
    if sections > 96 or section_offset + sections * 40 > len(data):
        raise ValueError("Invalid or excessive PE section table")
    names = [data[section_offset + i * 40:section_offset + i * 40 + 8].rstrip(b"\0").decode("ascii", "replace")
             for i in range(sections)]
    return {"machine_code": hex(machine), "optional_header": "PE32+" if magic == 0x20b else "PE32",
            "sections": names, "coff_timestamp_untrusted": timestamp,
            "characteristics": hex(characteristics), "dynamic_base_flag": bool(dll_flags & 0x40),
            "nx_compat_flag": bool(dll_flags & 0x100), "cfg_flag": bool(dll_flags & 0x4000),
            "limit": "Header flags only; no import resolution, certificate validation, or runtime verification."}


def collect_binary(report: Report, source: FileInput, runner: Runner, strings: dict) -> None:
    prefix = "P" if report.category == "pwn" else "R"
    if source.profile["format_hint"] == "pe_candidate":
        try:
            report.add(prefix + "001", "PE header and declared flags", "complete", inspect_pe(source.data), refs=["E001"])
        except ValueError as exc:
            report.add(prefix + "001", "PE header and declared flags", "failed", {"error": str(exc)}, refs=["E001"])
        report.add(prefix + "002", "Detailed PE analysis", "unsupported", notes=["PE imports, symbols and disassembly are outside this alpha release."])
    elif source.profile["format_hint"] == "elf":
        header, h_ref = report.command(runner, ["readelf", "-W", "-h", str(source.path)], source.workdir)
        report.add(prefix + "001", "ELF architecture and header", header.status, {"header": header.stdout}, refs=[h_ref])
        layout, l_ref = report.command(runner, ["readelf", "-W", "-l", "-d", str(source.path)], source.workdir)
        symbols, s_ref = report.command(runner, ["readelf", "-W", "-s", str(source.path)], source.workdir)
        mitigations = elf_mitigations(header.stdout, layout.stdout, symbols.stdout,
                                     layout.status == "complete", symbols.status == "complete")
        status = layout.status if layout.status != "complete" else ("complete" if header.status == "complete" and symbols.status == "complete" else "partial")
        report.add(prefix + "002", "ELF mitigation indicators", status, mitigations, refs=[h_ref, l_ref, s_ref],
                   notes=["These are static indicators; they do not establish exploitability or runtime configuration."])
        needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", layout.stdout)
        paths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[(.*?)\]", layout.stdout)
        report.add(prefix + "003", "Declared ELF dependencies and search paths", layout.status,
                   {"needed": needed, "rpath_runpath": paths,
                    "interpreter": re.findall(r"Requesting program interpreter:\s*([^\]]+)", layout.stdout)}, refs=[l_ref],
                   notes=["Declarations only. Libraries are never loaded and ldd is never called."])
        report.add(prefix + "004", "Selected symbols and symbol-table evidence", symbols.status,
                   {"symbols": parse_symbols(symbols.stdout),
                    "symtab_observed": "Symbol table '.symtab'" in symbols.stdout,
                    "dynsym_observed": "Symbol table '.dynsym'" in symbols.stdout}, refs=[s_ref],
                   notes=["A function name is a lead, not a confirmed vulnerability. Dynamic symbols may survive stripping."])
    else:
        report.add(prefix + "001", "Binary format support", "unsupported",
                   {"format_hint": source.profile["format_hint"]},
                   notes=["This release supports ELF and basic PE headers. Shared file evidence remains available."])
    if report.category == "re":
        groups = {"urls_paths": [], "runtime_hints": [], "challenge_keywords": []}
        for item in strings.get("strings", []):
            text = item["text"]
            if re.search(r"https?://|/usr/|/bin/|[A-Za-z]:\\", text):
                groups["urls_paths"].append(item)
            if re.search(r"GLIBC|rust|go\.build|python|UPX|GCC|clang", text, re.I):
                groups["runtime_hints"].append(item)
            if re.search(r"flag|ctf|correct|incorrect|license|serial", text, re.I):
                groups["challenge_keywords"].append(item)
        report.add("R005", "RE leads from selected strings", "partial" if strings.get("selection_truncated") else "complete",
                   groups, refs=["E001"], notes=["Heuristic labels over C004's selected strings; no decompilation or control-flow analysis.",
                                               *string_selection_notes(strings)])
