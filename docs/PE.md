# Static PE triage in 0.2.0a2

This phase expands Windows PE evidence within the existing Kali CLI. It reports
declared image structure and useful leads without loading the image, resolving
libraries, disassembling code or executing an entry point. PE32 and PE32+ share
the bounded parser, with their respective field and thunk widths.

## Try the synthetic example later

```bash
.venv/bin/wired2ai triage examples/pe-demo.bin --category re --out ./runs/pe-demo
.venv/bin/wired2ai triage examples/pe-demo.bin --category pwn --out ./runs/pe-pwn
```

Automatic selection also chooses RE for this MZ candidate. Keep the `.bin`
extension and inspect the fixture as data. It was generated for parser testing;
Windows execution/loader compatibility is not a validation goal.

Expected observations:

- PE32+, AMD64, DLL flag, two sections (`.text`, `.rdata`).
- Entry RVA `0x1000` maps to file offset `0x200`.
- Ordinary imports declare `KERNEL32.dll`, named `VirtualProtect` and ordinal 7.
  The API name is a lead, not evidence of a vulnerability.
- Three nonempty exports: `DemoEntry`, `ForwardedSleep` forwarding to
  `KERNEL32.Sleep`, and unnamed ordinal 3.
- DYNAMIC_BASE and NX_COMPAT flags are set; runtime enforcement is unknown.
- A 16-byte certificate-table range at file offset `0xc00` has valid framing.
  Its payload is the synthetic text `DEMO`, not a valid Authenticode signature.
- There are 33 bytes after section raw data. Excluding the framed 16-byte
  certificate range leaves 17 unclassified bytes at offset `0xc10`.

`examples/pe-report/` contains an actual RE report from the installed package.
The report includes nine complete checks on the recorded development host;
missing optional `file` identification changes C002 on other hosts.

Regenerate either form at a new path without a compiler or network access:

```bash
python3 examples/make_pe_demo.py /tmp/wired2ai-pe64.bin
python3 examples/make_pe_demo.py /tmp/wired2ai-pe32.bin --bits 32
sha256sum examples/pe-demo.bin /tmp/wired2ai-pe64.bin
```

The generator refuses existing destinations. The default 64-bit output is
byte-for-byte reproducible. No real executable, customer data or signing key was
used to create it.

## Checks and provenance

| Check | Scope |
| --- | --- |
| P/R001 | Header admission, machine/bitness, image base, entry RVA, declared sizes/flags, section names and directory declarations |
| P/R002 | Section raw/virtual layout, permissions, entropy samples, entry mapping, static mitigation declarations, certificate framing and trailing ranges |
| P/R003 | Ordinary import descriptors and bounded name/ordinal lookup, with selected exact API leads |
| P/R004 | Export address/name/ordinal tables, unnamed exports, aliases and forwarder declarations |
| R005 | Existing heuristic grouping of C004's selected strings |

All PE checks cite E001, the complete snapshot hash. Section headers, names,
thunks, export slots and certificate entries retain file offsets. RVA fields
remain explicitly distinguished from offsets. Section-name hex retains all eight
bytes; escaped text preserves invalid/non-ASCII bytes. The parser never uses a
replacement character to hide an invalid name byte.

MZ is a routing hint. Header admission requires a supported optional-header
layout, a bounded section table, header coverage and in-file raw section ranges.
A malformed core fails P/R001 and skips its dependent checks. Unsupported header
magic or section counts beyond the supported cap get `unsupported`. Once the
core is admitted, layout/import/export failures do not suppress one another.
Failed checks retain an error, not apparently successful empty results.

An RVA lookup must be file-backed and unambiguous. A requested span crossing
regions, conflicting section mappings, or virtual-only bytes fails the relevant
lookup. A string preview stops at its mapped region or its byte cap. Unknown
machine/linker variants are not interpreted as proof of compatibility. The parser
is a strict bounded subset, not a replacement for the Windows loader.

## Selection and scan limits

| Collection | Bound and behavior |
| --- | --- |
| Complete input | Existing 32 MiB default snapshot limit; configurable to 256 MiB |
| Sections | At most 96 admitted; all admitted section metadata retained |
| Data directories | First 16 recognized slots; extra declared slots produce a partial note |
| Section entropy | First 65,536 raw bytes per section; exact sample range/count retained |
| Import descriptors | At most 128; unread descriptors/symbols remain unknown |
| Import thunks | At most 4,096 across all DLLs, not per DLL |
| Import details | At most 128; exact API leads prioritized over ordinary entries |
| Export scan | At most 4,096 address slots and 4,096 name entries; declared counts retained |
| Export details | First 128 nonempty inspected slots; at most eight aliases per slot |
| Name/forwarder preview | At most 256 bytes; capped prefixes are explicitly marked partial |
| Certificate entries | At most 64 framed entries; no payload decoding or trust check |
| Layout observations | First 80; observed total retained |

Detail selection can be partial even when a scan completes. Notes distinguish
that case from unread data. An exact cap with a verified terminator and no omitted
result is not itself partial. A capped export-name scan does not establish which
exports are truly unnamed. JSON retains all collected data; Markdown can omit
details while preserving a compact summary and explicit omission notices.

A missing original import lookup table can use an unbound IAT. If the descriptor
indicates binding and no original table exists, its symbols remain unknown and
the check is partial. Ordinals remain numeric; the tool does not invent names.
Delay-import and bound-import directories are disclosed when declared but not
decoded. `no_match` only describes an absent ordinary directory.

## Interpretation limits

Write/execute permissions, overlapping ranges and unmapped entry points are
observations for manual investigation. High entropy does not identify a packer
or cipher. Import names do not establish reachability, use or exploitation.
Export targets may be code or data; forwarded exports are never followed.

Mitigation fields describe declared flags. Canary coverage, SafeSEH, valid CFG
tables, usable relocations and actual ASLR/NX enforcement are not determined.
Load configuration, TLS callbacks, relocation contents, resources, CLR metadata,
COFF/debug symbols and disassembly remain deferred. COFF timestamps are untrusted.

Certificate-table addresses are handled as file offsets. Only a fully framed,
non-overlapping table is excluded from the tail classification. If its scan is
capped, its range remains unclassified. Legitimate padding, debug/COFF data and
other contents can also appear after sections. Neither an unclassified tail nor
a framed certificate is a security verdict; no Authenticode verification occurs.

GNU objdump independently reads the synthetic fixture's declarations, and tests
also parse GNU-linked PE32/PE32+ files. This does not establish compatibility with
all MSVC/MinGW, packed, signed or malicious files. Combined Kali/manual acceptance
is deferred; see [VALIDATION.md](VALIDATION.md).

Layout reference: [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
