# CLI reference

## Commands

| Command | Meaning |
| --- | --- |
| `wired2ai --version` | Show the package version |
| `wired2ai doctor [--json]` | Inspect Linux/Python and installed native tools |
| `wired2ai triage FILE [--category auto\|pwn\|re\|crypto\|forensics]` | Snapshot a file and collect one category |
| `wired2ai web URL [--probe-paths]` | Collect one explicitly supplied HTTP(S) endpoint |

No "deep" profile, plugin loader, daemon, remote model connection or automatic
exploit mode exists in this alpha. Web is a separate command because it performs
network I/O; file triage does not intentionally request a network resource.

## Options

| Option | Default | Accepted range / behavior |
| --- | --- | --- |
| `--out PATH` | Unique `wired2ai-runs/` subdirectory | PATH must not already exist |
| `--timeout SECONDS` | 10 | 0.1–60, finite; each native process/request |
| `--max-output-kib N` | 64 | 16–1024, combined stdout/stderr per command |
| `--markdown-kib N` | 32 | 8–256; UTF-8 byte budget, not tokens |
| `--max-file-mib N` | 32 | 1–256; triage only; complete snapshot required |
| `--max-requests N` | 10 | 1–20; web only; redirects count |
| `--probe-paths` | Off | Up to four additional scoped GETs: robots, missing-path control, Git HEAD, environment |
| `--strict` | Off | Exit 1 for failed/timeout/unavailable checks |

Tool-version probes have the same command guard but do not count as HTTP
requests. The overall run can take longer than `--timeout` because it contains
multiple sequential subprocesses. HTTP headers count against curl's combined
output limit, so a body may be shorter than that configured limit.

Optional probes are skipped when the main request has no HTTP status and curl
returns 6 (DNS resolution) or 7 (connection failure). The skip notes reference
the main request's evidence. HTTP 403/404 responses do not trigger this gate;
paths other than the entry page can remain accessible. Other failure types keep
the existing bounded probe behavior. No automatic retry is introduced.

## Check statuses and exit codes

| Status | Meaning |
| --- | --- |
| `complete` | Collector completed within its stated scope |
| `no_match` | A bounded search completed without the specified match |
| `partial` | Truncated/limited or dependent evidence incomplete |
| `timeout` | Process/request timed out |
| `failed` | Tool or parser failed; inspect its error evidence |
| `unavailable` | Required native tool was not found |
| `unsupported` | Input type is outside the collector's implemented coverage |
| `not_applicable` | Collector does not apply to the observed input |
| `skipped` | A configured gate or safety/data-handling rule prevented collection |

Exit 0 means reports were written, possibly with incomplete checks. Exit 1 means
reports were written but `--strict` found failed, timed-out or unavailable checks.
`partial`, `unsupported`, `not_applicable` and `skipped` do not by themselves fail
strict mode; automation should inspect JSON when it needs stronger acceptance
criteria. Exit 2 indicates invalid input/arguments or an operational error.
Exit 130 indicates interruption. `doctor` returns 0 even when optional tools are
missing; inspect its JSON for coverage decisions.

## Current check IDs

- C001–C004: snapshot identity, native format, header bytes, selected strings.
- P001–P004: ELF header, mitigation indicators, declared dependencies, symbols.
- R001–R004: corresponding RE binary observations; R005: selected string groups.
- K001–K004: statistics, encoding candidates, literal RSA checks, public PEM/X.509 data.
- F001–F003: statistics, supported container structure, optional ExifTool metadata.
- W001–W005: response/redirects, headers, HTML, optional robots, optional exposure indicators.

P/R001 adapts to a PE header for PE inputs; P/R002 then explicitly marks detailed
PE analysis unsupported. These alpha IDs are versioned by the report schema;
do not assume they are the same identifiers as the earlier planning catalog.

## Export behavior

All data retained by collectors is present in `report.json`. This does **not**
mean every byte of input/native output was retained. Each collector has limits,
native output is bounded, and exports are sanitized. The Markdown export also
caps individual check excerpts and omits sections when its total budget is full.
JSON remains valid even when a Markdown excerpt is truncated.

Partial-check notes identify the limiting condition. String notes report how
many candidates were kept from those considered; when a per-encoding scan cap
is hit, the full candidate count is explicitly unknown. Encoding notes give the
kept/found count within the first 65,536 bytes and state how much of the input
was sampled. At most 12 decoding previews are retained; exactly 12 candidates
is not a partial result when the complete input was scanned. Counts include
separate hex/base64 interpretations of the same token. Tokens outside the
bounded 8–32,768-character encoding search are not decoded.

Notes precede long check data. When a full partial-check section exceeds the
Markdown budget, a notes-only section is retained if it fits; otherwise its ID
is listed among the omissions. JSON always retains all collected check notes.
PNG trailing data gets a separate compact highlight with check/evidence IDs,
byte count and offset. PNG `type` escapes invalid chunk-name bytes as `\xNN`;
`type_hex` preserves all four bytes. A trailing-data finding is a lead for
inspection, not a claim that a flag or exploit exists.

UTF-16 string detection is heuristic and may report overlapping interpretations.
ASCII/UTF-16 scans consider at most 2,000 candidates per encoding, select at most
80 across them, and split long strings into segments of at most 256 characters.
An absent selected string does not prove it is absent from the artifact.
