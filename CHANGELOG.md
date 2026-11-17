# Changelog

## 0.2.0a2 — 2026-10-21

Second incremental 0.2.0 expansion; release label `v0.2.0-alpha.2`.

- Replace the basic PE-only header path with independent PE32/PE32+ header, layout, ordinary import and export checks in both pwn and RE categories.
- Add section permissions, offset-bearing section maps, bounded entropy samples, entry-point mappings, and conservative static mitigation declarations.
- Resolve file-backed RVAs with explicit bounds and reject overlapping/ambiguous mappings. Preserve invalid section-name bytes with escaped text and hexadecimal evidence.
- Collect named/ordinal imports, bounded exact API leads, named/unnamed exports and forwarded-export declarations. Report unknown bound-IAT names and deferred delay/bound import tables explicitly.
- Validate certificate-table framing using file offsets and exclude only fully framed table ranges from trailing-data accounting. No Authenticode or trust validation is claimed.
- Add per-collector limits, partial notes and compact PE observations in the Markdown brief. A failed import/export table does not erase other completed PE checks.
- Add 32 PE test methods, a reproducible synthetic PE fixture and example report. Compare fixture declarations with GNU objdump and parse independently linked PE32/PE32+ fixtures without executing them.
- Retain PCAPNG support and earlier fixes. Refresh the complete browser-upload package and consolidate later Kali acceptance steps.

No application runtime dependency was added. Local regression results and the
deferred combined Kali test session are recorded separately in `docs/VALIDATION.md`.

## 0.2.0a1 — 2026-10-20

First incremental forensics expansion; release label `v0.2.0-alpha.1`.

- Add bounded PCAPNG 1.0 section, interface and packet metadata for Enhanced, Simple and obsolete Packet Blocks, including mixed-endian sections and interface ID resets.
- Preserve raw timestamp ticks and exact seconds/fractions with decimal/binary interface resolutions and signed offsets. Simple packets retain an explicit absent timestamp.
- Validate block framing, section boundaries, packet bounds and supported option layouts. Distinguish malformed input, unsupported versions, scan limits and retained-sample limits.
- Add per-interface aggregate counts, byte counts, offset-bearing packet samples and length anomalies. Opaque blocks are counted with an explicit scope note.
- Observe decryption-secrets block presence/type/length without exporting values. Suppress generic raw/native PCAPNG exports and crypto previews across category overrides.
- Add a compact Markdown capture summary, 22 PCAPNG regression/integration tests and a deterministic two-interface synthetic capture with its generator and actual report.
- Retain all 0.1.0a2 fixes, update browser-upload instructions and record separate validation of this package.

Packet dissection, replay, address/name extraction and richer PE analysis remain
deferred. This release adds no runtime dependency. Kali acceptance is pending;
the maintainer's earlier Kali report remains specific to 0.1.0a1.

## 0.1.0a2 — 2026-10-15

Reporting fixes following the maintainer's Kali validation of 0.1.0a1;
release label `v0.1.0-alpha.2`. Date is in the maintainer's Asia/Karachi timezone.

- Applied the maintainer's curl-error diagnostic fix and connection-refused regression. Transport reasons now reach check notes while evidence retains stderr, return codes and header-parse errors.
- Skip optional web probes after curl DNS/connect failures (6/7) without an HTTP response. HTTP 403/404 responses still permit probes. Incomplete probe sets include counts and reasons.
- Flag PNG trailing bytes as an anomaly and a Markdown highlight with the offset and evidence reference, even when earlier anomalies or check details are capped.
- Preserve PNG chunk-name bytes using escaped labels plus `type_hex`; invalid type bytes are explicitly flagged.
- Explain partial string, encoding, statistics, container and native-tool results. Keep-versus-found counts distinguish result selection from incomplete scans. Markdown retains compact partial notes when the full section does not fit.
- Fix the encoding result boundary: exactly 12 candidates no longer implies truncation. Count compatible interpretations throughout the bounded 64 KiB sample while retaining at most 12 previews.
- Handle expected connection resets in the self-signed TLS test server without suppressing unrelated exceptions.
- Record the maintainer-reported Kali/Python 3.14.7 results, remaining manual coverage gaps, editable installation instructions and separate validation of this update.
- Add `runs/` to `.gitignore`; retain the existing `wired2ai-runs/` rule. Refresh the harmless example report and complete browser-upload package.

The Kali report covers 0.1.0a1 and its locally patched 60-test state, not a Kali
run of this release. The updated package still requires a Kali rerun. No new
CTF category or extraction/exploitation feature was added.

## 0.1.0a1 — 2026-10-11

First working alpha; Git tag `v0.1.0-alpha.1`.

- Added a Python CLI for web, pwn, RE, cryptography and digital-forensics triage.
- Added bounded private input snapshots, full-snapshot SHA-256 and offset-bearing strings.
- Added native-command provenance, explicit collector statuses, process timeouts and output limits.
- Added static ELF and basic PE observations, bounded crypto preprocessing, PNG/ZIP/PCAP structure checks and optional ExifTool metadata.
- Added scoped GET requests, redirect/request limits, content-aware exposure indicators and environment-value omission.
- Added private JSON/Markdown reports, a Markdown byte budget and best-effort redaction.
- Added local regression/integration tests, documentation, release history and a proposed GitHub CI workflow.
- Added a complete browser-upload source ZIP and browser-only publication instructions; README installation now uses the uploaded source directly. This packaging/documentation update does not change the application code.

Validation and remaining limitations are recorded in `docs/VALIDATION.md`.
This release does not implement the full planned check catalog.
