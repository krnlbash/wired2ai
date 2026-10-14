# Changelog

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
