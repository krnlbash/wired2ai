# Changelog

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
