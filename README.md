# wired2ai

Local CTF triage with traceable evidence for analysts and LLMs.

**Version: 0.1.0a1 — first working alpha.** Maintainer: **krnlbash**.
Target platform: Kali Linux; Python 3.11+. This release was validated on Ubuntu
24.04 with Python 3.12, not on a Kali installation. See [validation](docs/VALIDATION.md).

wired2ai turns a challenge file or an explicitly supplied web URL into a bounded
Markdown brief and a structured JSON report. It collects observations and records
where they came from. It does not execute challenge programs, generate exploits,
send anything to an LLM, or guarantee that an LLM's conclusions are correct.

## First-release coverage

| Category | Implemented | Deliberate limits |
| --- | --- | --- |
| Web exploitation | GET response/redirect evidence, selected headers, HTML forms/scripts, optional robots/Git HEAD/environment probes with a missing-path control | No crawler, authenticated session, JavaScript execution, fuzzing, repository download or automatic exploit validation |
| Pwn | ELF headers, static NX/PIE/RELRO/canary indicators, declared libraries, selected exact symbol matches; basic PE headers | No `ldd`, target execution, gadget discovery or runtime protection claims |
| Reverse engineering | ELF evidence plus grouped strings/offsets and language/runtime hints; basic PE headers | No decompiler, call graph, emulator or unpacker |
| Cryptography | Byte statistics, bounded one-layer hex/base64 candidates, literal RSA n/e/c sanity checks, PEM public components/X.509 metadata | No factoring service, brute force, private-key dump, trust verification or encrypted-key unlocking |
| Digital forensics | File identity, header bytes, strings, optional ExifTool metadata, PNG chunks/CRC/trailing data, ZIP directory risks, classic PCAP record metadata | No extraction, image decompression, disk/memory-image analysis, packet dissection or PCAPNG parser |

File categories share a complete snapshot SHA-256, source filesystem timestamps,
native format identification, a 64-byte header preview and selected ASCII/UTF-16
strings. Private-key PEM markers suppress generic header/string previews.

## Install on Kali

Install the host prerequisites if they are not already available:

```bash
sudo apt update
sudo apt install python3 python3-venv file binutils openssl curl libimage-exiftool-perl
```

Download the project using GitHub's **Code → Download ZIP** button and extract
it. Open a terminal in the folder containing `pyproject.toml`, then run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/wired2ai doctor
```

There are **no third-party Python runtime dependencies**. Installing from source
requires setuptools >= 77 and may download build dependencies. You can also run
directly with `PYTHONPATH=src python3 -m wired2ai --help`.
Installing OS packages requires privileges; running wired2ai does not.

## Use

```bash
.venv/bin/wired2ai triage ./challenge --category pwn --out ./runs/pwn-01
.venv/bin/wired2ai triage ./challenge --category re --out ./runs/re-01
.venv/bin/wired2ai triage ./cipher.txt --category crypto --out ./runs/crypto-01
.venv/bin/wired2ai triage ./capture.pcap --category forensics --out ./runs/forensics-01
.venv/bin/wired2ai web 'http://127.0.0.1:8000/app/' --probe-paths --out ./runs/web-01
```

The web example assumes **your own running local challenge server**. Tests create
their own loopback server; no public target is needed to validate the release.
Only inspect systems you are authorized to test.

Without `--probe-paths`, web collection requests the supplied page and bounded
redirects only. Additional probes use the **directory of the original URL**:
`https://host/app/` probes inside `/app/`; `https://host/app` has `/` as its
directory. Include the trailing slash when a directory scope is intended.
Redirects cannot change scheme, host, effective port, or leave that directory.
Probe requests do not follow redirects. IP/private-address targets are permitted
for local CTFs; this is not an SSRF filtering service.

`--category auto` selects RE for ELF/MZ inputs, crypto for text, and forensics for
other files. This is a convenience heuristic; specify the category when you know
the challenge. Pwn and RE intentionally share their low-level ELF collectors.
An existing `--out` path is always rejected. Omitting it creates a unique directory
under `wired2ai-runs/`.

## Read the result

Each run creates:

- `context.md`: a Markdown brief within a byte budget, with a check inventory and explicit omissions.
- `report.json`: all collected structured observations, evidence references, tool versions and limits.
- `evidence/E001.json`, etc.: individual sanitized evidence records.

Read the check statuses first. `complete` means the collector finished; it does
not mean the target is safe or exploitable. Missing tools, timeouts, unsupported
formats, skipped checks and partial results are distinct states. A HTTP 404 is a
completed response, not a connection failure. Use [CLI reference](docs/CLI.md) for
the full status and exit-code definitions.

The input is copied to a temporary private snapshot, bounded by the configured
file-size limit. Native tools read that snapshot, not the original path. Hashes
cover the **complete snapshot**, not a prefix. Snapshot files are removed on
normal exit; reports use mode 0600 and their run directory uses mode 0700.
The tool does not modify the input's contents, but reading it can update access
time. This is a CTF triage utility, not a forensic acquisition system.

## Limits and trust

Defaults are a 32 MiB input limit, 10 seconds per native process, 64 KiB combined
stdout/stderr per command, a 32 KiB Markdown brief and 10 web requests including
redirects. These are byte/time limits, not model-specific token guarantees. A
large file is rejected instead of silently hashing or analyzing only its prefix.

Output is treated as untrusted data. Markdown fences and terminal control
characters are handled defensively, and familiar secret patterns are redacted.
Web environment probes export variable names only; raw response bodies are not
saved. **Redaction can miss secrets, personal data or obfuscated material. Review
every export before sharing it.** Sanitized evidence is not a lossless copy of
native output. A Markdown label cannot stop prompt injection in an LLM.

The process runner uses argument arrays, a controlled environment and process-group
timeouts. It is **not a sandbox**: a vulnerable native parser can still access
resources available to your account. Use an isolated VM for hostile artifacts.
No application-level promise of offline collection replaces an OS network policy.
See [security model](SECURITY.md) and [architecture](docs/ARCHITECTURE.md).

## Develop and test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests use Python's standard library. `gcc`, `readelf`, `openssl` and `curl` enable
the corresponding integration tests; absent tools cause explicit test skips.
Install `gcc` for the compiled ELF fixture. Test-generated private keys and all
web fixtures are disposable local data.

The GitHub CI workflow uses Ubuntu 24.04 and runs installation and tests. Check
the repository's **Actions** tab for the actual hosted run status; the presence
of a workflow file is not evidence of a passing run. The repository includes a [changelog](CHANGELOG.md),
[roadmap](docs/ROADMAP.md), [contribution guide](CONTRIBUTING.md) and JSON Schema.

## Publishing through the browser

The maintainer's workflow is **GitHub browser uploads for every version**.
The browser-upload ZIP contains all 34 repository files, including
`pyproject.toml`, `.gitignore`, and `.github/workflows/ci.yml`. Extract it on
Windows, open the extracted folder, and drag its contents into GitHub's
**Add file → Upload files** page. `README.md`, `pyproject.toml`, and `src/`
must be directly at the repository root.

The archive is source-only: everything inside is intended for the repository.
Installation uses the source command above. Uploading extracted files creates
GitHub commits; it does not import a separate local Git history or tag. Create
the alpha tag and pre-release through GitHub's Releases page when ready.
The Python version `0.1.0a1` corresponds to the release label
`v0.1.0-alpha.1`. See the [browser release guide](docs/RELEASING.md) for the
complete procedure and updates to later versions.

This initial implementation was developed with Codex assistance; project
maintenance belongs to krnlbash. The
portfolio value will come from understanding the code, reproducing results,
fixing real failures and documenting useful improvements.

License: [MIT](LICENSE).
