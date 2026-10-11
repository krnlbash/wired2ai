# Validation record — 0.1.0a1

Completed **2026-10-11 UTC**. This is a local validation record, not a third-party
audit or a claim of comprehensive security/format correctness.

## Host and dependencies

| Component | Observed |
| --- | --- |
| OS | Ubuntu 24.04.3 LTS, Linux x86_64 |
| Python | 3.12.14 |
| file | 5.45 |
| GNU readelf | Binutils 2.42 |
| OpenSSL | 3.0.13 |
| curl | 8.5.0 |
| ExifTool | Not installed; unavailable handling exercised |
| Runtime Python dependencies | None outside the standard library |

The package was built without network access to a package index:

```bash
python3 -m pip wheel --no-deps --no-build-isolation --no-index . -w dist
python3 -m venv .venv
.venv/bin/python -m pip install --no-index dist/wired2ai-0.1.0a1-py3-none-any.whl
.venv/bin/python -m unittest discover -s tests -v
```

The final test invocation imported the installed package from the virtual
environment's `site-packages`, not the source tree.

```text
Ran 59 tests in 1.939s
OK
```

All 59 tests passed; no tests were skipped on this host. Execution time is only
a local observation, not a performance promise.

## Meaningful coverage

- Input admission: regular files, final-component symlinks, FIFOs, size limits,
  private snapshots, complete identity and stability after the original changes.
- Subprocess behavior: argv isolation, output cap, timeout, inherited pipe handles,
  environment filtering and missing tools.
- Reports: private modes, refusal to overwrite, redaction patterns, control
  characters, Markdown fences, byte-budget omissions and evidence references.
- Pwn/RE: a real locally compiled PIE/RELRO ELF, exact symbol normalization,
  basic PE headers and invalid offsets. The fixture would create a sentinel if
  executed; neither category created it.
- Crypto: canonical decoding, source offsets, literal RSA checks, invalid or
  ambiguous parameters, generated RSA private-key public-only export and
  encrypted-container suppression without a password prompt.
- Forensics: PNG chunk CRCs/trailing bytes/malformed lengths, valid consecutive
  IDAT handling, ZIP unsafe paths/directory inconsistencies and classic PCAP
  record bounds.
- Web: a local HTTP fixture server, default no-probe behavior, scoped optional
  probes, query/cookie/environment-value omission, soft-404 handling, request
  and redirect limits, out-of-scope redirects, body caps and chunked transfer.
- TLS: a local server with a disposable self-signed certificate was rejected by
  curl with return code 60; the request did not reach its HTTP handler.

A separate installed-CLI forensic smoke run used a valid one-pixel PNG with a
17-byte synthetic trailer. C001–C004, F001 and F002 completed; F002 reported the
trailer with no chunk anomalies. F003 reported `unavailable` because ExifTool
was absent. The harmless crypto CLI example produced seven completed checks
and one non-applicable PEM check; its actual report is included under `examples/`.

## Not yet validated

- A clean Kali installation, other Python minor versions, ARM Linux, or other OSes.
- Successful ExifTool execution on this host; only its missing-tool behavior.
- A hosted GitHub Actions run. The workflow is prepared, not executed remotely.
- A broad corpus of real CTF files, adversarial parser fuzzing, complex PE variants,
  alternate native-tool implementations or every HTTPS deployment.
- Time savings, model accuracy, reduced hallucination or prompt-injection resistance.
- Strong isolation, forensic acquisition/chain of custody or secure erasure.

## Kali acceptance steps

1. Install the host tools listed in the README and `gcc` for the ELF test fixture.
2. Install the supplied wheel in a fresh virtual environment.
3. Save `wired2ai doctor --json` and run the complete test command above.
4. Run the synthetic crypto example and a redistributable PNG/ZIP/PCAP fixture;
   inspect `context.md`, `report.json` and ExifTool status.
5. Record the actual Kali release, Python/native-tool versions, test count and
   any failures before removing the alpha label or claiming Kali validation.
