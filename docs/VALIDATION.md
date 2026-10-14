# Validation record

Results belong to a specific version and environment. A passing regression suite
is not a security audit, full format-conformance result or proof of CTF usefulness.
Maintainer-reported Kali observations below are distinguished from checks run in
the development environment; the underlying Kali logs/artifacts were not supplied
with that report for independent replay.

| Version / state | Environment | Evidence and result |
| --- | --- | --- |
| 0.1.0a1 original | Ubuntu 24.04.3, Python 3.12.14; 2026-10-11 UTC | Installed package: 59 tests passed, no skips |
| 0.1.0a1 original, then local curl patch | Kali rolling, Python 3.14.7; maintainer report dated 2026-10-15, Asia/Karachi | Maintainer reports 59/59 original tests, then 60/60 with the curl diagnostic regression |
| 0.1.0a2 | Ubuntu 24.04.3, Python 3.12.14; 2026-10-14 UTC (2026-10-15 Asia/Karachi) | Fresh installed package: 72 tests passed, no skips; Kali rerun pending |

## Environment details

| Component | Development host, directly observed | Kali, as reported by maintainer |
| --- | --- | --- |
| OS | Ubuntu 24.04.3 LTS, Linux x86_64 | Kali Linux rolling, 2026-10-15 |
| Python | 3.12.14 | 3.14.7 |
| file | 5.45 | 5.47 |
| GNU readelf | Binutils 2.42 | Binutils 2.47 |
| OpenSSL | 3.0.13 | 3.6.4 |
| curl | 8.5.0 | 8.22.0 |
| ExifTool | Not installed; unavailable handling exercised | 13.55, found by doctor; forensic category runs reported successful |
| Installation | Offline wheel build, fresh venv, installed wheel | git clone, venv, pip install .; later editable installation |

The Kali installation method does not change the maintainer's publishing
preference: all GitHub updates and releases use the browser.

## 0.1.0a2 development verification

The package was built from the changed source without a package-index connection,
using build tooling already installed on the development host. The resulting
wheel was installed in a fresh virtual environment. The test process imported
`wired2ai` from that environment's `site-packages`, not from `src/`.

```text
wired2ai 0.1.0a2
Ran 72 tests in 1.872s
OK
```

All 72 tests passed and none were skipped. Duration describes this single local
run, not a performance guarantee. The suite includes 13 new test methods beyond
the original 59, plus strengthened existing assertions. New regression
assertions were first run against the old implementation and reproduced the
reported missing notes, diagnostic, byte-preservation and trailer issues.

This update verifies:

- Actual loopback connection refusal reports curl exit 7 and sends no optional
  probes. The test keeps an unlistening socket bound to avoid a port-reuse race.
- Stubbed DNS/transport failures exercise the error mapping without contacting
  public services; HTTP 403 still permits scoped probes on the local fixture.
- Request-budget exhaustion gives a completed/attempted count and reasons for
  incomplete exposure probes. Existing header, form, script, Git HEAD and
  secret-omission assertions inspect report contents, not only completion status.
- PNG trailing bytes appear in anomalies and a Markdown highlight with an offset
  and evidence reference. The lead survives an anomaly cap and an 8 KiB brief.
- Invalid PNG type bytes, including non-ASCII, NUL, escape and backslash bytes,
  retain escaped labels and exact hexadecimal bytes.
- String notes distinguish selecting 80 of 81 candidates from stopping a scan at
  2,000 candidates. Encoding tests cover exactly 12, 13 and 30 candidates and
  input beyond the 64 KiB sample boundary.
- Native output caps reach check notes. Partial notes precede data and can be
  retained alone when a long check does not fit the Markdown budget.

The included synthetic crypto example was regenerated using the installed
0.1.0a2 CLI: seven checks completed and one PEM check was not applicable.
`examples/crypto-report/` contains that actual report. Its timestamps and tool
versions belong to this run.

The TLS fixture now handles an expected `ConnectionResetError` during rejection
of its self-signed certificate. Unrelated server exceptions remain visible. No
server traceback appeared in this local run; the reported Python 3.14 noise fix
still needs confirmation on Kali.

## Maintainer's 0.1.0a1 Kali validation

The maintainer reports all 59 original tests passing. After applying the supplied
curl-error patch locally, a new regression failed without the patch, passed with
it, and the full suite passed at 60/60. The self-signed TLS rejection test passed
but emitted a server-thread `ConnectionResetError` traceback.

### Pwn and reverse engineering

`/bin/ls` was identified as a stripped PIE x86-64 ELF with full RELRO indicators,
a non-executable stack and an observed `__stack_chk_fail` symbol. The declared
libraries were `libselinux.so.1` and `libc.so.6`. `strcpy` was an imported-symbol
lead, not a vulnerability claim. `symtab_observed: false` and
`dynsym_observed: true` were consistent with the observed stripped file.

This manual run did not cover non-PIE, no-canary, executable-stack or PE samples.
Static indicators do not establish runtime mitigation coverage.

### Cryptography

| Input | Maintainer's observation |
| --- | --- |
| Base64 text | Six complete, one no_match, one not_applicable; K002 content was not inspected |
| Public PEM | K004 complete; K003 no_match, as expected |
| Private PEM | Generic header/strings/encoding/RSA previews suppressed; no private-key marker or selected key-body line found in output; K004 contained modulus and exponent, not private components |
| X.509 certificate | CN=test.local subject/issuer, dates and serial; no trust claim; K002 partial with unexplained selection cap in a1 |
| AES-256 encrypted PEM | No prompt or hang; most checks skipped |
| Literal n=3233, e=17, c=2790 in text and JSON | Consistent observations with source locations (line number versus JSON path) |
| n=49, e=3, c=80 | Perfect-square modulus, out-of-range ciphertext and conservatively worded small-exponent observation |

The private-key checks establish what those inspections found for those samples;
they do not establish complete secret-redaction coverage.

### Web

Testing used a local `http.server`. Both a clean fixture page and a server serving
the repository produced five completed checks with probes enabled. Logs showed
the entry page, robots, random missing-path control, Git HEAD and environment
requests. The first failure was reproduced as a server-not-listening case.
Closed-port results remained failed/partial/skipped rather than falsely complete.

The main failure note was too vague: `Incomplete HTTP response headers` obscured
curl's connection failure. The supplied patch and 60th test surfaced curl exit 7.
That fix is integrated in 0.1.0a2, which additionally skips optional probes on
DNS/connect failures without a response. The a1 failed-probe observations do not
describe a2's new skip policy.

The manual session did not inspect W003 forms/scripts, W005's Git HEAD 200
classification or header observations, and did not test redirects or a successful
trusted TLS connection. Local automated fixtures cover several of these paths;
that is separate evidence from the manual Kali run.

### Digital forensics

| Input | Maintainer's observation |
| --- | --- |
| Clean PNG | Seven chunks, valid CRCs, no trailing bytes |
| PNG with appended data | 25 trailing bytes at offset 14249; a synthetic flag string appeared among strings; a1 left anomalies empty |
| PNG with byte 40 overwritten | CRC mismatch at chunk offset 33; the invalid chunk-name byte rendered as a replacement character in a1 |
| PNG with byte 60 overwritten | CRC mismatch for pHYs at offset 51 |
| ZIP containing a.txt | Entry listed, no risks, no extraction; only a trivial ZIP was tested manually |
| Classic tcpdump PCAP | 17 records, link-type field 276 (LINUX_SLL2), plausible timestamps, no reported anomalies |
| Hand-built and real PCAPNG | F002 unsupported with an explanation; six other checks completed; no crash |

PNG trailing-data visibility and raw type-byte preservation are corrected in a2.
PCAPNG remains explicitly unsupported; this update adds no parser for it.

## Earlier regression coverage retained

The original suite covers regular-file admission, symlink/FIFO/size rejection,
private snapshots and hashing, subprocess output/time limits and environment
isolation, redaction/fences/report permissions, real compiled ELF fixtures,
public-only private-key export, malformed PNG/ZIP/PCAP, scoped local HTTP probes,
redirect limits and rejection of a self-signed certificate. The ELF fixture uses
a sentinel to detect accidental target execution; no sentinel was created.

These checks do not replace a corpus of independently reviewed real challenges.

## Remaining coverage and release gates

- Rerun the complete 0.1.0a2 package on Kali/Python 3.14.7, including ExifTool,
  changed notes/PNG evidence, probe skipping and the TLS test log.
- Inspect successful trusted HTTPS behavior and repeat redirect, header,
  form/script and Git HEAD content checks manually on Kali.
- Broaden forensic fixtures: unsafe/absolute ZIP paths, encrypted and ZIP64
  containers, truncated PCAP, files near the 32 MiB limit and EXIF-rich images.
  ZIP64 is outside the current bounded parser's support; validate its rejection.
- Broaden binary fixtures: non-PIE, no-RELRO, executable-stack, no-canary and
  representative PE variants; absence of one symbol is not proof of no canaries.
- Inspect actual base64/hex K002 observations and duplicate/oversized RSA input
  behavior manually; unit tests alone do not complete that acceptance task.
- A passing hosted GitHub Actions run remains unverified here. Check the actual
  Actions result after uploading this release.
- ARM Linux, other Python versions, parser fuzzing, strong isolation, forensic
  acquisition/chain of custody and secure erasure are not validated.
- Time savings, model accuracy, hallucination reduction and prompt-injection
  resistance remain unmeasured. No result here supports claims about them.

## Next Kali acceptance steps

Download/extract the updated source and create a virtual environment using the
README. From the folder containing `pyproject.toml`, install from source and run:

```bash
.venv/bin/python -m pip install .
.venv/bin/wired2ai --version
.venv/bin/wired2ai doctor --json
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/wired2ai triage examples/crypto-demo.txt --category crypto
```

The version should be `0.1.0a2`; the suite currently contains 72 tests. Record any
skips as reduced coverage. Repeat the PNG trailer/invalid-byte and capped-result
cases and inspect both JSON and Markdown. Save the actual environment and test
results before claiming that a2 has been validated on Kali. For source editing,
use `.venv/bin/python -m pip install -e .`; ordinary installation copies code and
must be repeated after edits.
