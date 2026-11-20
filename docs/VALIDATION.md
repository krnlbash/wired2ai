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
| 0.2.0a1 | Ubuntu 24.04.3, Python 3.12.14; 2026-10-20 UTC | Fresh installed package: 94 tests passed, no skips; Kali and independent PCAPNG-reader comparison pending |
| 0.2.0a2 | Ubuntu 24.04.3, Python 3.12.14; 2026-10-21 UTC | Fresh installed package: 126 tests passed, no skips; combined Kali acceptance deferred |
| 0.2.0a3 | Ubuntu 24.04.3, Python 3.12.14; 2026-10-22 UTC | Fresh installed package: 158 tests passed, no skips; manual Kali and independent packet-reader comparison deferred |

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

## 0.2.0a3 development verification

The packet-header phase was verified locally on 2026-10-22 UTC. Manual Kali
acceptance remains deferred at the maintainer's request. Built a wheel offline,
installed it in a fresh virtual environment and ran tests outside the source
repository with `PYTHONPATH` unset. The imported package was the new environment's
`site-packages`, not the source tree.

```text
wired2ai 0.2.0a3
Ran 158 tests in 2.509s
OK
```

All 158 tests passed with no skips. The 32 added packet tests cover:

- A literal UDP wire fixture with independently specified byte offsets/ports;
  six supported link types, both classic-PCAP byte orders and timestamp units.
- PCAPNG mixed-endian sections and Enhanced/Simple/obsolete Packet Block forms;
  counts extending beyond F002's retained packet sample.
- VLAN and IPv6-extension count/byte bounds, IPv4 options and invalid lengths,
  fragments, IPv6 atomic/repeated fragment headers, and unsupported protocols.
- Truncated header prefixes, declared IP bounds versus Ethernet padding,
  incomplete captured payload with retained header evidence, UDP/TCP lengths,
  ARP framing and ICMP common prefixes.
- The actual 10,000/10,001-packet boundary, container scan limits, capped port/link
  tables, continuing counts for retained keys and late packet-issue provenance.
- Malformed containers discarding earlier header results, omission across all
  category overrides, absence of fixture addresses/payload markers in every
  exported file, and compact observations within an 8 KiB Markdown budget.

The installed CLI regenerated four documentation examples:

| Example | Actual check results |
| --- | --- |
| Crypto | 7 complete, 1 not applicable |
| PCAPNG | 5 complete, 3 skipped; F004 observes two IPv4/UDP packets |
| PE RE | 9 complete |
| Packet PCAP | 4 complete, 3 skipped, 1 partial; eight records and three packet issues |

The 647-byte packet fixture has five decoded, one fragmented, one truncated and
one unsupported record. Six records have decoded supported headers, including
the packet with a missing payload suffix. Ports and offsets agree with the
fixture's declared layout. Source hashes and report/evidence references were
checked during packaging; examples are actual CLI output, not hand-written
expected-result files.

The 2.509-second run is a regression result, not a performance benchmark. The
host has no tcpdump, tshark or capinfos, so independent packet-reader comparison
and broad real-capture compatibility remain pending. No network traffic was
captured or replayed; existing web integration tests use disposable loopback
servers. Existing ELF/PE integration checks remain in the same suite. The JSON
data schema is included as a field contract; no external JSON Schema validator
was installed for this run. See [packet scope](PACKETS.md) for limits.

## 0.2.0a2 development verification

The next phase expands static PE triage while retaining PCAPNG and earlier
reporting fixes. At the maintainer's request, manual VM testing is grouped into
a later session. Developer regression checks below do not close that gate.

Built the wheel offline and installed it into a fresh virtual environment.
The test process ran outside the repository with `PYTHONPATH` unset, importing
the package from the new environment's `site-packages`.

```text
wired2ai 0.2.0a2
Ran 126 tests in 2.211s
OK
```

All 126 tests passed with no skips, including 32 new PE test methods. The existing
header-only fixture was updated to declare its header extent explicitly, matching
the stricter supported PE admission checks. New coverage includes:

- PE32/PE32+ field and thunk widths; file-backed versus virtual-only mappings;
  overlapping mappings; entry-point absence; raw overlaps and section permissions.
- Every truncated prefix before the synthetic fixture's last raw section byte,
  hostile offsets/counts and optional-header/section bounds.
- Named/ordinal imports, an unbound IAT fallback, unresolved bound IATs,
  terminators, reserved thunk bits, unterminated/capped names and late API leads.
- A global 4,096-thunk cap across multiple DLLs and the exact 128-descriptor
  boundary, including verified terminators and explicit incomplete-count notes.
- Named, unnamed and forwarded exports, empty slots, invalid ordinal indices,
  null array RVAs, ordinal overflow, oversized counts and bounded aliases/details.
- Certificate addresses treated as file offsets, table framing/range failures,
  the 64-entry cap and conservative trailing-data classification.
- Section entropy provenance, escaped section names, independent collector
  failures and compact observations within an 8 KiB brief.

GNU objdump 2.42 independently decoded both synthetic PE variants and reported
the expected DLL/name/ordinal and forwarded-export declarations. Separate tests
used GNU as/objcopy/ld to build PE32 and PE32+ fixtures, then parsed their header,
entry-point and export evidence. No resulting PE file was executed. These are
independent construction/reader checks, not broad Windows-loader validation.

The installed CLI regenerated all three examples. Crypto produced seven complete
checks and one not applicable; PCAPNG produced four complete and three deliberately
skipped checks; PE RE triage produced nine complete checks. The PE input is 3,105
bytes, with two sections, two imports, three nonempty exports and 17 unclassified
trailing bytes after excluding its 16-byte framed synthetic certificate table.
Regeneration produced byte-identical input. The fake certificate payload is not
an Authenticode signature and was never described as trusted.

This run took 2.211 seconds; that is one regression run, not a benchmark. Real
MSVC/MinGW, packed/obfuscated, signed and malicious PE coverage remains pending,
as does the combined Kali session. Hosted GitHub CI remains unverified here.
See [PE scope](PE.md) for exact limits and deferred structures.

## 0.2.0a1 development verification

Built a wheel offline from the changed source with no runtime dependencies,
installed it into a fresh virtual environment, and ran the suite from outside
the source directory with `PYTHONPATH` unset. The import path was the fresh
environment's `site-packages`.

```text
wired2ai 0.2.0a1
Ran 94 tests in 2.212s
OK
```

All 94 tests passed with no skips. The 22 added PCAPNG test methods cover:

- A literal section-header fixture, both byte orders, mixed-endian sections,
  section-local interface resets, multiple interfaces and declared boundaries.
- Decimal/binary resolutions, negative offsets, 64-bit ticks, extreme allowed
  resolution exponents and exact integer arithmetic. File order is distinguished
  from chronological order; Simple Packet Blocks have no invented timestamp.
- Enhanced, Simple and obsolete Packet Blocks; inconsistent length observations;
  missing interfaces; malformed option lengths and duplicate timestamp options.
- Every nonempty truncated prefix of a small supported capture, corrupted
  lengths/trailers/magic and attacker-controlled oversized declarations.
- Actual traversal to the 100,000-block cap with distinct unknown types; section,
  interface, per-block option and global option caps; retained-sample counts.
- Opaque/decryption-secrets block omission and complete report export checks
  across auto/forensics/crypto/re/pwn category selections. The native runner is
  forbidden in this test to verify that generic collectors cannot bypass the
  PCAPNG metadata-only gate.
- CLI failed/unsupported/partial statuses, strict exit behavior and a compact
  capture summary within an 8 KiB Markdown budget.

The installed CLI generated both example reports in that release. Crypto produced
seven complete checks and one not-applicable check. PCAPNG produced four complete
checks and three explicitly skipped raw/native collectors, with two packet
records across two interfaces, 138 captured bytes, all 288 input bytes inspected,
no anomalies and no decryption-secrets blocks. Regenerating the synthetic capture
produced identical bytes and SHA-256:

```text
d51eefc5f087c47f0c16b5d46bb49fb0e7e1e1d95e00c001babbbb447d01766f
```

The demo contains synthetic Ethernet/IPv4/UDP bytes; this parser does not dissect
those protocols. No real traffic was captured or replayed. The host has no
Wireshark/capinfos/dumpcap installation, so no independent reader comparison is
claimed. The previous Kali real-capture test exercised 0.1.0a1's unsupported
status and does not validate this new parser. Duration above is one regression
run, not a throughput or security guarantee. See [PCAPNG scope](PCAPNG.md).

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
The 0.1.0a2 archive contains that actual report. The current examples were
regenerated with the current package; each report records its own tool version and run time.

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
PCAPNG was explicitly unsupported in a1 and a2. Support starts in 0.2.0a1;
the historical Kali result above is not a test of the new parser.

## Earlier regression coverage retained

The original suite covers regular-file admission, symlink/FIFO/size rejection,
private snapshots and hashing, subprocess output/time limits and environment
isolation, redaction/fences/report permissions, real compiled ELF fixtures,
public-only private-key export, malformed PNG/ZIP/PCAP, scoped local HTTP probes,
redirect limits and rejection of a self-signed certificate. The ELF fixture uses
a sentinel to detect accidental target execution; no sentinel was created.

These checks do not replace a corpus of independently reviewed real challenges.

## Remaining coverage and release gates

- Run the complete 0.2.0a3 package on Kali, including ExifTool, the inherited
  a2 reporting fixes, probe skipping and the TLS test log. Record the installed
  OS/Python/tool versions; the new work does not close the earlier Kali gate.
- Inspect real dumpcap PCAPNG files, multiple interfaces/sections, snaplen
  truncation and decryption-secrets block omission. Compare supported counts
  and exact timestamps against an independent reader; retain harmless fixtures.
- Inspect successful trusted HTTPS behavior and repeat redirect, header,
  form/script and Git HEAD content checks manually on Kali.
- Broaden forensic fixtures: unsafe/absolute ZIP paths, encrypted and ZIP64
  containers, truncated PCAP, files near the 32 MiB limit and EXIF-rich images.
  ZIP64 is outside the current bounded parser's support; validate its rejection.
- Broaden binary fixtures: non-PIE, no-RELRO, executable-stack, no-canary and
  representative PE variants; absence of one symbol is not proof of no canaries.
- Compare PE imports/exports and section offsets on permitted MSVC/MinGW samples;
  include signed files and packed/overlapping layouts. Verify that unsupported
  structures and certificate trust remain explicit rather than inferred.
- Inspect actual base64/hex K002 observations and duplicate/oversized RSA input
  behavior manually; unit tests alone do not complete that acceptance task.
- A passing hosted GitHub Actions run remains unverified here. Check the actual
  Actions result after uploading this release.
- ARM Linux, other Python versions, parser fuzzing, strong isolation, forensic
  acquisition/chain of custody and secure erasure are not validated.
- Time savings, model accuracy, hallucination reduction and prompt-injection
  resistance remain unmeasured. No result here supports claims about them.

## Combined Kali acceptance session — deferred

When ready, download/extract the updated source and create a virtual environment using the
README. From the folder containing `pyproject.toml`, install from source and run:

```bash
.venv/bin/python -m pip install .
.venv/bin/wired2ai --version
.venv/bin/wired2ai doctor --json
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/wired2ai triage /bin/ls --category pwn
.venv/bin/wired2ai triage /bin/ls --category re
.venv/bin/wired2ai triage examples/pe-demo.bin --category pwn
.venv/bin/wired2ai triage examples/pe-demo.bin --category re
.venv/bin/wired2ai triage examples/crypto-demo.txt --category crypto
.venv/bin/wired2ai triage examples/pcapng-demo.pcapng --category forensics
.venv/bin/wired2ai triage examples/packet-demo.pcap --category forensics
```

The version should be `0.2.0a3`; the suite currently contains 158 tests. Record any
skips as reduced coverage. Repeat the PNG trailer/invalid-byte and capped-result
cases and inspect both JSON and Markdown. Save the actual environment and test
results before claiming that this release has been validated on Kali. These
steps can wait until the maintainer resumes VM testing. For source editing,
use `.venv/bin/python -m pip install -e .`; ordinary installation copies code and
must be repeated after edits.

The full suite includes disposable loopback HTTP/TLS fixtures for the web
category; no public endpoint is needed. Manual web checks should use a permitted
local challenge with known headers/forms/scripts and inspect W001–W005 contents.
For PCAPNG, check the documented example counts/timestamps and then a real capture
with an independent reader. For PE, compare P/R001–004 to the expectations in
`docs/PE.md`; do not mistake a complete check or framed certificate for a security
verdict. For packet headers, compare F004 against `docs/PACKETS.md`, then compare
permitted real captures with a current independent reader. Include Linux SLL2,
fragments, snaplen truncation and unsupported link types. This one session can
cover the accumulated reporting, PCAPNG, PE and packet-summary work.
