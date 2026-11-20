# Roadmap

Ship improvements when a real fixture demonstrates the need. Version numbers
represent coherent capabilities, not a schedule for generating GitHub activity.

| Milestone | Deliverable | Release gate |
| --- | --- | --- |
| 0.1.0 alpha | Five small category modules, local reports, bounds and provenance | Local regression suite, usable package and honest coverage documentation |
| 0.1.0a2 | Kali-driven reporting fixes: curl reasons, PNG leads, explicit partial counts | Local regression suite and package validation; Kali rerun pending |
| 0.2.0a1 | First forensics expansion: bounded PCAPNG 1.0 metadata and safe exports | Installed-package regression suite, reproducible synthetic capture; Kali/real-capture acceptance pending |
| 0.2.0a2 | Static PE expansion: section layout, imports/exports, flags and certificate/tail accounting | Installed-package suite, independent objdump/linker fixtures; combined Kali acceptance deferred |
| 0.2.0a3 | Bounded PCAP/PCAPNG packet-header summaries and consistent capture export policy | Local regression/package checks; independent reader and combined Kali acceptance deferred |
| 0.1.0 stable / 0.1.x | Kali validation, parser compatibility fixes, sharper failure reporting | Reproduced installation on a clean Kali VM, recorded doctor output, no unresolved critical regression |
| 0.2.0 | Deeper forensics/RE: PCAPNG, selected packet dissection, improved PE detail | Bounded malformed-input fixtures and useful evidence beyond the alpha |
| 0.3.0 | Better web/crypto: explicit custom CA support, stronger soft-404 handling, richer crypto formats | Negative controls, no secret-export regression, reproducible examples |
| 0.4.0 | Controlled derived artifacts/extraction, report reuse and improved context selection | Path/link/bomb limits; provenance for every derived artifact; evaluated report usefulness |
| 1.0.0 | Stable schema/collector interfaces and published support matrix | Independent use, compatibility policy and measured time/accuracy results |

## Next concrete issues

1. Validate the current 0.2.0a3 package together on Kali when the maintainer is
   ready, including the inherited reporting fixes, ExifTool, PCAPNG, PE and packet-header cases.
   The maintainer's 0.1.0a1 validation is recorded in `docs/VALIDATION.md`;
   retain version-specific results and inspect the JSON/Markdown contents.
2. Add the first false-positive or missed-observation regression from a real,
   redistributable CTF artifact. Include its expected evidence, not only a flag.
3. Evaluate 10–20 permitted fixtures against manual triage: collection time,
   useful observations, misleading observations and report size. If using an
   LLM, compare the same model/settings with and without the report; do not
   claim reduced hallucination without measurement.
4. Tighten redaction and schema contracts before expanding collectors.
5. Next feature candidate: explicit custom CA support for permitted web targets,
   with strict TLS/redirect tests and no automatic trust bypass. Further packet
   decoding and deeper PE structures need independent-reader comparisons and
   representative redistributable captures/binaries before broader claims.

0.2.0a1, a2 and a3 are incremental parts of the 0.2.0 milestone, not completion of
that milestone or stable releases. Advancing development does not close the
pending Kali validation gate. Test real dumpcap captures with multiple interfaces
and compare counts/timestamps against an independent reader before making broader
compatibility claims.
The maintainer has chosen to group VM testing into a later session. Local
developer checks continue to catch regressions; they are not labeled as Kali
acceptance. The same later session should cover permitted MSVC/MinGW PE samples.

The earlier 200-entry catalog is a planning backlog. It is not a shipped feature
count or an obligation to implement every proposed check.
