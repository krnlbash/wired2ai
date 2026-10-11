# Roadmap

Ship improvements when a real fixture demonstrates the need. Version numbers
represent coherent capabilities, not a schedule for generating GitHub activity.

| Milestone | Deliverable | Release gate |
| --- | --- | --- |
| 0.1.0 alpha | Five small category modules, local reports, bounds and provenance | Local regression suite, usable package and honest coverage documentation |
| 0.1.0 stable / 0.1.x | Kali validation, parser compatibility fixes, sharper failure reporting | Reproduced installation on a clean Kali VM, recorded doctor output, no unresolved critical regression |
| 0.2.0 | Deeper forensics/RE: PCAPNG, selected packet dissection, improved PE detail | Bounded malformed-input fixtures and useful evidence beyond the alpha |
| 0.3.0 | Better web/crypto: explicit custom CA support, stronger soft-404 handling, richer crypto formats | Negative controls, no secret-export regression, reproducible examples |
| 0.4.0 | Controlled derived artifacts/extraction, report reuse and improved context selection | Path/link/bomb limits; provenance for every derived artifact; evaluated report usefulness |
| 1.0.0 | Stable schema/collector interfaces and published support matrix | Independent use, compatibility policy and measured time/accuracy results |

## Next concrete issues

1. Run the alpha on a clean Kali VM, including ExifTool. Record package versions,
   test result and CLI outputs in `docs/VALIDATION.md`; fix differences first.
2. Add the first false-positive or missed-observation regression from a real,
   redistributable CTF artifact. Include its expected evidence, not only a flag.
3. Evaluate 10–20 permitted fixtures against manual triage: collection time,
   useful observations, misleading observations and report size. If using an
   LLM, compare the same model/settings with and without the report; do not
   claim reduced hallucination without measurement.
4. Tighten redaction and schema contracts before expanding collectors.
5. Add one high-value forensics or RE collector per reviewed change.

The earlier 200-entry catalog is a planning backlog. It is not a shipped feature
count or an obligation to implement every proposed check.
