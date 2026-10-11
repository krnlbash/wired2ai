# Contributing

Keep changes small enough to review and reproduce. A useful collector needs a
clear question, bounded inputs, traceable observations, explicit failures and
one meaningful regression fixture. Adding another command to a list is not
sufficient if its output cannot be interpreted reliably.

1. Open an issue describing the missing observation and a non-sensitive example.
2. Add a bounded collector or improve an existing one. Use `Report.add` and the
   shared runner. Do not use shell execution or run supplied programs.
3. Add tests for the actual failure risk, including a malformed or ambiguous case.
4. Update the capability table, limitations and changelog.
5. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` and include the
   result and relevant `doctor` output in the pull request.

Do not commit challenge binaries, real keys, generated case reports, credentials,
virtual environments or downloaded toolchains. Small synthetic fixtures and
redacted examples are appropriate. Avoid network-dependent tests: use local
fixture servers. Keep public issue descriptions free of private artifacts.

Never change `complete` to mean "vulnerable". Preserve evidence IDs and disclose
heuristic inference. Changes to the JSON contract require a schema-version review.
