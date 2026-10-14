# Architecture

The CLI validates the command and limits. A file run acquires a complete bounded
snapshot in a private temporary directory, records its hash and source metadata,
then invokes shared collectors and one category module. A web run validates one
origin/directory scope and passes every request through a bounded curl runner.
Collectors append structured observations and evidence records to `Report`.
Serialization applies defensive text handling and best-effort redaction before
writing the JSON, evidence files and size-bounded Markdown brief.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument validation, category routing, output paths, exit semantics |
| `files.py` | File admission, snapshot, SHA-256, magic hints and strings |
| `runner.py` | Trusted tool lookup, argv-only execution, versions, timeout/output bounds |
| `binary.py` | ELF/static mitigation observations and bounded PE header parsing |
| `crypto.py` | Descriptive statistics, encoding derivation, literal public parameters, key containers |
| `forensics.py` | PNG, limited ZIP directory and classic PCAP parsers; ExifTool integration |
| `web.py` | HTTP(S) scope, redirects, metadata, HTML structure and optional probes |
| `report.py` | Common check/evidence contract, redaction, private files and Markdown budget |

There is intentionally no general-purpose plugin loader in this first release.
Collector interfaces can evolve before external plugins depend on them. JSON
Schema `schemas/report.schema.json` specifies the public envelope, with flexible
category data. No cloud provider SDK or Python runtime package is required.

## Observation versus conclusion

- An imported `gets` symbol is a lead; its presence does not establish reachability
  or a usable overflow. `fgets` is not matched as `gets`.
- `DT_NEEDED` is a declaration, not proof a particular library will be loaded.
- A GNU stack program header and RELRO/NOW indicators describe static properties.
  ASLR and per-function canary coverage are not established.
- A valid base64 decoding is a candidate interpretation. Entropy is descriptive,
  not a reliable cipher classifier.
- HTTP 200 is not an exposed-secret verdict. Git/environment checks require
  recognizable content, compare a missing-path control and retain uncertainty.
- PNG CRCs and ZIP/PCAP structure checks are limited parser observations, not
  complete format conformance or malware detection.

## Dependency strategy

`file`, `readelf`, `openssl`, `curl` and `exiftool` are optional at application
startup. Each affected collector reports `unavailable` when its tool is absent.
`curl` is necessary for web collection; `readelf` for detailed ELF collection.
No fallback silently substitutes a weaker result. Tool version probes are cached
within the run. Missing ExifTool does not prevent built-in forensic parsing.

Tools are looked up in a fixed system PATH, not the challenge directory or the
inherited environment. Their output is collected through pipes. The runner
terminates the process group when a deadline/output cap is reached and records
the reason. This is a resource guard, not a security isolation boundary.

## Technical references

The implementation was checked against these primary references:

- [Python 3.11 subprocess](https://docs.python.org/3.11/library/subprocess.html)
- [GNU readelf](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [OpenSSL pkey](https://docs.openssl.org/3.5/man1/openssl-pkey/)
- [curl options and response handling](https://curl.se/docs/manpage.html)
- [curl error code meanings](https://curl.se/libcurl/c/libcurl-errors.html)
- [PNG Third Edition](https://www.w3.org/TR/png-3/)
- [Python zipfile](https://docs.python.org/3/library/zipfile.html)

Consult the installed tool versions and their manuals when a new platform differs
from the tested host. A reference to a specification does not mean this alpha
implements its complete validation requirements.
