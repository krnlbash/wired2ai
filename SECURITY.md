# Security model

Challenge artifacts and HTTP responses are hostile input. Native tools are
trusted executables installed by the host administrator; malformed input can
still exploit bugs in those tools. The same applies to Python and its parsers.

## Implemented boundaries

- File input must be a regular file. The final path component cannot be a symlink.
  Parent-directory symlinks are resolved by the OS; this is not a filesystem jail.
- A complete, size-limited snapshot is hashed and analyzed. Normal metadata
  changes during the read are rejected; this does not defeat a malicious writer
  that can manipulate the underlying filesystem or guarantee forensic immutability.
- Native subprocesses receive argv arrays, closed stdin, a clean environment,
  a private working directory, time limits and combined output caps. A fixed
  system PATH is used. No challenge executable is passed as the executable.
- The runner kills its process group on completion or limit failure. An exploited
  tool could deliberately escape that group. Memory, CPU, filesystem and network
  access are not restricted by a kernel sandbox or cgroup.
- No target execution, `ldd`, archive extraction, decompilation plugins, shell
  command strings, Python `eval`, authentication flow or automatic LLM upload.
- Web collection allows HTTP(S) only, verifies TLS using curl's normal trust
  store, disables curl configuration/proxy inheritance and enforces origin and
  directory checks before each request. It does not maintain a cookie session.
- Private network targets are allowed for local CTFs. DNS is not pinned between
  requests. Do not expose this CLI as an untrusted multi-user web service.
- The Markdown export uses dynamic fences and visible control-character escapes.
  This reduces formatting ambiguity; it does not neutralize model prompt injection.

## Data handling

Report files are private to the current account by default. Original artifacts
are not included in reports. Temporary copies are deleted on normal exit; forceful
termination or a crash can leave temporary files. Deletion is not secure erasure.
Run in a disposable encrypted VM if the artifacts require that level of handling.

PEM private-key markers suppress generic byte/string previews. OpenSSL exports
only public components of unencrypted keys. Encrypted PEM containers are skipped.
Embedded or encoded secrets can evade these markers. Common assignments, token
forms, authorization values and private PEM blocks are masked best effort.
Environment probe values are omitted wholesale. Source paths, binary strings,
EXIF data and other metadata can still contain sensitive information.

Evidence records are sanitized and bounded; they are not a forensic evidence
archive. Keep original artifacts separately. Reading a source can affect atime.

## Reporting a problem

Report reproducible failures with a harmless minimized fixture and the output
of `wired2ai doctor`. Do not post real credentials, private challenge data or
working secrets. Once the GitHub repository exists, enable private vulnerability
reporting before inviting sensitive reports. No private reporting endpoint has
been configured in this local release.
