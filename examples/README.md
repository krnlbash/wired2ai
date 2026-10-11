# Harmless example

`crypto-demo.txt` contains toy RSA public parameters and a base64-encoded
synthetic flag string. There is no real challenge secret or private key.

```bash
wired2ai triage examples/crypto-demo.txt --category crypto --out ./demo-run
```

`crypto-report/` is the actual report produced during validation on the documented
Ubuntu host. Its source timestamps and tool versions describe that one run.
Your timestamps may differ after downloading/extracting the example. The input
hash and deterministic content observations should agree.

This report is a documentation fixture, not proof of solving an unfamiliar CTF.
