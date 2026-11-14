# Harmless examples

## Crypto

`crypto-demo.txt` contains toy RSA public parameters and a base64-encoded
synthetic flag string. There is no real challenge secret or private key.

```bash
wired2ai triage examples/crypto-demo.txt --category crypto --out ./demo-run
```

`crypto-report/` is the actual report produced by installed wired2ai 0.2.0a1
during validation on the documented Ubuntu host. Its source timestamps and tool
versions describe that one run.
Your timestamps may differ after downloading/extracting the example. The input
hash and deterministic content observations should agree.

## PCAPNG

`pcapng-demo.pcapng` is a 288-byte synthetic capture with one section, two
interfaces and two packet records. The interfaces use different timestamp
resolutions. It contains no real network traffic or keys.

```bash
wired2ai triage examples/pcapng-demo.pcapng --category forensics --out ./pcapng-demo-run
```

`pcapng-report/` is the actual installed 0.2.0a1 report. The expected F002 result
is two packets, two interfaces, 138 captured packet bytes, no anomalies and no
decryption-secrets blocks. Four checks complete and three generic raw/native
collectors are deliberately skipped. Only numeric capture metadata is exported.

`make_pcapng_demo.py` reproduces the input bytes without wired2ai imports,
third-party packages, live capture or network I/O:

```bash
python3 examples/make_pcapng_demo.py /tmp/wired2ai-demo.pcapng
sha256sum examples/pcapng-demo.pcapng /tmp/wired2ai-demo.pcapng
```

Choose a new output path; the generator refuses an existing file. See
[PCAPNG coverage](../docs/PCAPNG.md) for timestamp expectations and limits.

These reports are documentation fixtures, not proof of solving unfamiliar CTFs.
