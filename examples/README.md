# Harmless examples

## Crypto

`crypto-demo.txt` contains toy RSA public parameters and a base64-encoded
synthetic flag string. There is no real challenge secret or private key.

```bash
wired2ai triage examples/crypto-demo.txt --category crypto --out ./demo-run
```

`crypto-report/` is the actual report produced by installed wired2ai 0.2.0a3
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

`pcapng-report/` is the actual installed 0.2.0a3 report. The expected F002 result
is two packets, two interfaces, 138 captured packet bytes, no anomalies and no
decryption-secrets blocks. Five checks complete and three generic raw/native
collectors are deliberately skipped. F004 additionally observes two IPv4/UDP packets and numeric port pair 55000→4242.
Packet bodies and addresses are omitted.

`make_pcapng_demo.py` reproduces the input bytes without wired2ai imports,
third-party packages, live capture or network I/O:

```bash
python3 examples/make_pcapng_demo.py /tmp/wired2ai-demo.pcapng
sha256sum examples/pcapng-demo.pcapng /tmp/wired2ai-demo.pcapng
```

Choose a new output path; the generator refuses an existing file. See
[PCAPNG coverage](../docs/PCAPNG.md) for timestamp expectations and limits.

## PE

`pe-demo.bin` is a 3,105-byte synthetic PE32+ fixture for static inspection.
It declares two sections, two imports and three exports. Its certificate entry
contains the text `DEMO`, not a real signature; a 17-byte trailer follows it.
Do not execute the fixture. The generator and collector never load it or its DLLs.

```bash
wired2ai triage examples/pe-demo.bin --category re --out ./pe-demo-run
```

`pe-report/` is the actual installed 0.2.0a3 RE report: nine checks complete on
the documented host. Expected import names, ordinals, forwarded exports, byte
offsets and interpretation limits are listed in [PE coverage](../docs/PE.md).

Recreate the default 64-bit fixture or generate its 32-bit counterpart:

```bash
python3 examples/make_pe_demo.py /tmp/wired2ai-pe64.bin
python3 examples/make_pe_demo.py /tmp/wired2ai-pe32.bin --bits 32
sha256sum examples/pe-demo.bin /tmp/wired2ai-pe64.bin
```

Choose new output paths; existing files are refused. Source timestamps in the
reports describe the validation run and can differ after downloading the files.

These reports are documentation fixtures, not proof of solving unfamiliar CTFs.

## Packet headers

`packet-demo.pcap` is a 647-byte synthetic Ethernet capture with eight records.
It combines TCP, UDP, ICMPv6 and ARP headers with an IPv4 fragment, truncated
captured payload and unsupported EtherType. No live traffic is included.

```bash
wired2ai triage examples/packet-demo.pcap --out ./packet-demo-run
python3 examples/make_packet_demo.py /tmp/wired2ai-packets.pcap
```

`packet-report/` is the actual installed 0.2.0a3 report: four complete, three
skipped and one partial check. F004 is deliberately partial because three
packets require follow-up. Expected counts, offsets, export policy and
limitations are documented in [packet coverage](../docs/PACKETS.md).
