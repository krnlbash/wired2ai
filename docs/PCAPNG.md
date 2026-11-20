# PCAPNG triage in 0.2.0a1

The first forensics expansion turns supported PCAPNG structure into bounded
evidence. It is useful for establishing what a capture contains before opening
it in a packet analyzer: sections, interfaces, supported packet counts, capture
lengths, timestamps, malformed structure and embedded decryption-secrets blocks.
This F002 scope does not identify protocols, conversations or vulnerabilities.
Starting in 0.2.0a3, a separate F004 [packet summary](PACKETS.md) adds a bounded
header subset. No packet bodies, addresses or names are exported.

## Run the included example

```bash
.venv/bin/wired2ai triage examples/pcapng-demo.pcapng --out ./runs/pcapng-demo
```

Automatic category selection recognizes the signature. An explicit
`--category forensics` works too. No extra tool or Python package is required
for this format. As with other runs, the output directory must be new.

The example is generated without capturing or sending traffic. Expect one
section, two Ethernet interfaces and two Enhanced Packet Blocks, one packet per
interface. Their timestamps are `1700000000 + 123456/1000000` and
`1700000001 + 123456789/1000000000` seconds since the Unix epoch. Each packet
contains 69 captured bytes; F002 should report 138 captured bytes, 288 inspected
file bytes, no anomalies and no decryption-secrets blocks. These are synthetic
values, not observations from a real network.

Recreate the file at a new path and compare its SHA-256 with the included file:

```bash
python3 examples/make_pcapng_demo.py /tmp/wired2ai-demo.pcapng
sha256sum examples/pcapng-demo.pcapng /tmp/wired2ai-demo.pcapng
```

The generator refuses an existing destination. The committed
`examples/pcapng-report/` is an actual run; source timestamps differ after
extraction, while the complete-file hash and structural observations should agree.

## Implemented scope

| Input structure | Exported observations |
| --- | --- |
| Section Header Block, version 1.0 | Offset, byte order, declared section length; sections may mix byte orders |
| Interface Description Block | Section-local ID, numeric link type, snaplen, numeric timestamp settings, observed packet/byte totals |
| Enhanced or obsolete Packet Block | Section/interface, block and payload offsets, captured/original lengths, exact timestamp |
| Simple Packet Block | Lengths and offsets; interface 0; timestamp is null |
| Decryption Secrets Block | Count, type code, declared byte length and offset; no value |
| Other blocks, including name resolution, interface statistics and custom blocks | Framing checked, count and bounded type/offset details; body not interpreted |

Packet data and text options are not copied into reports. Generic header/string
and native metadata collectors are suppressed for recognized PCAPNG even when
the user overrides the category. Crypto payload previews are also suppressed.
File names, hashes, source times and numeric metadata are still exported; review
them before sharing. This is an omission policy, not proof that all possible
sensitive information has been removed. See [security model](../SECURITY.md).

F002 refers to the complete snapshot evidence, E001. Its offsets are absolute
byte offsets in that snapshot. The JSON envelope remains schema version 0.1;
this is an additive F002 data shape, identified by `data.format: "pcapng"`.

## Bounds and status

| Bound | Maximum | On reaching it |
| --- | --- | --- |
| Complete input snapshot | 32 MiB by default; configurable up to 256 MiB | Larger inputs rejected before parsing |
| Blocks inspected | 100,000 | Stop at a block boundary; counts beyond the prefix unknown |
| Sections / total interfaces | 64 / 256 | Stop before the next section/interface |
| Options | 256 per supported block; 100,000 in total | Stop before counting the current block |
| Packet detail records retained | First 32 | Continue aggregate counts within scan limits |
| Anomalies retained | First 40 | Continue the observed anomaly count |
| Opaque / secrets block details retained | First 16 of each | Continue aggregate counts within scan limits |

`partial` notes give kept/observed counts or the stop reason and inspected bytes.
Exactly reaching a cap is not partial if nothing was omitted. A full scan can
still have capped detail samples. A complete metadata scan does not validate
opaque bodies or packet protocols. Deliberately uninterpreted bodies are called
out in notes even when the status is `complete`.

Invalid supported structure is `failed` with an offset-bearing error, without
attempting resynchronization or returning a trusted packet count from a malformed
file. A section version other than 1.0 is `unsupported`. Consistent framing with
captured lengths exceeding snaplen/original lengths produces anomaly observations;
those observations alone do not make collection partial or prove an exploit.

The parser checks lengths before reading fields, including the duplicated block
length, payload padding, known section boundaries and supported option areas.
Duplicate or wrongly sized timestamp options fail rather than choosing a value.
A clean option-list end without an end marker is accepted. Other option semantics
are not validated. Unknown link types remain numeric. F002 does not decode packets; F004 records
unsupported link/header types explicitly.

Timestamps retain integer ticks, whole seconds, and an exact fractional numerator
and denominator. Decimal and binary resolutions and signed offsets are applied
without floats. First/last timestamped packets mean file order; clocks may be
unsynchronized or timestamps out of order. No duration or clock accuracy is inferred.

## Validation and remaining work

Regression fixtures cover endian changes, interface resets, timestamp arithmetic,
Simple/obsolete packets, truncation, malformed options, framing, bounds, retained
counts and secret omission in exported files. The complete installed package is
tested separately; results and platform gaps are in [VALIDATION.md](VALIDATION.md).

The development host has no Wireshark/capinfos/dumpcap installation. An independent
reader comparison and real-capture Kali acceptance are still pending. The earlier
Kali test of a real PCAPNG file exercised the old unsupported status, not this parser.

Layout reference: [PCAPNG draft-ietf-opsawg-pcapng-06](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-06.html),
a versioned IETF Internet-Draft (work in progress). This implementation covers a
subset and is not a full conformance validator.
