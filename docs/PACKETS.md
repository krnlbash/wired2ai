# Packet header summaries in 0.2.0a3

F004 helps choose packets for manual inspection. It reports protocol counts,
numeric TCP/UDP port pairs, TCP flag counts and bounded packet details with
absolute snapshot offsets. It never opens a socket or invokes a packet analyzer.
F002 still describes the capture container; these are separate scopes.

```bash
wired2ai triage examples/packet-demo.pcap --category forensics --out ./runs/packet-demo
wired2ai triage examples/pcapng-demo.pcapng --out ./runs/pcapng-demo
```

No new switch or runtime dependency is required. Automatic category selection
recognizes either signature, including when the extension is `.bin`.

## Header coverage

| Encapsulation or header | Observations and limits |
| --- | --- |
| Ethernet, link type 1 | EtherType and up to two 802.1Q/802.1ad tags; no MAC addresses or VLAN identifiers |
| Linux SLL / SLL2, link types 113 / 276 | Fixed cooked header and its protocol field; no addresses or OS-interface name resolution |
| Raw IP / IPv4 / IPv6, link types 101 / 228 / 229 | Version checked before the corresponding IP parser |
| IPv4 | Header/total lengths, protocol, fragmentation fields; IP options are bounded but uninterpreted |
| IPv6 | Fixed header, declared length and up to eight hop-by-hop, routing, destination or fragment headers; option bodies/order semantics are not validated |
| TCP | Header length, numeric ports and eight flag bits; options bounded but uninterpreted |
| UDP | Length and numeric ports; additional bytes within IP are not assumed to be UDP application data |
| ICMP / ICMPv6 | Common four-byte prefix and numeric type/code only; message bodies are uninterpreted |
| ARP | Declared address lengths, hardware/protocol types and operation; address bytes are omitted |

First and later IPv4/IPv6 fragments stop before transport interpretation. There
is no reassembly. An IPv6 atomic fragment (zero offset, no more-fragments bit)
can continue; repeated fragment headers are rejected for that packet.
ESP, AH, other IPv6 extensions, IPv6 jumbograms, tunneled IP, LLC/SNAP, radiotap
and other link types remain unsupported. An unknown value is never guessed from
its body. There is no TCP stream, connection-state or application parser: UDP
port 53 alone is not evidence of DNS, and TCP port 443 is not evidence of TLS.

No checksums or FCS are verified. Classic PCAP separates the lower 16-bit link
type from the additional flags, records a declared FCS length, and rejects
nonzero reserved bits. FCS bytes/options are not independently interpreted by
F004. This is header triage, not proof that a receiver would accept the packet.

## Counts, bounds and status

F002 passes each admitted packet to F004 while scanning. Classic PCAP uses
logical section/interface index 0; PCAPNG preserves section-local interface IDs. F004 is not restricted
to F002's 32-record display sample. If the container later fails, F004 discards
its accumulated results and reports `skipped`; F002 retains the actual failure.
A packet-level problem is retained with its record index and absolute offset
without discarding other packet observations.

| Bound | Maximum | Behavior |
| --- | --- | --- |
| Input snapshot | 32 MiB default; configurable to 256 MiB | Whole file required; oversized input rejected |
| Packet records inspected by F004 | First 10,000 admitted records | F002 continues within its own bounds; subsequent packets not classified |
| Header byte range | First 2,048 bytes from each packet start | Larger header chains produce `limited` observations |
| VLAN tags / IPv6 extensions | 2 / 8 per packet | Stop before the next header |
| Packet details / issue details | First 32 / first 16 | Counts continue over inspected packets |
| Port pairs / link types | First 64 / first 32 distinct keys | Existing keys keep counting; unretained occurrences counted separately |

Port pairs are directional `(transport, source port, destination port)` groups
across the inspected capture prefix. They are **not conversations**, because
addresses are omitted; repeated packets and packets on different interfaces can
share a pair. Counts are capture records, not unique transmitted packets.
Omitted pair counts are packet occurrences, not a count of unique omitted pairs.

`outcome_counts` partitions inspected packets into `decoded`, `truncated`,
`malformed`, `unsupported`, `fragmented` and `limited`. A packet with complete
supported headers but missing captured IP payload has `headers_decoded: true`
and outcome `truncated`; its observed ports remain useful. Header counts and
outcome counts therefore answer different questions. Error reasons contain fixed
parser descriptions rather than target-derived bytes.

F004 is `complete` when all inspected records fit its header subset and no
scan/detail/table limits omit results. Empty supported captures are `no_match`.
An all-unsupported inspected set is `unsupported` unless the packet/container
scan stopped, when it is `partial`. Mixed coverage, packet issues or omitted
details yield `partial`, with counts/reasons in notes. Partial packet results do
not by themselves fail `--strict`; inspect F002 and F004 together.

The JSON envelope remains schema 0.1. F004 data uses `format: packet_summary`
and `summary_version: 1`; its field contract is separately described by
[packet-summary.schema.json](../schemas/packet-summary.schema.json). Packet detail
objects disallow undeclared fields. The schema describes the F004 data object,
not an entire report. Markdown preserves a compact count/limitation summary even
when the detailed check exceeds its display budget.

## Export policy

Both recognized classic PCAP and PCAPNG suppress generic raw/header/string,
native metadata and crypto previews across category overrides, including when
the capture parser fails. This extends the PCAPNG policy from 0.2.0a1 to classic
PCAP. There is no raw-content export switch.

F004 exports numeric ports, protocol fields, lengths, flags and offsets. Packet
payloads, MAC/IP addresses, names, text options and secret values are omitted.
Source filenames, hashes, timestamps and numeric metadata can still be sensitive;
this policy does not anonymize a report or defeat information deliberately encoded
in numeric fields. Damaged/missing capture signatures fall outside this gate.
Review exports before sharing, and retain original evidence separately.

## Reproducible example

`packet-demo.pcap` is a 647-byte synthetic Ethernet capture with eight records.
It contains no live traffic. Expected F002: eight records, no structural anomalies.
Expected F004:

- Five `decoded`, one `fragmented`, one `truncated`, one `unsupported` record.
- Network headers: IPv4 = 4, IPv6 = 2, ARP = 1.
- Transport headers: UDP = 2, TCP = 2, ICMPv6 = 1; six records have decoded supported headers.
- TCP flags: SYN = 2, ACK = 1. Packet issue record indices: 4, 5, 6 (zero based).
- Overall F004 status `partial`; four complete checks, three skipped, one partial.

Transport checksums are intentionally zero; no verification is claimed. The
fixture is for parser behavior, not valid network replay. Its SHA-256 is
`752a05461e7613f2605a2d247a0dca613b3209707d53487d660d361b50e67524`.
Recreate it at a new path:

```bash
python3 examples/make_packet_demo.py /tmp/wired2ai-packets.pcap
sha256sum examples/packet-demo.pcap /tmp/wired2ai-packets.pcap
```

The earlier PCAPNG example adds F004: two IPv4/UDP packets, port pair 55000→4242,
no packet issues, five complete checks and three skipped checks. Its input bytes
and F002 counts/timestamps are unchanged.

## References and pending validation

- [IPv4, RFC 791](https://www.rfc-editor.org/rfc/rfc791.html)
- [IPv6, RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html)
- [TCP, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html)
- [UDP, RFC 768](https://www.rfc-editor.org/rfc/rfc768.html)
- [libpcap cooked header definitions](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h)
- [Classic PCAP draft -07](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap-07)
  (versioned Internet-Draft; not a final RFC)

Local tests exercise literal header bytes, deterministic fixtures, malformed
bounds, both container byte orders, packet block forms and export omission.
Wireshark/tcpdump comparison and real-capture manual Kali testing remain pending.
See the version-specific [validation record](VALIDATION.md). No broad protocol
conformance, malicious-capture robustness or performance claim follows from the
synthetic test suite.
