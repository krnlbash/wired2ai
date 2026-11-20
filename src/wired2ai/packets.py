"""Bounded packet-header observations; never export addresses or payload bytes.

Offsets refer to the original snapshot. Protocol labels describe header fields,
not application detection, checksum verification, reassembly or a network flow.
"""
from __future__ import annotations

import struct
from collections import Counter

MAX_PACKETS = 10000
MAX_HEADER_BYTES = 2048
MAX_IPV6_EXTENSIONS = 8
MAX_VLAN_TAGS = 2
PACKET_SAMPLE = 32
ISSUE_SAMPLE = 16
PORT_PAIRS = 64
LINK_TYPES = 32
LINK_NAMES = {1: "Ethernet", 101: "raw IP", 113: "Linux SLL", 228: "raw IPv4",
              229: "raw IPv6", 276: "Linux SLL2"}
TRANSPORT_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 59: "no next header"}
OUTCOMES = ("decoded", "truncated", "malformed", "unsupported", "fragmented", "limited")


class _Stop(Exception):
    def __init__(self, outcome: str, reason: str):
        self.outcome, self.reason = outcome, reason


class _Header:
    def __init__(self, packet: memoryview, origin: int):
        self.packet, self.origin = packet, origin
        self.result = {"network": None, "transport": None, "headers_decoded": False,
                       "ip_capture_truncated": False}

    def need(self, start: int, size: int, end: int | None = None) -> None:
        if end is not None and start + size > end:
            raise _Stop("malformed", "Header exceeds the enclosing protocol's declared length")
        if start + size > len(self.packet):
            raise _Stop("truncated", "Captured bytes end before the required header")
        if start + size > MAX_HEADER_BYTES:
            raise _Stop("limited", f"Header inspection exceeds {MAX_HEADER_BYTES} bytes from packet start")

    def u16(self, offset: int) -> int:
        return struct.unpack_from("!H", self.packet, offset)[0]

    def transport(self, start: int, end: int, protocol: int, version: int) -> None:
        r = self.result
        r["ip_protocol"] = protocol
        r["transport_offset"] = self.origin + start
        if protocol == 59 and version == 6:
            r["transport"] = "no next header"
        elif protocol == 6:
            self.need(start, 20, end)
            size = (self.packet[start + 12] >> 4) * 4
            if size < 20:
                raise _Stop("malformed", "TCP data offset is smaller than its fixed header")
            self.need(start, size, end)
            r.update(transport="TCP", source_port=self.u16(start), destination_port=self.u16(start + 2),
                     tcp_flags=self.packet[start + 13], transport_header_bytes=size)
        elif protocol == 17:
            self.need(start, 8, end)
            size = self.u16(start + 4)
            if size < 8 or size > end - start:
                raise _Stop("malformed", "UDP length is outside the enclosing IP datagram")
            r.update(transport="UDP", source_port=self.u16(start), destination_port=self.u16(start + 2),
                     udp_declared_bytes=size, transport_header_bytes=8)
        elif (protocol, version) in ((1, 4), (58, 6)):
            # Only the common four-byte prefix is interpreted, not message bodies.
            self.need(start, 4, end)
            r.update(transport=TRANSPORT_NAMES[protocol], icmp_type=self.packet[start],
                     icmp_code=self.packet[start + 1], transport_header_bytes=4)
        else:
            raise _Stop("unsupported", "IP protocol or extension is outside the supported header subset")
        r["headers_decoded"] = True

    def ipv4(self, start: int) -> None:
        self.need(start, 20)
        if self.packet[start] >> 4 != 4:
            raise _Stop("malformed", "Expected IPv4 version at the network header")
        size = (self.packet[start] & 15) * 4
        total = self.u16(start + 2)
        if size < 20 or total < size:
            raise _Stop("malformed", "Invalid IPv4 header or total length")
        self.need(start, size)
        end = start + total
        fragment = self.u16(start + 6)
        r = self.result
        r.update(network="IPv4", network_offset=self.origin + start, ip_declared_bytes=total,
                 ip_protocol=self.packet[start + 9], ip_capture_truncated=end > len(self.packet),
                 fragment_offset_bytes=(fragment & 0x1FFF) * 8, more_fragments=bool(fragment & 0x2000))
        if r["fragment_offset_bytes"] or r["more_fragments"]:
            raise _Stop("fragmented", "IPv4 fragment: transport decoding requires reassembly and is deferred")
        self.transport(start + size, end, r["ip_protocol"], 4)

    def ipv6(self, start: int) -> None:
        self.need(start, 40)
        if self.packet[start] >> 4 != 6:
            raise _Stop("malformed", "Expected IPv6 version at the network header")
        length, protocol = self.u16(start + 4), self.packet[start + 6]
        end, cursor = start + 40 + length, start + 40
        r = self.result
        r.update(network="IPv6", network_offset=self.origin + start, ip_declared_bytes=40 + length,
                 ip_capture_truncated=end > len(self.packet), ipv6_extensions=[])
        if length == 0 and protocol != 59:
            raise _Stop("unsupported", "Zero IPv6 payload length: jumbogram interpretation is deferred")
        while protocol in (0, 43, 44, 60):
            if len(r["ipv6_extensions"]) >= MAX_IPV6_EXTENSIONS:
                raise _Stop("limited", f"IPv6 extension limit {MAX_IPV6_EXTENSIONS} reached")
            self.need(cursor, 8, end)
            next_protocol = self.packet[cursor]
            size = 8 if protocol == 44 else (self.packet[cursor + 1] + 1) * 8
            self.need(cursor, size, end)
            r["ipv6_extensions"].append({"type": protocol, "offset": self.origin + cursor, "bytes": size})
            if protocol == 44:
                if r.get("fragment_header"):
                    raise _Stop("malformed", "Repeated IPv6 fragment header")
                fragment = self.u16(cursor + 2)
                r.update(fragment_header=True, fragment_offset_bytes=fragment & 0xFFF8,
                         more_fragments=bool(fragment & 1), ip_protocol=next_protocol)
                if r["fragment_offset_bytes"] or r["more_fragments"]:
                    raise _Stop("fragmented", "IPv6 fragment: transport decoding requires reassembly and is deferred")
                r["atomic_fragment"] = True
            cursor, protocol = cursor + size, next_protocol
        self.transport(cursor, end, protocol, 6)

    def decode(self, link_type: int) -> dict:
        r, start = self.result, 0
        try:
            if link_type == 1:
                self.need(0, 14)
                ether_type, start = self.u16(12), 14
            elif link_type in (113, 276):
                size = 16 if link_type == 113 else 20
                self.need(0, size)
                ether_type, start = self.u16(14 if link_type == 113 else 0), size
            elif link_type in (101, 228, 229):
                self.need(0, 1)
                version = self.packet[0] >> 4
                if link_type == 101 and version not in (4, 6):
                    raise _Stop("unsupported", "Raw-IP version is outside the supported subset")
                ether_type = 0x0800 if link_type == 228 or (link_type == 101 and version == 4) else 0x86DD
            else:
                raise _Stop("unsupported", "Link type is outside the supported subset")
            tags = 0
            if link_type in (1, 113, 276):
                while ether_type in (0x8100, 0x88A8):
                    if tags >= MAX_VLAN_TAGS:
                        raise _Stop("limited", f"VLAN tag limit {MAX_VLAN_TAGS} reached")
                    self.need(start, 4)
                    ether_type, start, tags = self.u16(start + 2), start + 4, tags + 1
                r.update(ether_type=ether_type, vlan_tags=tags)
            if ether_type == 0x0800:
                self.ipv4(start)
            elif ether_type == 0x86DD:
                self.ipv6(start)
            elif ether_type == 0x0806:
                self.need(start, 8)
                hlen, plen = self.packet[start + 4], self.packet[start + 5]
                self.need(start, 8 + 2 * (hlen + plen))
                r.update(network="ARP", network_offset=self.origin + start, arp_operation=self.u16(start + 6),
                         arp_hardware_type=self.u16(start), arp_protocol_type=self.u16(start + 2),
                         arp_hardware_bytes=hlen, arp_protocol_bytes=plen, headers_decoded=True)
            else:
                raise _Stop("unsupported", "EtherType or IEEE 802.3 payload is outside the supported subset")
            if r["ip_capture_truncated"]:
                raise _Stop("truncated", "IP headers decoded, but the declared datagram exceeds captured bytes")
            r.update(outcome="decoded", reason=None)
        except _Stop as exc:
            r.update(outcome=exc.outcome, reason=exc.reason)
        return r


class PacketSummary:
    """A callback for admitted packet records; discard it if container parsing fails."""
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.seen = self.inspected = self.captured = self.decoded = self.ip_truncated = 0
        self.outcomes = Counter({key: 0 for key in OUTCOMES})
        self.networks, self.transports, self.flags = Counter(), Counter(), Counter()
        self.links, self.ports = {}, {}
        self.link_omitted = self.port_omitted = 0
        self.packets, self.issues = [], []
        self.issue_count = 0

    def observe(self, record: dict, link_type: int) -> None:
        self.seen += 1
        if self.inspected >= MAX_PACKETS:
            return
        self.inspected += 1
        self.captured += record["captured_bytes"]
        origin = record["payload_offset"]
        packet = self.data[origin:origin + record["captured_bytes"]]
        detail = {key: record[key] for key in ("record_index", "offset", "payload_offset", "captured_bytes",
                                               "original_bytes", "section_index", "interface_id")}
        detail["link_type"] = link_type
        if record["captured_bytes"] > record["original_bytes"]:
            result = {"outcome": "malformed", "reason": "Captured length exceeds original length",
                      "network": None, "transport": None, "headers_decoded": False, "ip_capture_truncated": False}
        else:
            result = _Header(packet, origin).decode(link_type)
        detail.update(result)
        self.outcomes[result["outcome"]] += 1
        self.decoded += int(result["headers_decoded"])
        self.ip_truncated += int(result["ip_capture_truncated"])
        for field, counts in (("network", self.networks), ("transport", self.transports)):
            if result[field] is not None:
                counts[result[field]] += 1
        if "tcp_flags" in result:
            for bit, name in enumerate(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")):
                if result["tcp_flags"] & (1 << bit):
                    self.flags[name] += 1
        if link_type in self.links or len(self.links) < LINK_TYPES:
            self.links[link_type] = self.links.get(link_type, 0) + 1
        else:
            self.link_omitted += 1
        if "source_port" in result:
            key = (result["transport"], result["source_port"], result["destination_port"])
            if key in self.ports or len(self.ports) < PORT_PAIRS:
                self.ports[key] = self.ports.get(key, 0) + 1
            else:
                self.port_omitted += 1
        if len(self.packets) < PACKET_SAMPLE:
            self.packets.append(detail)
        if result["outcome"] != "decoded":
            self.issue_count += 1
            if len(self.issues) < ISSUE_SAMPLE:
                self.issues.append({key: detail[key] for key in ("record_index", "offset", "payload_offset", "outcome", "reason")})

    def finish(self, structure: dict) -> tuple[str, dict, list[str]]:
        container_limited = structure.get("scan_limited", False)
        notes = []
        if self.seen > self.inspected:
            notes.append(f"Inspected headers in {self.inspected} of {self.seen} admitted packet records; packet scan limit {MAX_PACKETS}.")
        if container_limited:
            notes.append("Container scanning stopped early; packet counts beyond its inspected prefix are unknown (see F002).")
        if self.inspected > len(self.packets):
            notes.append(f"Kept {len(self.packets)} of {self.inspected} inspected packet details; aggregate counts cover the inspected prefix.")
        if self.issue_count:
            notes.append(f"{self.issue_count} inspected packets were not fully decoded within the supported header subset; see outcome counts and issue samples.")
        if self.issue_count > len(self.issues):
            notes.append(f"Kept {len(self.issues)} of {self.issue_count} packet issue details.")
        if self.port_omitted:
            notes.append(f"Port-pair table retained the first {PORT_PAIRS} pairs; {self.port_omitted} packet occurrences used unretained pairs. Unique omitted pair count is unknown.")
        if self.link_omitted:
            notes.append(f"Link-type table retained the first {LINK_TYPES} types; {self.link_omitted} packet occurrences used unretained types.")
        limited = self.seen > self.inspected or container_limited
        status = "partial" if notes else ("complete" if self.inspected else "no_match")
        if self.inspected and self.outcomes["unsupported"] == self.inspected and not limited:
            status = "unsupported"
        notes.append("Header declarations only: no checksum verification, option-body validation, reassembly, application detection or flow inference. Ports do not establish a service.")
        result = {"format": "packet_summary", "summary_version": 1, "capture_format": structure["format"],
                  "packet_records_available": self.seen, "packets_inspected": self.inspected,
                  "headers_decoded": self.decoded, "captured_bytes_in_inspected_packets": self.captured,
                  "packets_with_ip_capture_truncation": self.ip_truncated,
                  "container_scan_limited": container_limited, "scan_limited": limited,
                  "selection_truncated": self.inspected > len(self.packets) or self.issue_count > len(self.issues)
                                          or bool(self.port_omitted or self.link_omitted),
                  "outcome_counts": dict(self.outcomes), "network_counts": dict(self.networks),
                  "transport_counts": dict(self.transports), "tcp_flag_counts": dict(self.flags),
                  "link_types": [{"link_type": key, "name": LINK_NAMES.get(key, "unsupported"), "packets": value}
                                 for key, value in self.links.items()],
                  "link_type_occurrences_omitted": self.link_omitted,
                  "port_pairs": [{"transport": key[0], "source_port": key[1], "destination_port": key[2], "packets": value}
                                 for key, value in self.ports.items()],
                  "port_pair_occurrences_omitted": self.port_omitted,
                  "packet_sample": self.packets, "packet_issues": self.issues, "packet_issues_seen": self.issue_count,
                  "limits": {"packets": MAX_PACKETS, "header_bytes_per_packet": MAX_HEADER_BYTES,
                             "ipv6_extensions": MAX_IPV6_EXTENSIONS, "vlan_tags": MAX_VLAN_TAGS,
                             "packet_sample": PACKET_SAMPLE, "issue_sample": ISSUE_SAMPLE,
                             "port_pairs": PORT_PAIRS, "link_types": LINK_TYPES},
                  "export_policy": {"payloads": False, "addresses": False, "names": False, "numeric_ports": True},
                  "scope": "Fixed IP/TCP/UDP/ICMP prefixes, ARP framing, bounded VLAN/IPv6 extension framing. "
                           "No packet bytes, MAC/IP addresses, option text, DNS names, secrets or application bodies exported. "
                           "No replay, resolution, decryption, reassembly, checksum or connection-state validation."}
        return status, result, notes
