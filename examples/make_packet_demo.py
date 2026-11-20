"""Write a synthetic Ethernet PCAP for header triage; no traffic is sent.

Usage: python3 examples/make_packet_demo.py NEW_OUTPUT.pcap
No wired2ai imports or third-party packages. Existing paths are refused.
"""
import argparse
import struct
from pathlib import Path


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(payload, protocol=17, fragment=0):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, fragment, 64, protocol, 0,
                         bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(payload, protocol=17):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 64,
                       bytes.fromhex("20010db8000000000000000000000001"),
                       bytes.fromhex("20010db8000000000000000000000002")) + payload


def ethernet(payload, kind=0x0800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", kind) + payload


def udp(payload=b"SYNTHETIC_PAYLOAD_NOT_FOR_EXPORT", source=55000, dest=4242):
    return struct.pack("!HHHH", source, dest, 8 + len(payload), 0) + payload


def tcp(source=55001, dest=443, flags=2):
    # Zero transport checksum is intentional: these fixtures test header layouts.
    return struct.pack("!HHIIBBHHH", source, dest, 1, 0, 0x50, flags, 1024, 0, 0)


def capture_bytes():
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("020000000001c0000201000000000000c6336402")
    hop = bytes([6, 0]) + b"\0" * 6
    packets = [ethernet(ipv4(udp())), ethernet(ipv4(tcp(), 6)),
               ethernet(ipv6(hop + tcp(flags=0x12), 0), 0x86DD), ethernet(arp, 0x0806),
               ethernet(ipv4(udp(), fragment=0x2000)), ethernet(ipv4(udp()))[:-5],
               ethernet(b"UNSUPPORTED_BODY_PRIVATE", 0x88B5),
               ethernet(ipv6(bytes([128, 0, 0, 0]) + b"\0" * 4, 58), 0x86DD)]
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, packet in enumerate(packets):
        original = len(packet) + (5 if index == 5 else 0)
        records.append(struct.pack("<IIII", 1700000100 + index, 0, len(packet), original) + packet)
    return header + b"".join(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = capture_bytes()
    with args.output.open("xb") as stream:
        stream.write(data)
    print(f"Wrote {len(data)} synthetic bytes to {args.output}")


if __name__ == "__main__":
    main()
