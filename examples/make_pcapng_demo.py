"""Write a deterministic, synthetic capture; never capture or send traffic.

Usage: python3 examples/make_pcapng_demo.py NEW_OUTPUT.pcapng
Existing files are refused. No wired2ai imports or third-party packages are used.
"""

import argparse
import struct
from pathlib import Path


def padded(data):
    return data + b"\0" * (-len(data) % 4)


def block(kind, body):
    size = len(body) + 12
    assert size % 4 == 0
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def option(code, value):
    return struct.pack("<HH", code, len(value)) + padded(value)


def ethernet_packet(message):
    # Synthetic Ethernet / IPv4 / UDP. Addresses are documentation examples.
    udp = struct.pack("!HHHH", 55000, 4242, 8 + len(message), 0) + message
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", (~checksum) & 0xFFFF) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800") + ip + udp
    return ethernet.ljust(60, b"\0")


def capture_bytes():
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    # Interface 0 has default microseconds. Interface 1 has nanoseconds.
    first_idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    second_idb = block(1, struct.pack("<HHI", 1, 0, 65535) + option(9, b"\x09") + option(0, b""))
    packets = []
    for identifier, ticks in ((0, 1700000000123456), (1, 1700000001123456789)):
        packet = ethernet_packet(f"wired2ai synthetic packet {identifier + 1}".encode("ascii"))
        fields = struct.pack("<IIIII", identifier, ticks >> 32, ticks & 0xFFFFFFFF, len(packet), len(packet))
        packets.append(block(6, fields + padded(packet)))
    return shb + first_idb + second_idb + b"".join(packets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New .pcapng path; parent directory must exist")
    args = parser.parse_args()
    data = capture_bytes()
    with args.output.open("xb") as stream:
        stream.write(data)
    print(f"Wrote {len(data)} synthetic bytes to {args.output}")


if __name__ == "__main__":
    main()
