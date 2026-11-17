"""Generate a deterministic PE metadata fixture; do not execute the result.

Usage: python3 examples/make_pe_demo.py NEW_OUTPUT.bin [--bits 32|64]
No compiler, network access, wired2ai import or third-party package is needed.
The certificate entry is deliberately synthetic, not a valid signature.
"""

import argparse
import struct
from pathlib import Path


def image_bytes(bits=64):
    if bits not in (32, 64):
        raise ValueError("bits must be 32 or 64")
    data = bytearray(0xC00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    optional_size = 240 if bits == 64 else 224
    flags = 0x2022 if bits == 64 else 0x2102
    struct.pack_into("<HHIIIHH", data, 0x44, 0x8664 if bits == 64 else 0x14C, 2, 0, 0, 0, optional_size, flags)
    optional = 0x58
    struct.pack_into("<H", data, optional, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<III", data, optional + 4, 0x200, 0x800, 0)
    struct.pack_into("<II", data, optional + 16, 0x1000, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
        struct.pack_into("<QQQQ", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    else:
        struct.pack_into("<II", data, optional + 24, 0x2000, 0x400000)
        struct.pack_into("<IIII", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HH", data, optional + 40, 6, 0)
    struct.pack_into("<HH", data, optional + 48, 6, 0)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", data, optional + 68, 3, 0x140)
    directory_offset = optional + (112 if bits == 64 else 96)
    struct.pack_into("<I", data, directory_offset - 4, 16)
    struct.pack_into("<II", data, directory_offset, 0x2200, 0x200)
    struct.pack_into("<II", data, directory_offset + 8, 0x2000, 40)
    struct.pack_into("<II", data, directory_offset + 4 * 8, 0xC00, 16)
    section_offset = optional + optional_size
    for index, (name, virtual, rva, raw_size, raw, flags) in enumerate([
        (b".text", 3, 0x1000, 0x200, 0x200, 0x60000020),
        (b".rdata", 0x800, 0x2000, 0x800, 0x400, 0x40000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", data, section_offset + 40 * index,
                         name, virtual, rva, raw_size, raw, 0, 0, 0, 0, flags)
    data[0x200:0x203] = b"\x31\xc0\xc3"  # Inert return stub; never run by the generator/collector.
    struct.pack_into("<IIIII", data, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
    data[0x460:0x460 + 13] = b"KERNEL32.dll\0"
    values = (0x20C0, (1 << (bits - 1)) | 7, 0)
    for offset in (0x480, 0x4A0):
        struct.pack_into("<QQQ" if bits == 64 else "<III", data, offset, *values)
    struct.pack_into("<H", data, 0x4C0, 0)
    imported = b"VirtualProtect\0"
    data[0x4C2:0x4C2 + len(imported)] = imported
    struct.pack_into("<IIHHIIIIIII", data, 0x600, 0, 0, 0, 0, 0x2260, 1, 3, 2, 0x2240, 0x2250, 0x2258)
    struct.pack_into("<III", data, 0x640, 0x1000, 0x2280, 0x1001)
    struct.pack_into("<II", data, 0x650, 0x22A0, 0x22B0)
    struct.pack_into("<HH", data, 0x658, 0, 1)
    for offset, value in ((0x660, b"wired2ai-demo.dll\0"), (0x680, b"KERNEL32.Sleep\0"),
                          (0x6A0, b"DemoEntry\0"), (0x6B0, b"ForwardedSleep\0")):
        data[offset:offset + len(value)] = value
    data.extend(struct.pack("<IHH", 12, 0x200, 2) + b"DEMO" + b"\0" * 4)
    data.extend(b"W2AI-PE-DEMO-TAIL")
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New .bin path; existing files are refused")
    parser.add_argument("--bits", type=int, choices=(32, 64), default=64)
    args = parser.parse_args()
    data = image_bytes(args.bits)
    with args.output.open("xb") as stream:
        stream.write(data)
    print(f"Wrote {len(data)} synthetic PE{args.bits} fixture bytes to {args.output}; do not execute this fixture.")


if __name__ == "__main__":
    main()
