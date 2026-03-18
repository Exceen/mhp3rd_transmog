#!/usr/bin/env python3
"""
Dump MHP3rd monster names by type ID from a save state.
Uses the name lookup table at 0x08A39F4C with bias +382.
"""

import zstandard
import struct
import sys

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
OFFSET_IN_FILE = 0x48

NAME_TABLE_BASE = 0x08A39F4C
NAME_BIAS = 382

def psp_to_file(addr):
    return addr - PSP_BASE + OFFSET_IN_FILE

def read_psp_u32(data, addr):
    off = psp_to_file(addr)
    return struct.unpack_from('<I', data, off)[0]

def read_psp_string(data, addr, max_len=64):
    off = psp_to_file(addr)
    result = b''
    for i in range(max_len):
        b = data[off + i]
        if b == 0:
            break
        result += bytes([b])
    try:
        return result.decode('utf-8')
    except:
        try:
            return result.decode('shift-jis')
        except:
            return result.hex()

def main():
    with open(SAVE_STATE, 'rb') as f:
        raw = f.read()

    compressed = raw[HEADER_SIZE:]
    dctx = zstandard.ZstdDecompressor()
    data = dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)

    print(f"Decompressed size: {len(data)} bytes")
    print(f"Name table base: 0x{NAME_TABLE_BASE:08X}")
    print()

    # Dump names for type IDs 0-255
    print(f"{'TypeID':>6} | {'Name':40} | {'Ptr Offset':>10}")
    print("-" * 65)

    for type_id in range(256):
        index = type_id + NAME_BIAS
        ptr_addr = NAME_TABLE_BASE + index * 4

        try:
            offset = read_psp_u32(data, ptr_addr)
            if offset == 0:
                continue

            # Name string = table_base + offset
            name_addr = NAME_TABLE_BASE + offset
            name = read_psp_string(data, name_addr)

            if name and name.strip():
                print(f"{type_id:>6} | {name:40} | 0x{offset:08X}")
        except:
            continue

if __name__ == '__main__':
    main()
