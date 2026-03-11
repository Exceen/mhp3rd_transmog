#!/usr/bin/env python3
"""Quick check of layout table entry 82 and verify our theory."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

data = decompress_ppst(PPST_FILE)

TABLE_BASE = 0x09D92CB0
ENTRY_SIZE = 36

# Check entries 47, 57, 70, 82 and a few more
for idx in [47, 57, 70, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93]:
    addr = TABLE_BASE + idx * ENTRY_SIZE
    off = psp_to_offset(addr)
    if off + ENTRY_SIZE <= len(data):
        x = read_s16(data, off + 24)
        y = read_s16(data, off + 26)
        xy_addr = addr + 24
        cw = xy_addr - 0x08800000
        raw = ' '.join(f'{data[off+j]:02X}' for j in range(ENTRY_SIZE))
        print(f"Entry {idx:3d} at 0x{addr:08X}: X={x:4d} Y={y:4d}  XY_addr=0x{xy_addr:08X} CW=0x{cw:07X}")
        print(f"  Raw: {raw}")

# Summary for CWCheat
print("\n=== CWCheat addresses for player list base positions ===")
for i, idx in enumerate([47, 57, 70, 82]):
    addr = TABLE_BASE + idx * ENTRY_SIZE + 24
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        x = read_s16(data, off)
        y = read_s16(data, off + 2)
        cw = addr - 0x08800000
        val = read_u16(data, off) | (read_u16(data, off + 2) << 16)
        print(f"Player {i+1}: entry {idx}, 0x{addr:08X} (CW 0x{cw:07X}), current X={x} Y={y}, value=0x{val:08X}")
