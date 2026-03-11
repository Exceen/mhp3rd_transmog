#!/usr/bin/env python3
"""Verify 0x09BB5CA7 is the selector state across all save states."""

import struct
import os
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

state_dir = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"
states = sorted([f for f in os.listdir(state_dir)
                 if f.startswith("ULJM05800") and f.endswith(".ppst") and "undo" not in f])

FLAG_ADDR = 0x09BB5CA7
FLAG2_ADDR = 0x09BB5DA7  # 256 bytes later, also changed 3->4

print(f"=== SELECTOR STATE BYTE AT 0x{FLAG_ADDR:08X} ACROSS SAVE STATES ===")
for fname in states:
    path = os.path.join(state_dir, fname)
    try:
        d = decompress_ppst(path)
        off = psp_to_offset(FLAG_ADDR)
        val = read_u8(d, off)
        off2 = psp_to_offset(FLAG2_ADDR)
        val2 = read_u8(d, off2)
        # Also check surrounding context
        prev = read_u8(d, psp_to_offset(FLAG_ADDR - 1))  # should be 9
        print(f"  {fname}: @0x{FLAG_ADDR:08X}={val}, @-1={prev}, @0x{FLAG2_ADDR:08X}={val2}")
    except Exception as e:
        print(f"  {fname}: ERROR: {e}")

print("\nDone!")
