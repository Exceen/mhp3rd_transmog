#!/usr/bin/env python3
"""Read the $ra circular buffer logged by the code cave hook on 0x088FFF0C."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

# Read counter at 0x088001FC
counter_off = psp_to_offset(0x088001FC)
counter = read_u32(data, counter_off)
print(f"Counter: {counter}")

# Read buffer at 0x08800200 (64 entries)
print(f"\n=== All 64 buffer entries ===")
ra_values = []
for i in range(64):
    addr = 0x08800200 + i * 4
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    ra_values.append(val)
    if val != 0:
        region = "EBOOT" if val < 0x09000000 else "OVERLAY"
        print(f"  [{i:2d}] 0x{val:08X} ({region})")

# Show unique values with counts
print(f"\n=== Unique $ra values (callers of 0x088FFF0C) ===")
from collections import Counter
counts = Counter(v for v in ra_values if v != 0)
for val, cnt in counts.most_common():
    region = "EBOOT" if val < 0x09000000 else "OVERLAY"
    # The $ra value points to the instruction AFTER the jal/jalr
    # For jal: caller_addr = $ra - 8 (jal + delay slot)
    # For tail call (j): $ra is from the ORIGINAL caller of the wrapper
    print(f"  0x{val:08X} ({region}) — {cnt} times")

print("\nDone!")
