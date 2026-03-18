#!/usr/bin/env python3
"""Find item selector flag from fresh back-to-back save states.
Index 6 = selector CLOSED, Index 5 = selector OPEN."""

import struct
import zstandard as zstd

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

data_closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")
data_open = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Search ALL game RAM for 4-byte aligned values:
# CLOSED=0 → OPEN=small(1-10)
print("=== 4-byte aligned: CLOSED=0 → OPEN=1-10 ===")
for addr in range(0x09800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_closed) or off + 4 > len(data_open): break
    v_closed = read_u32(data_closed, off)
    v_open = read_u32(data_open, off)
    if v_closed == 0 and 1 <= v_open <= 10:
        # Skip known button state
        if 0x09BB7A60 <= addr <= 0x09BB7A80: continue
        print(f"  0x{addr:08X}: 0 → {v_open}")

# Also search for CLOSED=0 → OPEN=0x000000XX (byte-sized in 32-bit word)
print(f"\n=== 4-byte aligned: CLOSED=0 → OPEN=0x000000XX (11-255) ===")
for addr in range(0x09800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_closed) or off + 4 > len(data_open): break
    v_closed = read_u32(data_closed, off)
    v_open = read_u32(data_open, off)
    if v_closed == 0 and v_open != 0 and (v_open & 0xFFFFFF00) == 0 and v_open > 10:
        if 0x09BB7A60 <= addr <= 0x09BB7A80: continue
        print(f"  0x{addr:08X}: 0 → {v_open} (0x{v_open:02X})")

# Search for CLOSED=small → OPEN=different_small (state machine transitions)
print(f"\n=== 4-byte aligned: both 1-10, different values ===")
for addr in range(0x09800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_closed) or off + 4 > len(data_open): break
    v_closed = read_u32(data_closed, off)
    v_open = read_u32(data_open, off)
    if 1 <= v_closed <= 10 and 1 <= v_open <= 10 and v_closed != v_open:
        if 0x09BB7A60 <= addr <= 0x09BB7A80: continue
        print(f"  0x{addr:08X}: {v_closed} → {v_open}")

# Byte-level search for clean 0→1 flags across all RAM
print(f"\n=== Byte-level: CLOSED=0x00 → OPEN=0x01 (any alignment) ===")
count = 0
for addr in range(0x09800000, 0x09E00000):
    off = psp_to_offset(addr)
    if off >= len(data_closed) or off >= len(data_open): break
    if data_closed[off] == 0 and data_open[off] == 1:
        if 0x09BB7A60 <= addr <= 0x09BB7A80: continue
        count += 1
        aligned = "ALIGNED" if addr % 4 == 0 else f"+{addr%4}"
        if count <= 80:
            print(f"  0x{addr:08X} ({aligned})")
if count > 80:
    print(f"  ... {count} total")

print("\nDone!")
