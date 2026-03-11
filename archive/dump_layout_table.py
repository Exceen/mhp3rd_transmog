#!/usr/bin/env python3
"""Dump the UI layout table at 0x09D92CB0 to find player list entries."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u8(data, off):
    return data[off]

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

# Layout table at 0x09D92CB0, 36-byte entries
# X at +24 (0x18), Y at +26 (0x1A)
TABLE_BASE = 0x09D92CB0
ENTRY_SIZE = 36

print(f"\n=== LAYOUT TABLE AT 0x{TABLE_BASE:08X} (36-byte entries) ===")
print(f"{'Idx':>4} {'Address':>12} {'CW Offset':>12}  X(+24)  Y(+26)  Bytes")

# Dump first ~80 entries
for i in range(80):
    addr = TABLE_BASE + i * ENTRY_SIZE
    off = psp_to_offset(addr)
    if off + ENTRY_SIZE <= len(data):
        x = read_s16(data, off + 24)
        y = read_s16(data, off + 26)
        # Also read all bytes for context
        raw = data[off:off+ENTRY_SIZE]
        hex_preview = ' '.join(f'{b:02X}' for b in raw[:12])
        cw = addr - 0x08800000
        cw_x = (addr + 24) - 0x08800000
        cw_y = (addr + 26) - 0x08800000
        marker = ""
        # PSP screen is 480x272
        if 0 <= x <= 480 and 0 <= y <= 272:
            marker = f"  screen({x},{y})"
        elif x < 0 or y < 0:
            marker = f"  negative"
        print(f"{i:4d} 0x{addr:08X} CW 0x{cw:07X}  {x:6d}  {y:6d}  {hex_preview}{marker}")

# Also dump the second table that was referenced
TABLE2_BASE = 0x09D95DE0
print(f"\n\n=== TABLE 2 AT 0x{TABLE2_BASE:08X} ===")
for i in range(20):
    addr = TABLE2_BASE + i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        val = read_u32(data, off)
        b0 = data[off]
        b1 = data[off+1]
        b2 = data[off+2]
        b3 = data[off+3]
        print(f"  [{i:2d}] 0x{addr:08X}: 0x{val:08X}  bytes: {b0:3d} {b1:3d} {b2:3d} {b3:3d}")

# Also dump the secondary index table at 0x09D95DEC area
# From the code: lui $v0, 0x09D9; addiu $v1, $v1, 24044 (0x5DEC)
TABLE3_BASE = 0x09D95DEC
print(f"\n\n=== INDEX TABLE AT 0x{TABLE3_BASE:08X} ===")
for i in range(20):
    addr = TABLE3_BASE + i
    off = psp_to_offset(addr)
    if off < len(data):
        val = data[off]
        print(f"  [{i:2d}] 0x{addr:08X}: {val:3d} (entry at table1 + {val*36})")

# Dump the caller's structure to understand what's in it
# The function at 0x09D6C90C is called in a loop with $s2 as the struct
# $s2 has: offset +8 = count, +12 = data array (4 bytes each)
# Let me also look at the data structure referenced by 0x09BFB0BC
# which is loaded as: lui $v0, 0x09BF; lw $a0, -20292($v0) → 0x09BEB0BC
# Wait: 0x09BF0000 + (-20292) = 0x09BF0000 - 0x4F44 = 0x09BEB0BC
# Actually: -20292 decimal = -0x4F44, so 0x09BF0000 - 0x4F44 = 0x09BEB0BC
PTR_ADDR = 0x09BEB0BC
print(f"\n\n=== RENDER CONTEXT PTR AT 0x{PTR_ADDR:08X} ===")
off = psp_to_offset(PTR_ADDR)
if off + 4 <= len(data):
    ptr = read_u32(data, off)
    print(f"  0x{PTR_ADDR:08X} = 0x{ptr:08X}")
    if 0x08000000 <= ptr <= 0x0A000000:
        poff = psp_to_offset(ptr)
        print(f"  Dumping struct at 0x{ptr:08X}:")
        for j in range(0, 64, 4):
            if poff + j + 4 <= len(data):
                val = read_u32(data, poff + j)
                print(f"    +0x{j:02X}: 0x{val:08X}")

# The cursor setter is called with $a0 loaded from -24808($fp) where $fp = 0x09BF
# -24808 = -0x60E8, so addr = 0x09BF0000 - 0x60E8 = 0x09BE9F18
PRINT_PTR = 0x09BE9F18
print(f"\n\n=== PRINT STRUCT PTR AT 0x{PRINT_PTR:08X} ===")
off = psp_to_offset(PRINT_PTR)
if off + 4 <= len(data):
    ptr = read_u32(data, off)
    print(f"  0x{PRINT_PTR:08X} = 0x{ptr:08X}")
    # This should be the print settings structure
    if 0x08000000 <= ptr <= 0x0A000000:
        poff = psp_to_offset(ptr)
        # Dump cursor area
        for j in [0x120, 0x122, 0x124, 0x12C, 0x12D, 0x12E, 0x12F, 0x130, 0x131, 0x164, 0x166, 0x167]:
            if poff + j + 2 <= len(data):
                val = read_u16(data, poff + j)
                print(f"    +0x{j:03X}: 0x{val:04X} ({val})")

print("\nDone!")
