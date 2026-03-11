#!/usr/bin/env python3
"""Dump the 13 entries (36 bytes each) for BG_BF0 call #6 (item selector main panel)."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

a1_addr = 0x09D8F3F8  # BG_BF0 #6 $a1 table
ENTRY_SIZE = 36
COUNT = 13

print(f"=== BG_BF0 #6 ENTRIES (0x{a1_addr:08X}, {COUNT} x {ENTRY_SIZE} bytes) ===")
print(f"Format: 36-byte entries, X@+24(s16), Y@+26(s16)")
print()

for i in range(COUNT):
    addr = a1_addr + i * ENTRY_SIZE
    off = psp_to_offset(addr)

    # Read all fields
    words = []
    for w in range(9):  # 36 bytes = 9 words
        words.append(read_u32(data, off + w * 4))

    # Read as halfwords
    halfs = []
    for h in range(18):  # 36 bytes = 18 halfwords
        halfs.append(read_s16(data, off + h * 2))

    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)

    # Raw hex dump
    raw = data[off:off+ENTRY_SIZE]
    hex_str = ' '.join(f'{b:02X}' for b in raw)

    cw_x = (addr + 24) - 0x08800000
    cw_y = (addr + 26) - 0x08800000

    print(f"  [{i:2d}] 0x{addr:08X}:")
    print(f"       Raw: {hex_str}")
    print(f"       Words: {' '.join(f'{w:08X}' for w in words)}")
    print(f"       Halfs: {halfs}")
    print(f"       X={x:4d} Y={y:4d}  (CW X@0x{cw_x:07X}, Y@0x{cw_y:07X})")
    print()

# Also dump the $a2 table entries
a2_addr = 0x09D8F3D4
print(f"\n=== $a2 TABLE (0x{a2_addr:08X}) ===")
# $a2 is stored to sp+4, and sp+0 gets updated with current $s0 (entry pointer)
# The render function 0x08900B7C reads from $a1 (sp frame)
# sp+0 = current entry ptr, sp+4 = $a2 base, sp+8 = $t3, sp+12 = $t0, sp+16 = $t1(X), sp+18 = $t2(Y)

# $a2 might be a separate per-entry data table or a single shared data block
# Let's just dump it raw
off2 = psp_to_offset(a2_addr)
print(f"First 128 bytes of $a2 table:")
for row in range(8):
    row_off = off2 + row * 16
    raw = data[row_off:row_off+16]
    hex_str = ' '.join(f'{b:02X}' for b in raw)
    halfs = [read_s16(data, row_off + h*2) for h in range(8)]
    print(f"  0x{a2_addr + row*16:08X}: {hex_str}  halfs={halfs}")

# Also dump all 8 BG_BF0 calls' $a1 tables to see all entries
print("\n\n=== ALL BG_BF0 CALL #1 ENTRIES (for text+background) ===")
a1_1 = 0x09D8F5F0
for i in range(4):
    addr = a1_1 + i * ENTRY_SIZE
    off = psp_to_offset(addr)
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)
    raw = data[off:off+ENTRY_SIZE]
    hex_str = ' '.join(f'{b:02X}' for b in raw)
    cw_x = (addr + 24) - 0x08800000
    print(f"  [{i}] 0x{addr:08X}: X={x:4d} Y={y:4d}  (CW X@0x{cw_x:07X})")
    print(f"      Raw: {hex_str}")

print("\nDone!")
