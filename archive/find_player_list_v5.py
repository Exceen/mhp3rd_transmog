#!/usr/bin/env python3
"""Analyze the eboot sprite/layout table around the HP bar width addresses."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

# HP bar width addresses: 0x08938AB8 and 0x08938AC4 (12 bytes apart)
# These control bar width with values like 0x6A (106), 0x84 (132), 0x108 (264), 0x12C (300)
# Let's dump a wide area around this to find the structure

print("=== WIDE DUMP AROUND HP BAR WIDTH (0x08938A00 - 0x08938C00) ===")
print("Format: addr (CW) : u16 values | s16 values")
for addr in range(0x08938A00, 0x08938C00, 2):
    off = psp_to_offset(addr)
    if off + 2 <= len(data):
        val = read_u16(data, off)
        sval = read_s16(data, off)
        cw = addr - 0x08800000
        marker = ""
        if addr == 0x08938AB8: marker = " <-- HP bar width 1"
        elif addr == 0x08938AC4: marker = " <-- HP bar width 2"
        # Only print non-zero or marked values
        if val != 0 or marker:
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): u16={val:5d} (0x{val:04X})  s16={sval:6d}{marker}")

# Let's also dump as groups of 6 u16s (common sprite entry format: x, y, w, h, u, v or similar)
print("\n\n=== GROUPED DUMP (12-byte entries) ===")
for i in range(30):
    base = 0x08938A80 + i * 12
    off = psp_to_offset(base)
    if off + 12 <= len(data):
        vals = [read_s16(data, off + j*2) for j in range(6)]
        cw = base - 0x08800000
        marker = ""
        if base == 0x08938AB8: marker = " <-- HP bar width entry 1"
        elif base == 0x08938AC4: marker = " <-- HP bar width entry 2"
        print(f"  [{i:2d}] 0x{base:08X} (CW 0x{cw:07X}): {vals}{marker}")

# Try different entry sizes
for entry_size in [8, 10, 12, 14, 16, 20, 24]:
    # Check if HP bar addresses align to this entry size
    offset1 = (0x08938AB8 - 0x08938000) % entry_size
    offset2 = (0x08938AC4 - 0x08938000) % entry_size
    if offset1 == offset2:
        print(f"\n  Entry size {entry_size}: both HP addresses at field offset {offset1}")

# Wider search: dump 0x08938000-0x08939000 looking for screen coordinates
print("\n\n=== SCREEN COORDINATE SEARCH (0x08938000 - 0x0893A000) ===")
print("Looking for u16 pairs that could be (X,Y) screen positions")
for addr in range(0x08938000, 0x0893A000, 4):
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        x = read_s16(data, off)
        y = read_s16(data, off + 2)
        # Look for plausible screen coordinates
        if 0 <= x <= 480 and 0 <= y <= 272 and (x > 0 or y > 0):
            cw = addr - 0x08800000
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): X={x:4d} Y={y:4d}")

# Also dump the exact bytes around HP bar for structure analysis
print("\n\n=== RAW HEX AROUND HP BAR ADDRESSES ===")
for base_addr in [0x08938A80, 0x08938AA0, 0x08938AB0, 0x08938AC0, 0x08938AD0, 0x08938AE0]:
    off = psp_to_offset(base_addr)
    if off + 16 <= len(data):
        raw = ' '.join(f'{data[off+j]:02X}' for j in range(16))
        cw = base_addr - 0x08800000
        print(f"  0x{base_addr:08X} (CW 0x{cw:07X}): {raw}")

# Try to find what code reads from 0x08938AB8
# Search for LUI 0x0894 (since 0x08938AB8 = lui 0x0894, offset -0x7548)
# or LUI 0x0893, offset 0x8AB8 (but 0x8AB8 > 0x7FFF so sign-extended)
# 0x08938AB8: lui 0x0894, addiu -0x7548 (= 0x8AB8)
print("\n\n=== CODE REFERENCING 0x08938Axx AREA ===")
overlay_start = psp_to_offset(0x09C57C80)
overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)
eboot_start = psp_to_offset(0x08800000)
eboot_end = min(psp_to_offset(0x08960000), len(data) - 4)

# Look for LW/LH/LHU with offset 0x8AB8 or nearby (sign-extended = -0x7548)
target_offsets = [0x8AB8, 0x8AC4, 0x8AB0, 0x8AA0, 0x8A80]
for region_name, start, end in [("eboot", eboot_start, eboot_end), ("overlay", overlay_start, overlay_end)]:
    for off in range(start, end, 4):
        instr = read_u32(data, off)
        op = instr >> 26
        if op in (0x21, 0x25, 0x23, 0x29, 0x09):  # lh, lhu, lw, sh, addiu
            imm = instr & 0xFFFF
            if imm in target_offsets:
                rs = (instr >> 21) & 0x1F
                psp = off - MEM_OFFSET + PSP_BASE
                # Check if rs was loaded with 0x0894 nearby
                for k in range(1, 10):
                    prev_off = off - k * 4
                    if prev_off >= start:
                        pi = read_u32(data, prev_off)
                        if (pi >> 26) == 0x0F:  # LUI
                            lui_imm = pi & 0xFFFF
                            if lui_imm == 0x0894:
                                lui_rt = (pi >> 16) & 0x1F
                                if lui_rt == rs:
                                    full = (lui_imm << 16) + (imm if imm < 0x8000 else imm - 0x10000)
                                    print(f"  [{region_name}] 0x{psp:08X}: op={op:02X} offset=0x{imm:04X} -> 0x{full:08X}")
                                    break

print("\nDone!")
