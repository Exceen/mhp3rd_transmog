#!/usr/bin/env python3
"""Dump ALL layout table entries used by clock to find what's missing."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_1.ppst"
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

LAYOUT_BASE = 0x09D92CB0
ENTRY_SIZE = 36

# All addiu offsets from CLOCK1 disassembly
CLOCK1_ADDIU = {
    11512: "frame1(always)",
    11548: "frame2(always)",
    11908: "flash_mode2",
    11584: "mode2_sub / mode1_entry4",
    11944: "flash_mode3(entry14)",
    11692: "mode3_sub(entry7)",
    11980: "mode1_flash(NON-ALIGNED)",
    11620: "mode1_sub2(entry5)",
    11656: "mode1_sub3(entry6)",
    # 11440 is the base for dynamic hand index (entries 16-26)
}

print("=== ALL CLOCK1 SPRITE ENTRIES ===")
for addiu_val, desc in sorted(CLOCK1_ADDIU.items()):
    addr = 0x09D90000 + addiu_val
    entry_idx = (addr - LAYOUT_BASE) / ENTRY_SIZE
    aligned = entry_idx == int(entry_idx)
    off = psp_to_offset(addr)

    v0x = read_u16(data, off + 0)
    v0y = read_u16(data, off + 2)
    v1x = read_u16(data, off + 4)
    v1y = read_u16(data, off + 6)
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)

    marker = "ALIGNED" if aligned else "**NON-ALIGNED**"
    print(f"  addiu {addiu_val:5d} -> 0x{addr:08X} entry={entry_idx:5.1f} [{marker}]"
          f"  v0=({v0x},{v0y}) v1=({v1x},{v1y}) X={x} Y={y}  [{desc}]")

print(f"\n=== LAYOUT TABLE ENTRIES 0-40 ===")
print(f"{'Idx':>4} {'Address':>12}  v0_x v0_y v1_x v1_y    X    Y  | raw bytes 0-7           | tex 8-15")
for i in range(41):
    addr = LAYOUT_BASE + i * ENTRY_SIZE
    off = psp_to_offset(addr)

    v0x = read_u16(data, off + 0)
    v0y = read_u16(data, off + 2)
    v1x = read_u16(data, off + 4)
    v1y = read_u16(data, off + 6)
    tex0 = read_u32(data, off + 8)
    tex1 = read_u32(data, off + 12)
    flags = read_u32(data, off + 16)
    color = read_u32(data, off + 20)
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)
    pad0 = read_u32(data, off + 28)
    pad1 = read_u32(data, off + 32)

    w = abs(v1x - v0x)
    h = abs(v1y - v0y)

    print(f"  [{i:2d}] 0x{addr:08X}  {v0x:4d} {v0y:4d} {v1x:4d} {v1y:4d}  {x:4d} {y:4d}"
          f"  | {v0x:04X} {v0y:04X} {v1x:04X} {v1y:04X} | {tex0:08X} {tex1:08X}"
          f"  flags={flags:08X} color={color:08X} {w}x{h}")

# Also dump the CLOCK2 digit table
DIGIT_TABLE = 0x09D8E0B0
print(f"\n=== CLOCK2 DIGIT TABLE at 0x{DIGIT_TABLE:08X} ===")
for i in range(8):
    off = psp_to_offset(DIGIT_TABLE + i * 4)
    flag = read_s16(data, off)
    idx = read_s16(data, off + 2)

    if flag == 0 and 0 <= idx < 100:
        entry_addr = LAYOUT_BASE + idx * ENTRY_SIZE
        eoff = psp_to_offset(entry_addr)
        ex = read_s16(data, eoff + 24)
        ey = read_s16(data, eoff + 26)
        ev0x = read_u16(data, eoff + 0)
        ev0y = read_u16(data, eoff + 2)
        ev1x = read_u16(data, eoff + 4)
        ev1y = read_u16(data, eoff + 6)
        print(f"  [{i}] flag={flag} idx={idx:3d} -> entry at 0x{entry_addr:08X}"
              f"  v0=({ev0x},{ev0y}) v1=({ev1x},{ev1y}) X={ex} Y={ey}")
    elif flag == 1:
        print(f"  [{i}] flag={flag} idx={idx:3d} -> ANIMATED (RENDER_12D8)")
    else:
        print(f"  [{i}] flag={flag} idx={idx:3d} -> OTHER")

# Check the digit animation structure
# When flag=1, CLOCK2 does: $a0 = $s5 + idx * 80, reads offsets +32 and +36
# $s5 = $a0 + 724 (from function entry), $a0 is the clock state struct
print(f"\n=== CLOCK2 ANIMATED DIGIT DATA ===")
# The animation data is at clock_struct + 724 + idx * 80
# We don't know clock_struct address without tracing, but let's see what idx values are used
for i in range(8):
    off = psp_to_offset(DIGIT_TABLE + i * 4)
    flag = read_s16(data, off)
    idx = read_s16(data, off + 2)
    if flag == 1:
        print(f"  [{i}] animated idx={idx} (struct offset = 724 + {idx}*80 = {724 + idx*80})")
