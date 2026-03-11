#!/usr/bin/env python3
"""Find player list by searching for HP bar width value and nearby position data."""

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

# Strategy 1: The user's HP bar codes write to 0x08938AB8 and 0x08938AC4
# Let's find what code READS from these addresses
# Search for instructions that access memory near 0x08938AB8
# In MIPS, this could be via: lui $reg, 0x0894; lhu/lh $reg, -0x7548($reg)
# Or via a pointer in a register

print("=== STRATEGY 1: Find code that accesses 0x08938AB8 ===")
# The address 0x08938AB8 can be loaded as:
# lui $r, 0x0894 + addiu/lh/lhu $r, -0x7548($r)
# -0x7548 = 0x8AB8 (as unsigned)
# OR: lui $r, 0x0893 + lh/lhu $r, -0x7548... no, 0x8AB8 > 0x7FFF
# Actually: 0x08938AB8 = 0x08940000 - 0x7548
# So: lui 0x0894, offset = -0x7548 = 0x8AB8 (signed)

ranges = [
    ("eboot", 0x08800000, 0x08960000),
    ("overlay", 0x09C57C80, 0x09DC0000),
]

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)
    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        imm = instr & 0xFFFF
        op = instr >> 26
        # Look for load/store with offset 0x8AB8 or 0x8AC4
        if imm in (0x8AB8, 0x8AB6, 0x8AC4, 0x8AC2) and op in (0x21, 0x23, 0x25, 0x29, 0x09):
            rs = (instr >> 21) & 0x1F
            rt = (instr >> 16) & 0x1F
            psp = off - MEM_OFFSET + PSP_BASE
            print(f"  [{region_name}] 0x{psp:08X}: op=0x{op:02X} rs=${rs} rt=${rt} imm=0x{imm:04X}")

# Strategy 2: Search for the raw 32-bit value at these addresses
# and find what pointer math could reach them
# HP bar address 0x08938AB8 - look for this value stored somewhere
hp_bar_addr = 0x08938AB8
print(f"\n=== STRATEGY 2: Search for pointer to 0x{hp_bar_addr:08X} ===")
search_bytes = struct.pack('<I', hp_bar_addr)
idx = 0
while idx < len(data):
    found = data.find(search_bytes, idx)
    if found == -1:
        break
    psp = found - MEM_OFFSET + PSP_BASE
    if 0x08000000 <= psp <= 0x0A000000:
        print(f"  Found at 0x{psp:08X}")
    idx = found + 1

# Strategy 3: Look at the MHFU approach - search for code that sets
# screen coordinates before rendering player names
# In MHP3rd, look for addiu instructions setting values like 2 (X) or 50, 66, 87, 108 (Y)
# in the eboot code near rendering functions

# The rendering code for the player HUD likely calls functions in the 0x088Exxxx range
# Let's search for addiu $reg, $zero, 50 (0x0032) near JAL to 0x088Exxxx
print("\n=== STRATEGY 3: ADDIU with player list Y values near rendering calls ===")
target_values = {50: "Y=50 (P1)", 66: "Y=66 (P2)", 87: "Y=87 (P3)", 108: "Y=108 (P4)"}

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)
    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        # addiu $rt, $zero, value
        if (instr >> 21) == 0x120:  # addiu with rs=$zero
            imm = instr & 0xFFFF
            if imm in target_values:
                rt = (instr >> 16) & 0x1F
                psp = off - MEM_OFFSET + PSP_BASE
                # Check for JAL to 0x088Exxxx or 0x088Fxxxx nearby
                has_render_call = False
                for k in range(-20, 20):
                    noff = off + k * 4
                    if start_off <= noff < end_off:
                        ni = read_u32(data, noff)
                        if (ni >> 26) == 0x03:  # JAL
                            target = (ni & 0x03FFFFFF) << 2
                            if 0x088E0000 <= target <= 0x08910000:
                                has_render_call = True
                                break
                if has_render_call:
                    cw = psp - 0x08800000
                    print(f"  [{region_name}] 0x{psp:08X} (CW 0x{cw:07X}): addiu ${rt}, $zero, {imm} ({target_values[imm]})")

# Strategy 4: Look for the actual UI sprite/data table
# In MHFU, sprite tables at 0x0893xxxx had entries with X,Y,W,H as u16
# Search more broadly for consecutive small u16 values in eboot data
print("\n=== STRATEGY 4: Sprite-like data tables in eboot (0x0893-0x0897) ===")
for base in range(0x08930000, 0x08970000, 2):
    off = psp_to_offset(base)
    if off + 12 <= len(data):
        v0 = read_u16(data, off)
        v1 = read_u16(data, off+2)
        v2 = read_u16(data, off+4)
        v3 = read_u16(data, off+6)
        # Look for patterns like (small_x, small_y, width, height)
        # where x<480, y<272, w>0, h>0, w<480, h<272
        if (0 < v0 < 480 and 0 < v1 < 272 and 0 < v2 < 480 and 0 < v3 < 272):
            # Also require v2 > v0 or v3 > v1 (width > x or height > y)
            # to filter noise
            if v2 > 10 and v3 > 5:
                cw = base - 0x08800000
                print(f"  0x{base:08X} (CW 0x{cw:07X}): {v0:4d} {v1:4d} {v2:4d} {v3:4d}")

# Strategy 5: Check what the HP bar overlay code does
# The 'Bars' cheats write to 0x09DA93A0/A4 (overlay floats)
# The HP bar position code writes to 0x08938AB8/AC4 (eboot data)
# These two must be connected. Let me see what's near the eboot addresses.
print("\n=== STRATEGY 5: Wider context dump around HP bar data ===")
# Dump as u16 values with possible meanings
for addr in range(0x089380E0, 0x08938200, 2):
    off = psp_to_offset(addr)
    if off + 2 <= len(data):
        val = read_u16(data, off)
        sval = read_s16(data, off)
        cw = addr - 0x08800000
        if val != 0 and val <= 500:
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): u16={val:5d} s16={sval:6d}")

print("\n=== Also check 0x089390xx-0x089392xx ===")
for addr in range(0x089390E0, 0x08939300, 2):
    off = psp_to_offset(addr)
    if off + 2 <= len(data):
        val = read_u16(data, off)
        sval = read_s16(data, off)
        cw = addr - 0x08800000
        if val != 0 and val <= 500:
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): u16={val:5d} s16={sval:6d}")

print("\nDone!")
