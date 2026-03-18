#!/usr/bin/env python3
"""Check the HP/stamina bar layout table at 0x08938AB0 and find what writes to it."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

# Dump the layout table around 0x08938AB0
print("=== Layout table at 0x08938AA0-0x08938AF0 ===")
for addr in range(0x08938AA0, 0x08938AF0, 2):
    off = psp_to_offset(addr)
    val = read_u16(data, off)
    sval = read_s16(data, off)
    marker = ""
    if addr == 0x08938AB4: marker = " <<<< HP X"
    elif addr == 0x08938AB6: marker = " <<<< HP Y"
    elif addr == 0x08938AB8: marker = " <<<< HP W (bar width)"
    elif addr == 0x08938ABA: marker = " <<<< HP H"
    elif addr == 0x08938ABC: marker = " <<<< HP endcap X?"
    elif addr == 0x08938ABE: marker = " <<<< HP endcap Y"
    elif addr == 0x08938AC0: marker = " <<<< Stamina X"
    elif addr == 0x08938AC2: marker = " <<<< Stamina Y"
    elif addr == 0x08938AC4: marker = " <<<< Stamina W"
    elif addr == 0x08938AC6: marker = " <<<< Stamina H"
    elif addr == 0x08938AC8: marker = " <<<< Stamina endcap X?"
    elif addr == 0x08938ACA: marker = " <<<< Stamina endcap Y"
    print(f"  0x{addr:08X}: 0x{val:04X} ({sval:6d}){marker}")

# Show wider context as 12-byte entries
print("\n=== Entries as 12-byte sprite records ===")
for i in range(6):
    base = 0x08938AA0 + i * 12
    fields = []
    for j in range(6):
        off = psp_to_offset(base + j*2)
        fields.append(read_s16(data, off))
    print(f"  Entry {i} at 0x{base:08X}: X={fields[0]:5d} Y={fields[1]:5d} W={fields[2]:5d} H={fields[3]:5d} ?={fields[4]:5d} ?={fields[5]:5d}")

# Also check as 36-byte entries (known layout table format)
print("\n=== Check if this is within a larger structure ===")
# 0x08938AB4 relative to potential table bases
# From memory: layout table 0x09D92CB0, 36-byte entries
# But this is eboot data, not overlay
# Check what's at the broader area
for addr in range(0x08938A00, 0x08938B00, 4):
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    marker = ""
    if 0x08938AB4 <= addr <= 0x08938ACA:
        marker = " <<<< HP/Stamina bar data"
    print(f"  0x{addr:08X}: 0x{val:08X}{marker}")

# Now search for code that writes to the HP X address (0x08938AB4)
# This could be sh $reg, offset($base) where base+offset = 0x08938AB4
# Common pattern: lui $base, 0x0893; sh $reg, -0x754C($base)
# 0x08938AB4 = 0x08930000 + 0x8AB4
# or 0x08940000 + (-0x754C) = 0x08940000 - 0x754C = 0x0893_8AB4
print("\n=== Searching for writes to 0x08938AB4 area ===")
# lui 0x0894 = 0x3C0_0894_, offset = -0x754C = 0x8AB4
# sh at offset 0x8AB4 from 0x08940000? No: 0x08940000 + (-0x754C signed) = 0x08940000 - 0x754C = 0x0893_8AB4
# So: lui $reg, 0x0894 + sh $x, -0x754C($reg) = sh to 0x08938AB4
# Signed offset -0x754C = 0xFFFF8AB4 & 0xFFFF = 0x8AB4
# For addiu: 0x0894 + 0x8AB4 (sign extended) = 0x08940000 + 0xFFFF8AB4 = 0x08938AB4 ✓

# Search for lui with high part of 0x0893_8AB4
# lui $x, 0x0894 (because offset 0x8AB4 is negative when sign-extended)
target_hi = 0x0894
target_lo = 0x8AB4  # = -0x754C signed

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

# Search eboot for sh instructions with offset 0x8AB4
print(f"  Looking for sh $reg, 0x{target_lo:04X}($base) [where $base loaded with 0x{target_hi:04X}]...")
for addr in range(0x08800000, 0x089A0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x29 and imm == target_lo:  # sh with matching offset
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        print(f"    0x{addr:08X}: sh {REGS[rt]}, 0x{imm:04X}({REGS[rs]})")

# Also search overlay
for addr in range(0x09C50000, 0x09DB0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x29 and imm == target_lo:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        print(f"    0x{addr:08X}: sh {REGS[rt]}, 0x{imm:04X}({REGS[rs]}) [overlay]")

# Also check for sw (word write) that might cover this address
# 0x08938AB4 aligned to word = 0x08938AB4 (if writing 32-bit starting here)
# But 0x08938AB4 is not word-aligned (0xB4 % 4 = 0, actually it IS word aligned)
# So sw to 0x08938AB4 is possible
print(f"\n  Looking for sw to 0x{target_lo:04X}($base)...")
for addr in range(0x08800000, 0x089A0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x2B and imm == target_lo:  # sw with matching offset
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        print(f"    0x{addr:08X}: sw {REGS[rt]}, 0x{imm:04X}({REGS[rs]})")

for addr in range(0x09C50000, 0x09DB0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x2B and imm == target_lo:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        print(f"    0x{addr:08X}: sw {REGS[rt]}, 0x{imm:04X}({REGS[rs]}) [overlay]")

# Also check alternative: base could be loaded via addiu from gp or other method
# Maybe the base is loaded as 0x0893 with positive offset 0x8AB4?
# 0x0893_8AB4 = 0x08930000 + 0x8AB4
# If base has 0x0893 via lui, offset 0x8AB4 is > 0x7FFF (not valid for signed 16-bit)
# So must use lui 0x0894 with negative offset

print("\nDone!")
