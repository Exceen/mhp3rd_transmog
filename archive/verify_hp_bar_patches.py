#!/usr/bin/env python3
"""Verify the $t0=0 instructions in HP bar sub-renderers and generate CWCheat patches."""

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

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

data = decompress_ppst(PPST_FILE)

ADDU_T0_ZERO = 0x00004021  # addu $t0, $zero, $zero

# Dump functions to find all $t0=0 (addu $t0,$zero,$zero) instructions

print("=== 0x09D61838 (HP_BAR_SUB: 3x sprite_1000 + bg_BF0) ===")
for addr in range(0x09D61838, 0x09D61B00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == ADDU_T0_ZERO:
        cw = addr - 0x08800000
        # Check what follows (look for jal)
        next1 = read_u32(data, psp_to_offset(addr + 4))
        next2 = read_u32(data, psp_to_offset(addr + 8))
        for ni, na in [(next1, addr+4), (next2, addr+8)]:
            if ni >> 26 == 0x03:
                target = (ni & 0x03FFFFFF) << 2
                print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0,$zero,$zero  -> jal 0x{target:08X}")
                break

print()
print("=== 0x09D61558 (HP_BAR_SUB2: 2x sprite_1000 + 2x sprite_1168) ===")
for addr in range(0x09D61558, 0x09D61700, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == ADDU_T0_ZERO:
        cw = addr - 0x08800000
        next1 = read_u32(data, psp_to_offset(addr + 4))
        next2 = read_u32(data, psp_to_offset(addr + 8))
        for ni, na in [(next1, addr+4), (next2, addr+8)]:
            if ni >> 26 == 0x03:
                target = (ni & 0x03FFFFFF) << 2
                print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0,$zero,$zero  -> jal 0x{target:08X}")
                break

print()
print("=== 0x09D614EC (BG_SUB: bg_BF0) ===")
for addr in range(0x09D614EC, 0x09D61558, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    # For bg_BF0, check both $t0 and $t1 (since bg_BF0 uses $t1 for X)
    if instr == ADDU_T0_ZERO:
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0,$zero,$zero")
    ADDU_T1_ZERO = 0x00004821  # addu $t1, $zero, $zero
    if instr == ADDU_T1_ZERO:
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t1,$zero,$zero")

print()
print("=== 0x09D61248 (SPRITE_1000_DIRECT) ===")
for addr in range(0x09D61248, 0x09D614EC, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == ADDU_T0_ZERO:
        cw = addr - 0x08800000
        next1 = read_u32(data, psp_to_offset(addr + 4))
        next2 = read_u32(data, psp_to_offset(addr + 8))
        for ni, na in [(next1, addr+4), (next2, addr+8)]:
            if ni >> 26 == 0x03:
                target = (ni & 0x03FFFFFF) << 2
                print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0,$zero,$zero  -> jal 0x{target:08X}")
                break

# Also check 0x09D6228C (SPRITE_1000_SUB)
print()
print("=== 0x09D6228C (SPRITE_1000_SUB) ===")
for addr in range(0x09D6228C, 0x09D62384, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == ADDU_T0_ZERO:
        cw = addr - 0x08800000
        next1 = read_u32(data, psp_to_offset(addr + 4))
        next2 = read_u32(data, psp_to_offset(addr + 8))
        for ni, na in [(next1, addr+4), (next2, addr+8)]:
            if ni >> 26 == 0x03:
                target = (ni & 0x03FFFFFF) << 2
                print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0,$zero,$zero  -> jal 0x{target:08X}")
                break

# Generate CWCheat patch lines
print("\n\n=== CWCHEAT PATCH LINES (X=98 offset) ===")
print("; Sentinel: overlay loaded check")
print("; _L 0xD1457C90 0x00005FA0")
print("; addiu $t0,$zero,98 = 0x24080062")
print("; addiu $t1,$zero,98 = 0x24090062")

# Collect all addresses to patch
patches = []
for start, end in [(0x09D61838, 0x09D61B00), (0x09D61558, 0x09D61700),
                    (0x09D61248, 0x09D614EC), (0x09D6228C, 0x09D62384)]:
    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        if instr == ADDU_T0_ZERO:
            # Verify a jal follows within 2 instructions
            for k in [4, 8]:
                ni = read_u32(data, psp_to_offset(addr + k))
                if ni >> 26 == 0x03:
                    target = (ni & 0x03FFFFFF) << 2
                    if target in [0x08901000, 0x08901168, 0x0890112C]:
                        cw = addr - 0x08800000
                        patches.append((addr, cw, f"$t0 before jal 0x{target:08X}"))
                    break

# Also check bg_BF0 sub for $t1
for addr in range(0x09D614EC, 0x09D61558, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    ADDU_T1_ZERO = 0x00004821
    if instr == ADDU_T1_ZERO:
        for k in [4, 8, 12, 16]:
            if addr + k >= 0x09D61558: break
            ni = read_u32(data, psp_to_offset(addr + k))
            if ni >> 26 == 0x03:
                target = (ni & 0x03FFFFFF) << 2
                if target == 0x08900BF0:
                    cw = addr - 0x08800000
                    patches.append((addr, cw, f"$t1 before jal 0x{target:08X} (bg)"))
                break

print()
for addr, cw, desc in patches:
    instr_val = read_u32(data, psp_to_offset(addr))
    if instr_val == ADDU_T0_ZERO:
        print(f"_L 0xD1457C90 0x00005FA0")
        print(f"_L 0x2{cw:07X} 0x24080062  ; {desc}")
    elif instr_val == 0x00004821:
        print(f"_L 0xD1457C90 0x00005FA0")
        print(f"_L 0x2{cw:07X} 0x24090062  ; {desc}")

print(f"\nTotal patches: {len(patches)}")
print("\nDone!")
