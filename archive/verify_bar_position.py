#!/usr/bin/env python3
"""Verify the HP bar position mechanism and find all relevant data addresses."""

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

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F; sa = (instr >> 6) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x1F:
        # Decode SEH/SEB
        if (func == 0x20) and (sa == 0x18):
            return f"seh {REGS[rd]}, {REGS[rt]}"
        if (func == 0x20) and (sa == 0x10):
            return f"seb {REGS[rd]}, {REGS[rt]}"
        return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Dump the entry at 0x09DC0164 in detail
print("=== Entry at 0x09DC0164 (shared bar data, $t0 pointer) ===")
base = 0x09DC0164
off = psp_to_offset(base)
for i in range(0, 36, 2):
    val = read_u16(data, off + i)
    sval = read_s16(data, off + i)
    label = ""
    if i == 0: label = "x1 (texture)"
    elif i == 2: label = "y1 (texture)"
    elif i == 4: label = "x2 (texture)"
    elif i == 6: label = "y2 (texture)"
    elif i == 24: label = "X POSITION <<<<"
    elif i == 26: label = "Y POSITION <<<<"
    elif i == 28: label = "field_28"
    elif i == 30: label = "field_30"
    print(f"  +{i:2d} (0x{base+i:08X}): 0x{val:04X} ({sval:6d})  {label}")

# Dump 0x088FF8F0 complete (need to see $s4=0 branch)
print(f"\n=== 0x088FF8F0 complete (bar render path after $a2 position) ===")
for addr in range(0x088FFAB0, 0x088FFB40, 4):
    off2 = psp_to_offset(addr)
    instr = read_u32(data, off2)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [-> 0x{target:08X}]"
    if "jr $ra" in d: m = " [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Check what code is just before the HP bar render calls (0x09D61300-0x09D61490)
# to understand $s2 value
print(f"\n=== Code at 0x09D61380-0x09D61500 (HP bar area entry) ===")
jal_bar = 0x0C000000 | (0x08904570 >> 2)
for addr in range(0x09D61380, 0x09D61500, 4):
    off2 = psp_to_offset(addr)
    instr = read_u32(data, off2)
    d = disasm(instr, addr)
    m = ""
    if instr == jal_bar: m = " <<<< BAR RENDER"
    if "$s2" in d: m += " [S2]"
    if "$s3" in d: m += " [S3]"
    if "$s0" in d: m += " [S0]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Also check: is $s2 used directly or is it always combined with 0x164?
# What if $s2 is NOT 0x09DC0000 but something else?
# Let me look for where $s2 is loaded with a lui instruction in the broader area
print(f"\n=== lui $s2 instructions near HP bar area ===")
for addr in range(0x09D60000, 0x09D62000, 4):
    off2 = psp_to_offset(addr)
    instr = read_u32(data, off2)
    op = instr >> 26
    rt = (instr >> 16) & 0x1F
    if op == 0x0F and rt == 18:  # lui $s2
        imm = instr & 0xFFFF
        print(f"  0x{addr:08X}: lui $s2, 0x{imm:04X}")
    # Also addiu $s2, with a non-$sp source
    if op == 0x09 and rt == 18:
        rs = (instr >> 21) & 0x1F
        simm = (instr & 0xFFFF)
        if simm >= 0x8000: simm -= 0x10000
        d = disasm(instr, addr)
        if rs != 29:  # not $sp
            print(f"  0x{addr:08X}: {d}")

# Check: what's the complete function at 0x09D60DD4 (frame=80) - closest big func before bar area
print(f"\n=== Function at 0x09D60DD4 (80-byte frame) - looking for $s2 setup ===")
for addr in range(0x09D60DD4, 0x09D60DD4 + 100, 4):
    off2 = psp_to_offset(addr)
    instr = read_u32(data, off2)
    d = disasm(instr, addr)
    m = ""
    if "$s2" in d: m = " [S2]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
