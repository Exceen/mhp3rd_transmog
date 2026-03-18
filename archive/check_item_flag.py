#!/usr/bin/env python3
"""Check candidate item selector flags and their context."""

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

data_off = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")
data_on = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

# Check 0x09BE9F5C in detail
print("=== 0x09BE9F5C context (32-bit values) ===")
for addr in range(0x09BE9F40, 0x09BE9F80, 4):
    off = psp_to_offset(addr)
    v_off = read_u32(data_off, off)
    v_on = read_u32(data_on, off)
    diff = " <<<< DIFF" if v_off != v_on else ""
    print(f"  0x{addr:08X}: OFF=0x{v_off:08X}  ON=0x{v_on:08X}{diff}")

# Also look for code that references 0x09BE9F5C
# It might be accessed as an offset from a base pointer
# Common pattern: lui $reg, 0x09BF; lw/sw $reg2, offset($reg)
# 0x09BE9F5C relative to 0x09BF0000 = -0x60A4 = 0x9F5C (signed: -24740)
# Or relative to 0x09BE0000 = 0x9F5C
print(f"\n0x09BE9F5C = 0x09BF0000 + (-0x60A4) = lui 0x09BF, offset 0x9F5C")
print(f"0x09BE9F5C = 0x09BE0000 + 0x9F5C")

# Search eboot for references to offset 0x9F5C with lui 0x09BF
# lw/sw rt, -0x60A4(rs) where rs was loaded with 0x09BF via lui
# The immediate would be 0x9F5C (signed = -24740)
print(f"\n=== Searching for 0x9F5C offset in overlay code (0x09D50000-0x09D70000) ===")
for addr in range(0x09D50000, 0x09D70000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_on): break
    instr = read_u32(data_on, off)
    imm = instr & 0xFFFF
    if imm == 0x9F5C:
        op = instr >> 26
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        if op in [0x23, 0x20, 0x24, 0x21, 0x25]:  # lw, lb, lbu, lh, lhu
            ops = {0x23:'lw', 0x20:'lb', 0x24:'lbu', 0x21:'lh', 0x25:'lhu'}
            print(f"  0x{addr:08X}: {ops[op]} {REGS[rt]}, 0x9F5C({REGS[rs]})")
        elif op in [0x2B, 0x28, 0x29]:  # sw, sb, sh
            ops = {0x2B:'sw', 0x28:'sb', 0x29:'sh'}
            print(f"  0x{addr:08X}: {ops[op]} {REGS[rt]}, 0x9F5C({REGS[rs]})")
        elif op == 0x09:  # addiu
            print(f"  0x{addr:08X}: addiu {REGS[rt]}, {REGS[rs]}, 0x9F5C")
        else:
            print(f"  0x{addr:08X}: op=0x{op:02X} with imm 0x9F5C")

# Also check: what's at the $fp-relative addresses used in the overlay rendering?
# The item selector jal at 0x09D63D54 uses $fp. Let me check $fp-relative loads nearby
print(f"\n=== $fp-relative loads near 0x09D63D54 (item selector area) ===")
for addr in range(0x09D63C00, 0x09D63F00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_on): break
    instr = read_u32(data_on, off)
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    if rs == 30:  # $fp
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        simm = imm if imm < 0x8000 else imm - 0x10000
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        if op == 0x23:
            print(f"  0x{addr:08X}: lw {REGS[rt]}, {simm}($fp)  [0x{imm:04X}]")
        elif op == 0x20:
            print(f"  0x{addr:08X}: lb {REGS[rt]}, {simm}($fp)  [0x{imm:04X}]")
        elif op == 0x24:
            print(f"  0x{addr:08X}: lbu {REGS[rt]}, {simm}($fp)  [0x{imm:04X}]")

print("\nDone!")
