#!/usr/bin/env python3
"""Trace the HP/stamina bar rendering in the overlay to find position control.
HP bars use 0x08904570 (not 0x08901168). We need to find the overlay code
that calls 0x08904570 and sets up the X/Y positions passed to it."""

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
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x18: return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x01:
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# First, understand 0x08904570 calling convention
# Dump the function entry to see what args it uses
print("=== 0x08904570 (bar render function) - first 60 instructions ===")
for addr in range(0x08904570, 0x08904570 + 240, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jr $ra" in d:
        marker = " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Find callers of 0x08904570 near 0x09D61800 (the known HP bar area)
print("\n=== Callers of 0x08904570 near HP bar area 0x09D61700-0x09D61900 ===")
jal_target = 0x0C000000 | (0x08904570 >> 2)
for addr in range(0x09D61700, 0x09D61900, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_target:
        print(f"  0x{addr:08X}: jal 0x08904570")

# Dump the full function containing these callers
# Find the function prologue by scanning back from 0x09D61700
print("\n=== Finding function containing HP bar calls ===")
func_start = None
for addr in range(0x09D61800, 0x09D61400, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:  # addiu
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            func_start = addr
            print(f"  Function starts at 0x{addr:08X}: addiu $sp, $sp, {simm}")
            break

if func_start:
    # Dump the full function, focusing on $a3/$t0 setup before jal 0x08904570
    print(f"\n=== Full function from 0x{func_start:08X} (HP bar rendering) ===")
    for addr in range(func_start, func_start + 0x400, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""
        if instr == jal_target:
            marker = " <<<< CALLS BAR RENDER"
        elif "$a3" in d or "$t0" in d:
            marker = " [a3/t0]"
        if "jr $ra" in d:
            marker += " [RETURN]"
            print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")
            break
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Also check the HP bar render from 0x09D61830 - maybe that's inside a different function
print("\n=== Looking for function containing 0x09D61830 ===")
for addr in range(0x09D61830, 0x09D61600, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Function at 0x{addr:08X}: addiu $sp, $sp, {simm}")
            # Dump around the call site
            print(f"\n=== Context around 0x09D61830 (HP bar caller) ===")
            for a2 in range(addr, addr + 0x200, 4):
                o2 = psp_to_offset(a2)
                if o2 + 4 > len(data): break
                i2 = read_u32(data, o2)
                d2 = disasm(i2, a2)
                m2 = ""
                if i2 == jal_target:
                    m2 = " <<<< CALLS BAR RENDER"
                elif "$a3" in d2 or "$t0" in d2:
                    m2 = " [a3/t0]"
                if "jal " in d2 and "jalr" not in d2:
                    target = (i2 & 0x03FFFFFF) << 2
                    m2 += f" [CALL -> 0x{target:08X}]"
                if a2 == 0x09D61830:
                    m2 += " <<<< CAVE RETURN ADDR"
                if "jr $ra" in d2:
                    m2 += " [RETURN]"
                    print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
                    break
                print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
            break

# Also check: what does the sharpness overlay rendering look like?
# The working sharpness patches are at overlay addrs like 0x09D5EAD0
# Let's dump the function around that area to understand the pattern
print("\n\n=== Sharpness overlay rendering (around 0x09D5E9E0) ===")
for addr in range(0x09D5E9D0, 0x09D5E9D0 - 0x100, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Sharpness function at 0x{addr:08X}: addiu $sp, $sp, {simm}")
            for a2 in range(addr, addr + 0x200, 4):
                o2 = psp_to_offset(a2)
                if o2 + 4 > len(data): break
                i2 = read_u32(data, o2)
                d2 = disasm(i2, a2)
                m2 = ""
                if a2 in [0x09D5EAD0, 0x09D5EAF4, 0x09D5E9EC, 0x09D5E9F0,
                          0x09D5EA20, 0x09D5EA24, 0x09D5EA48, 0x09D5EA4C,
                          0x09D5EA7C, 0x09D5EA80]:
                    m2 = " <<<< SHARPNESS PATCH ADDR"
                if "$a3" in d2 or "$t0" in d2:
                    m2 += " [a3/t0]"
                if "jal " in d2 and "jalr" not in d2:
                    target = (i2 & 0x03FFFFFF) << 2
                    m2 += f" [CALL -> 0x{target:08X}]"
                if "jr $ra" in d2:
                    m2 += " [RETURN]"
                    print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
                    break
                print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
            break

print("\nDone!")
