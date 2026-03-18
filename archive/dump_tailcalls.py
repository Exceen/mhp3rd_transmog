#!/usr/bin/env python3
"""Dump context around the j 0x088FFF0C tail call sites."""

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
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# 1. Function containing 0x089012B0
print("=== Function containing j 0x088FFF0C at 0x089012B0 ===")
# Scan back for prologue
for probe in range(0x089012B0, 0x089012B0 - 0x200, -4):
    off = psp_to_offset(probe)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Function starts at 0x{probe:08X} (frame={-simm})")
            for addr in range(probe, 0x089012D8, 4):
                off2 = psp_to_offset(addr)
                i2 = read_u32(data, off2)
                d = disasm(i2, addr)
                m = ""
                if addr == 0x089012B0: m = " <<<< TAIL CALL to 0x088FFF0C"
                if "jr $ra" in d: m += " [RETURN]"
                print(f"  0x{addr:08X}: 0x{i2:08X}  {d}{m}")
            break

# 2. Overlay tail calls - dump the functions
print("\n=== Overlay functions with j 0x088FFF0C ===")
overlay_j_sites = [0x09D60024, 0x09D600A8, 0x09D60170, 0x09D601C8]
# Find the containing function
for probe in range(0x09D60024, 0x09D5FF00, -4):
    off = psp_to_offset(probe)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            func_start = probe
            print(f"\n  Function starts at 0x{probe:08X} (frame={-simm})")
            for addr in range(probe, probe + 0x300, 4):
                off2 = psp_to_offset(addr)
                i2 = read_u32(data, off2)
                d = disasm(i2, addr)
                m = ""
                if addr in overlay_j_sites: m = " <<<< TAIL CALL to 0x088FFF0C"
                if "jr $ra" in d:
                    m += " [RETURN]"
                    print(f"  0x{addr:08X}: 0x{i2:08X}  {d}{m}")
                    break
                print(f"  0x{addr:08X}: 0x{i2:08X}  {d}{m}")
            break

# 3. Now find callers of the eboot function at 0x089012B0's parent
# It's a wrapper that tail-calls 0x088FFF0C, similar to how code goes through vtables
# Let's find all callers of whatever function contains 0x089012B0

print("\n\n=== Now find callers of the function containing 0x089012B0 ===")
# Already found function start above, let's also search for jal/j to it
# The function containing 0x089012B0 - scan back for it
func_addr = None
for probe in range(0x089012B0, 0x089012B0 - 0x200, -4):
    off = psp_to_offset(probe)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            func_addr = probe
            break

if func_addr:
    print(f"  Function at 0x{func_addr:08X}")
    # Search for jal to this function
    jal_instr = (0x03 << 26) | (func_addr >> 2)
    j_instr = (0x02 << 26) | (func_addr >> 2)
    print(f"  Looking for jal/j 0x{func_addr:08X}...")
    for addr in range(0x08800000, 0x08A00000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_instr:
            print(f"    EBOOT 0x{addr:08X}: jal 0x{func_addr:08X}")
        elif instr == j_instr:
            print(f"    EBOOT 0x{addr:08X}: j 0x{func_addr:08X}")
    for addr in range(0x09C50000, 0x09E00000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_instr:
            print(f"    OVERLAY 0x{addr:08X}: jal 0x{func_addr:08X}")
        elif instr == j_instr:
            print(f"    OVERLAY 0x{addr:08X}: j 0x{func_addr:08X}")

    # Also search for function pointer
    print(f"  Looking for 0x{func_addr:08X} as stored value...")
    for addr in range(0x08800000, 0x0A000000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        val = read_u32(data, off)
        if val == func_addr:
            print(f"    Found at 0x{addr:08X}")

print("\nDone!")
