#!/usr/bin/env python3
"""Dump function 0x09D627B4 — the item selector visibility check."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        return zstd.ZstdDecompressor().decompress(f.read(), max_output_size=64*1024*1024)

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
    target = (instr & 0x03FFFFFF) << 2
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
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0A: return f"movz {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0B: return f"movn {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X}"
    if op == 0x01:
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        return f"regimm rt=0x{rt:02X}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

print("=== Function 0x09D627B4 (item selector active check) ===")
for addr in range(0x09D627B4, 0x09D627B4 + 0x100, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}")
    if "jr $ra" in d:
        # Print delay slot
        addr2 = addr + 4
        off2 = psp_to_offset(addr2)
        instr2 = read_u32(data, off2)
        print(f"  0x{addr2:08X}: 0x{instr2:08X}  {disasm(instr2, addr2)}")
        print()
        # Check if there's more (function may have multiple return points)
        # Continue for a bit more to catch all paths
        # But stop if we hit a new prologue
        next_off = psp_to_offset(addr2 + 4)
        next_instr = read_u32(data, next_off)
        next_op = next_instr >> 26
        next_rs = (next_instr >> 21) & 0x1F
        next_rt = (next_instr >> 16) & 0x1F
        next_simm = next_instr & 0xFFFF
        if next_simm >= 0x8000: next_simm -= 0x10000
        if next_op == 0x09 and next_rs == 29 and next_rt == 29 and next_simm < 0:
            print(f"  (next function starts at 0x{addr2+4:08X})")
            break

# Also check what $s2 (the "self" pointer) fields contain
# The parent passes $a0=$s2, $a1=$s3 to this function
# $s2 is the HUD object, $s3 comes from 0x088B51B8 return value

# Let's check the value at the call site:
# At 0x09D6C7D0: addu $a0, $s2, $zero
# At 0x09D6C7D4: addu $a1, $s3, $zero
# $s3 was set at 0x09D6C4FC: addu $s3, $v0, $zero (from jal 0x088B51B8)
# $s3+0xBA0 is used in the item sel state flag code cave

print("\nDone!")
