#!/usr/bin/env python3
"""Find what dispatches to 0x09D6C978 (item selector render case).
This is likely part of a switch-case in the parent function 0x09D6C498."""

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
        return f"special func=0x{func:02X}"
    if op == 0x01:
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
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

# Find all branches/jumps in 0x09D6C498-0x09D6CA00 that target 0x09D6C978
print("=== Branches/jumps targeting 0x09D6C978 (item sel case) ===")
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    simm = (instr & 0xFFFF)
    if simm >= 0x8000: simm -= 0x10000

    if op in [0x04, 0x05, 0x06, 0x07]:  # beq, bne, blez, bgtz
        branch_target = addr + 4 + (simm << 2)
        if branch_target == 0x09D6C978:
            print(f"  0x{addr:08X}: {disasm(instr, addr)}")
    elif op == 0x01:  # bltz, bgez
        rt = (instr >> 16) & 0x1F
        if rt in [0x00, 0x01]:
            branch_target = addr + 4 + (simm << 2)
            if branch_target == 0x09D6C978:
                print(f"  0x{addr:08X}: {disasm(instr, addr)}")
    elif op == 0x02:  # j
        target = (instr & 0x03FFFFFF) << 2
        if target == 0x09D6C978:
            print(f"  0x{addr:08X}: {disasm(instr, addr)}")

# Also look for jr-based dispatch (jump table)
# jr $XX where $XX is loaded from a table
# Search for jr instructions
print("\n=== jr instructions in parent function ===")
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if (instr >> 26) == 0 and (instr & 0x3F) == 0x08:
        rs = (instr >> 21) & 0x1F
        if rs != 31:  # not jr $ra
            print(f"  0x{addr:08X}: {disasm(instr, addr)}")
            # Show 5 instructions before
            for ctx in range(addr - 20, addr, 4):
                ctx_off = psp_to_offset(ctx)
                ctx_instr = read_u32(data, ctx_off)
                print(f"    0x{ctx:08X}: {disasm(ctx_instr, ctx)}")

# Dump the full function from 0x09D6C498 to understand the dispatch
print("\n=== Full dump 0x09D6C498-0x09D6C560 (function start) ===")
for addr in range(0x09D6C498, 0x09D6C560, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {disasm(instr, addr)}")

# Continue: dump 0x09D6C560-0x09D6C660
print("\n=== Dump 0x09D6C560-0x09D6C660 ===")
for addr in range(0x09D6C560, 0x09D6C660, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {disasm(instr, addr)}")

# Dump 0x09D6C660-0x09D6C760
print("\n=== Dump 0x09D6C660-0x09D6C760 ===")
for addr in range(0x09D6C660, 0x09D6C760, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {disasm(instr, addr)}")

# Dump 0x09D6C760-0x09D6C830
print("\n=== Dump 0x09D6C760-0x09D6C830 ===")
for addr in range(0x09D6C760, 0x09D6C830, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {disasm(instr, addr)}")

print("\nDone!")
