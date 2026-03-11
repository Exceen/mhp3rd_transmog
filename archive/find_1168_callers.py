#!/usr/bin/env python3
"""Find all callers of jal 0x08901168 (SPRITE_1168) in the entire memory space."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

MIPS_REG_NAMES = {
    0: "$zero", 1: "$at", 2: "$v0", 3: "$v1",
    4: "$a0", 5: "$a1", 6: "$a2", 7: "$a3",
    8: "$t0", 9: "$t1", 10: "$t2", 11: "$t3",
    12: "$t4", 13: "$t5", 14: "$t6", 15: "$t7",
    16: "$s0", 17: "$s1", 18: "$s2", 19: "$s3",
    20: "$s4", 21: "$s5", 22: "$s6", 23: "$s7",
    24: "$t8", 25: "$t9", 26: "$k0", 27: "$k1",
    28: "$gp", 29: "$sp", 30: "$fp", 31: "$ra",
}

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    if off + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, off)[0]

def disasm_simple(instr, addr):
    """Simple MIPS disassembler for common instructions."""
    op = (instr >> 26) & 0x3F
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    shamt = (instr >> 6) & 0x1F
    funct = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    rn = MIPS_REG_NAMES

    if instr == 0:
        return "nop"

    if op == 0:  # R-type
        if funct == 0x21:  # addu
            return f"addu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x25:  # or
            if rt == 0:
                return f"move {rn[rd]}, {rn[rs]}"
            return f"or {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x08:  # jr
            return f"jr {rn[rs]}"
        elif funct == 0x00:  # sll
            return f"sll {rn[rd]}, {rn[rt]}, {shamt}"
        elif funct == 0x02:  # srl
            return f"srl {rn[rd]}, {rn[rt]}, {shamt}"
        elif funct == 0x03:  # sra
            return f"sra {rn[rd]}, {rn[rt]}, {shamt}"
        elif funct == 0x2A:  # slt
            return f"slt {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x2B:  # sltu
            return f"sltu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x23:  # subu
            return f"subu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x24:  # and
            return f"and {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x26:  # xor
            return f"xor {rn[rd]}, {rn[rs]}, {rn[rt]}"
        elif funct == 0x09:  # jalr
            return f"jalr {rn[rd]}, {rn[rs]}"
        return f"R-type funct=0x{funct:02X} {rn[rd]},{rn[rs]},{rn[rt]}"
    elif op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        return f"jal 0x{target:08X}"
    elif op == 0x02:  # j
        target = (instr & 0x03FFFFFF) << 2
        return f"j 0x{target:08X}"
    elif op == 0x09:  # addiu
        return f"addiu {rn[rt]}, {rn[rs]}, {simm}"
    elif op == 0x0D:  # ori
        return f"ori {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    elif op == 0x0F:  # lui
        return f"lui {rn[rt]}, 0x{imm:04X}"
    elif op == 0x0C:  # andi
        return f"andi {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    elif op == 0x0A:  # slti
        return f"slti {rn[rt]}, {rn[rs]}, {simm}"
    elif op == 0x0B:  # sltiu
        return f"sltiu {rn[rt]}, {rn[rs]}, {simm}"
    elif op == 0x23:  # lw
        return f"lw {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x25:  # lhu
        return f"lhu {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x21:  # lh
        return f"lh {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x20:  # lb
        return f"lb {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x24:  # lbu
        return f"lbu {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x2B:  # sw
        return f"sw {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x29:  # sh
        return f"sh {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x28:  # sb
        return f"sb {rn[rt]}, {simm}({rn[rs]})"
    elif op == 0x04:  # beq
        target = addr + 4 + (simm << 2)
        return f"beq {rn[rs]}, {rn[rt]}, 0x{target:08X}"
    elif op == 0x05:  # bne
        target = addr + 4 + (simm << 2)
        return f"bne {rn[rs]}, {rn[rt]}, 0x{target:08X}"
    elif op == 0x01:  # regimm
        if rt == 0x01:  # bgez
            target = addr + 4 + (simm << 2)
            return f"bgez {rn[rs]}, 0x{target:08X}"
        elif rt == 0x11:  # bgezal
            target = addr + 4 + (simm << 2)
            return f"bgezal {rn[rs]}, 0x{target:08X}"
        elif rt == 0x00:  # bltz
            target = addr + 4 + (simm << 2)
            return f"bltz {rn[rs]}, 0x{target:08X}"
    elif op == 0x06:  # blez
        target = addr + 4 + (simm << 2)
        return f"blez {rn[rs]}, 0x{target:08X}"
    elif op == 0x07:  # bgtz
        target = addr + 4 + (simm << 2)
        return f"bgtz {rn[rs]}, 0x{target:08X}"

    return f"??? (0x{instr:08X})"


def classify_region(addr):
    if 0x08800000 <= addr < 0x08A00000:
        return "EBOOT"
    elif 0x09C00000 <= addr < 0x09E00000:
        return "OVERLAY"
    elif 0x08000000 <= addr < 0x08800000:
        return "LOW_MEM"
    elif 0x09000000 <= addr < 0x09C00000:
        return "HEAP/DATA"
    else:
        return "OTHER"


print("Loading and decompressing save state...")
data = decompress_ppst(PPST_FILE)
print(f"Decompressed size: {len(data)} bytes")
print()

# Target: jal 0x08901168
TARGET_ADDR = 0x08901168
jal_opcode = 0x0C000000 | (TARGET_ADDR >> 2)
print(f"Target function: 0x{TARGET_ADDR:08X}")
print(f"JAL encoding:    0x{jal_opcode:08X}")
print()

# Search the entire memory space
# PSP user memory: 0x08000000 to 0x0A000000 (32 MB)
callers = []
search_start = 0x08000000
search_end = 0x0A000000

print(f"Searching 0x{search_start:08X} - 0x{search_end:08X} for jal 0x{TARGET_ADDR:08X}...")

for addr in range(search_start, search_end, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    if instr == jal_opcode:
        callers.append(addr)

print(f"\nFound {len(callers)} callers:\n")

for caller in callers:
    cw_offset = caller - 0x08800000
    region = classify_region(caller)
    print(f"{'='*70}")
    print(f"CALLER: 0x{caller:08X}  CW: 0x{cw_offset:07X}  Region: {region}")
    print(f"{'='*70}")

    # Dump 10 instructions before + the jal + delay slot
    for i in range(-10, 2):
        iaddr = caller + i * 4
        off = psp_to_offset(iaddr)
        instr = read_u32(data, off)
        if instr is None:
            continue
        marker = " >>>" if i == 0 else "    "
        dis = disasm_simple(instr, iaddr)
        print(f"{marker} 0x{iaddr:08X}: 0x{instr:08X}  {dis}")
    print()

# Also search for J (jump) instructions (tail calls)
j_opcode = 0x08000000 | (TARGET_ADDR >> 2)
print(f"\n{'='*70}")
print(f"Searching for J (tail call) 0x{j_opcode:08X} to 0x{TARGET_ADDR:08X}...")
print(f"{'='*70}")

j_callers = []
for addr in range(search_start, search_end, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    if instr == j_opcode:
        j_callers.append(addr)

if j_callers:
    print(f"\nFound {len(j_callers)} tail-call jumps:\n")
    for caller in j_callers:
        cw_offset = caller - 0x08800000
        region = classify_region(caller)
        print(f"  J from 0x{caller:08X}  CW: 0x{cw_offset:07X}  Region: {region}")
else:
    print("\nNo tail-call jumps found.")

print("\nDone!")
