#!/usr/bin/env python3
"""Dump the function at 0x09D6380C that renders each player list entry."""

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

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    sa = (instr >> 6) & 0x1F
    func = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x18: return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        if func == 0x04: return f"sllv {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
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
    if op == 0x04:
        target = addr + 4 + (simm << 2)
        return f"beq {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x05:
        target = addr + 4 + (simm << 2)
        return f"bne {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x06:
        target = addr + 4 + (simm << 2)
        return f"blez {REGS[rs]}, 0x{target:08X}"
    if op == 0x07:
        target = addr + 4 + (simm << 2)
        return f"bgtz {REGS[rs]}, 0x{target:08X}"
    if op == 0x01:
        if rt == 0x01:
            target = addr + 4 + (simm << 2)
            return f"bgez {REGS[rs]}, 0x{target:08X}"
        if rt == 0x00:
            target = addr + 4 + (simm << 2)
            return f"bltz {REGS[rs]}, 0x{target:08X}"
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        return f"jal 0x{target:08X}"
    if op == 0x02:
        target = (instr & 0x03FFFFFF) << 2
        return f"j 0x{target:08X}"
    if op == 0x1F:
        return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Dump function at 0x09D6380C
print("=== FUNCTION AT 0x09D6380C (player list entry renderer) ===")
# Called with: $a0=main_struct, $a1=player_data_ptr, $a2=loop_index
for addr in range(0x09D6380C, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if addr == 0x09D6392C: marker = " <<< Y from table"
    elif addr == 0x09D63930: marker = " <<< X from table"
    elif addr == 0x09D639EC: marker = " <<< X = tableX + offset"
    elif addr == 0x09D639F8: marker = " <<< Y = tableY + offset"
    elif addr == 0x09D63A10: marker = " <<< cursor setter"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {instr:08X}  {d}{marker}")

# Also dump what gets called at 0x09D669CC which populates the entries
# From the main function, this is called with $a0=$s2, $a1=$s2+12
print("\n\n=== FUNCTION AT 0x09D669CC (layout table populator?) ===")
for addr in range(0x09D669CC, 0x09D66C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    # Look for stores to offset 24/26 (X/Y)
    if "sh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y STORE?"
    if "sw" in d and "24(" in d:
        marker = " <<< XY STORE?"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {instr:08X}  {d}{marker}")

print("\nDone!")
