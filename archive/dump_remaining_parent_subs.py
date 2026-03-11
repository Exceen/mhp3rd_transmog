#!/usr/bin/env python3
"""Dump remaining parent sub-functions and find all JALR (indirect calls) in the overlay."""

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
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

RENDER_TARGETS = {
    0x08901168, 0x0890112C, 0x08901000, 0x088FF8F0,
    0x08900BF0, 0x08901C48, 0x089012D8
}

def dump_func_jals(start, max_len=0x600, label=""):
    """Dump only JAL/JALR and key instructions."""
    print(f"\n=== {label} ===")
    for addr in range(start, start + max_len, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        cw = addr - 0x08800000

        show = False
        marker = ""
        if "jal " in d and "jalr" not in d:
            show = True
            target = (instr & 0x03FFFFFF) << 2
            if target in RENDER_TARGETS:
                marker = " *** RENDER ***"
            elif 0x09C50000 <= target <= 0x09DA0000:
                marker = " [OVL]"
        if "jalr" in d:
            show = True
            marker = " *** INDIRECT ***"
        if "jr $ra" in d:
            show = True
            marker = " [RETURN]"
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
            break
        if show:
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Remaining parent subs
for func, name in [
    (0x09D6B53C, "PARENT_SUB_B53C"),
    (0x09D6B3F0, "PARENT_SUB_B3F0"),
    (0x09D643B0, "PARENT_SUB_43B0 (near own HP)"),
    (0x09D645FC, "PARENT_SUB_45FC (near own HP)"),
    (0x09D68040, "PARENT_SUB_8040"),
    (0x09D67AEC, "PARENT_SUB_7AEC"),
]:
    dump_func_jals(func, 0x600, name)

# Find ALL JALR in the player list rendering area (0x09D62000-0x09D64000)
print("\n\n=== ALL JALR (INDIRECT CALLS) IN PLAYER LIST AREA ===")
for addr in range(0x09D5E000, 0x09D70000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr >> 26 == 0 and (instr & 0x3F) == 0x09:  # JALR
        rs = (instr >> 21) & 0x1F
        rd = (instr >> 11) & 0x1F
        cw = addr - 0x08800000
        # Show context: what's loaded into the register being called
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jalr {REGS[rd]}, {REGS[rs]}")
        # Look back for the register load
        for k in range(1, 15):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            pi = read_u32(data, prev_off)
            pd = disasm(pi, prev)
            if REGS[rs] in pd and ("lw" in pd or "addiu" in pd or "lui" in pd or "addu" in pd):
                print(f"    -{k}: {pd}")
                break

print("\nDone!")
