#!/usr/bin/env python3
"""Dump the area around 0x08901310 to find what function it's in."""

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
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Scan backwards from 0x08901310 to find function prologue
print("=== Scanning backwards from 0x08901310 for function start ===")
for addr in range(0x08901310, 0x089011C0, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    simm = instr & 0xFFFF
    if simm >= 0x8000: simm -= 0x10000
    # Function prologue: addiu $sp, $sp, -N
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        print(f"  FOUND prologue at 0x{addr:08X}: addiu $sp, $sp, {simm}")
    if "jr" in disasm(instr, addr) and "$ra" in disasm(instr, addr):
        print(f"  FOUND return at 0x{addr:08X}: {disasm(instr, addr)}")

# Dump 0x089011C0 to 0x08901400 (everything after sprite render)
print("\n=== 0x089011C4 - 0x08901400 (past sprite render, includes 0x08901310) ===")
func_start = None
for addr in range(0x089011C4, 0x08901400, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if addr == 0x08901310:
        marker = " <<<< HUD CAVE HOOK POINT"
    if addr == 0x08901314:
        marker = " <<<< HUD CAVE HOOK (NOP'd)"
    # Track stack ops
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    simm = instr & 0xFFFF
    if simm >= 0x8000: simm -= 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        marker += f" *** FUNC START (frame={-simm}) ***"
        func_start = addr
    if "$sp" in d and ("sw " in d or "lw " in d):
        marker += " [STACK]"
    if "$ra" in d:
        marker += " [RA]"
    if "$a3" in d:
        marker += " [a3_X]"
    if "$t0" in d:
        marker += " [t0_Y]"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        marker += f" [CALL -> 0x{target:08X}]"
    if "jr $ra" in d:
        marker += " [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Now dump the HP bar rendering function in the overlay
# Looking for what calls 0x08901310-area functions for HP bars
# Let's trace from the HP bar area - 0x09D61558 and 0x09D61838
print("\n\n=== 0x09D61500-0x09D61840 (HP bar overlay rendering) ===")
for addr in range(0x09D61500, 0x09D61840, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        marker += f" [CALL -> 0x{target:08X}]"
    if "$a3" in d:
        marker += " [a3]"
    if "$t0" in d:
        marker += " [t0]"
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    simm = instr & 0xFFFF
    if simm >= 0x8000: simm -= 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        marker += f" *** FUNC START (frame={-simm}) ***"
    if "jr $ra" in d:
        marker += " [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

print("\nDone!")
