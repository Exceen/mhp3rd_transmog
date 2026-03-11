#!/usr/bin/env python3
"""Dump item selector function 0x09D60D88 fully, including conditional paths."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
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
    if off + 4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

RENDER_FUNCS = {
    0x0890112C: "SPRITE_112C",
    0x08901000: "SPRITE_1000",
    0x08901168: "SPRITE_1168",
    0x089012D8: "RENDER_12D8",
    0x088FF8F0: "SPRITE_F8F0",
    0x08901C48: "BAR_1C48",
    0x08900BF0: "BG_BF0",
    0x088FFF0C: "SPRITE_FF0C",
}

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
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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

# Dump full function including all paths
print("=== ITEM SELECTOR FUNCTION 0x09D60D88 (full) ===")
for addr in range(0x09D60D88, 0x09D610B8, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [OVL:0x{target:08X}]"
        elif 0x08800000 <= target <= 0x08A00000: marker = f" [EBOOT:0x{target:08X}]"
    if "jalr" in d: marker = " [INDIRECT]"
    if "j 0x" in d and "jal" not in d and "jr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [TAIL:{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [TAIL_OVL:0x{target:08X}]"
    cw = addr - 0x08800000
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also dump the sub-functions it calls
print("\n\n=== SUB-FUNCTIONS CALLED ===")

# 0x09D60660 - has BG_BF0 + SPRITE_FF0C calls
print("\n--- 0x09D60660 (BG_BF0 + SPRITE_FF0C) ---")
for addr in range(0x09D60660, 0x09D609A4, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [OVL:0x{target:08X}]"
        elif 0x08800000 <= target <= 0x08A00000: marker = f" [EBOOT:0x{target:08X}]"
    if "jalr" in d: marker = " [INDIRECT]"
    if "j 0x" in d and "jal" not in d and "jr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [TAIL:{RENDER_FUNCS[target]}]"
    cw = addr - 0x08800000
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also list all the $t1/$t2 setup addresses before each BG_BF0 call in 0x09D60D88
print("\n\n=== BG_BF0 CALL PARAMETERS IN 0x09D60D88 ===")
for addr in range(0x09D60D88, 0x09D60F30, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    if "jal 0x08900BF0" in d:
        # Look back for $t1 and $t2 setup
        for back in range(1, 8):
            ba = addr - back * 4
            bo = psp_to_offset(ba)
            bi = read_u32(data, bo)
            bd = disasm(bi, ba)
            if "$t1" in bd or "$t2" in bd:
                cw = ba - 0x08800000
                print(f"  0x{ba:08X} (CW 0x{cw:07X}): {bd}")
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d} [BG_BF0]")
        print()

print("\nDone!")
