#!/usr/bin/env python3
"""Dump eboot function 0x08901168 to understand how it uses X/Y from layout entries,
and check if $a2/$a3/$t0 can be used as offsets."""

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
        return f"special func=0x{func:02X}"
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

# Dump 0x08901168 (sprite render function in eboot)
print("=== EBOOT FUNCTION 0x08901168 (sprite renderer) ===")
print("Called with: $a0=context, $a1=entry_ptr, $a2=0?, $a3=0?, $t0=0?")
for addr in range(0x08901168, 0x08901400, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    # Highlight reads from $a1 (entry pointer)
    if "($a1)" in d: marker = " <<< ENTRY READ"
    # Highlight reads at offset 24/26
    if "24(" in d or "26(" in d: marker = " <<< X/Y?"
    if "18(" in d or "1a(" in d: marker += " <<< offset 24/26?"
    print(f"  0x{addr:08X}: {d}{marker}")

# Also check how the X/Y from entries is used
# Look for the function that entry 2 and 3 entries point to
# entry 2: starts at 0x09D92CF8
# Let me also check calls with non-zero $a2/$a3
print("\n\n=== CALLS TO 0x08901168 WITH NON-ZERO ARGS ===")
overlay_start = psp_to_offset(0x09C57C80)
overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)
target_jal = (0x03 << 26) | (0x08901168 >> 2)
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if instr == target_jal:
        addr = off - MEM_OFFSET + PSP_BASE
        # Check what $a2, $a3, $t0 are set to before this call
        # Look back up to 10 instructions for addiu to $a2, $a3, $t0
        a2_val = "?"
        a3_val = "?"
        t0_val = "?"
        for k in range(1, 15):
            prev_off = off - k * 4
            if prev_off >= overlay_start:
                pi = read_u32(data, prev_off)
                pop = pi >> 26
                if pop == 0x09:  # addiu
                    prt = (pi >> 16) & 0x1F
                    prs = (pi >> 21) & 0x1F
                    pimm = pi & 0xFFFF
                    psimm = pimm if pimm < 0x8000 else pimm - 0x10000
                    if prt == 6 and prs == 0: a2_val = str(psimm)  # $a2
                    if prt == 7 and prs == 0: a3_val = str(psimm)  # $a3
                    if prt == 8 and prs == 0: t0_val = str(psimm)  # $t0
                elif pop == 0:  # R-type
                    func = pi & 0x3F
                    if func == 0x21:  # addu
                        prd = (pi >> 11) & 0x1F
                        prs2 = (pi >> 21) & 0x1F
                        prt2 = (pi >> 16) & 0x1F
                        if prd == 6 and prs2 == 0 and prt2 == 0: a2_val = "0"
                        if prd == 7 and prs2 == 0 and prt2 == 0: a3_val = "0"
                        if prd == 8 and prs2 == 0 and prt2 == 0: t0_val = "0"
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jal 0x08901168  a2={a2_val} a3={a3_val} t0={t0_val}")

print("\nDone!")
