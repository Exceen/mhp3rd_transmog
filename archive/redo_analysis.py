#!/usr/bin/env python3
"""Redo HP bar analysis using save state slot 4 (which has overlay loaded)."""

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

RENDER_FUNCS = {
    0x0890112C: "SPRITE_112C($t0=X,$t1=Y)",
    0x08901000: "SPRITE_1000($t0=X,$t1=Y)",
    0x08901168: "SPRITE_1168",
    0x089012D8: "RENDER_12D8",
    0x088FF8F0: "SPRITE_F8F0",
    0x08901C48: "BAR_1C48",
    0x08900BF0: "BG_BF0($t1=X,$t2=Y)",
    0x088FFF0C: "SPRITE_FF0C",
}

# 1. Scan ALL render calls in the overlay
print("=== ALL RENDER CALLS IN OVERLAY (SLOT 4) ===")
OVL_START = 0x09C57C80
OVL_END = 0x09DA0000

jal_opcodes = {}
for target in RENDER_FUNCS:
    jal_opcodes[target] = (0x03 << 26) | (target >> 2)

calls_by_func = {t: [] for t in RENDER_FUNCS}
for addr in range(OVL_START, OVL_END, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr >> 26 != 0x03: continue
    target = (instr & 0x03FFFFFF) << 2
    if target in RENDER_FUNCS:
        calls_by_func[target].append(addr)

for target, addrs in sorted(calls_by_func.items()):
    if not addrs:
        continue
    print(f"\n--- {RENDER_FUNCS[target]} (0x{target:08X}) : {len(addrs)} calls ---")
    for addr in addrs:
        cw = addr - 0x08800000
        # Check $t0 setting before call
        t0_info = ""
        for k in range(1, 12):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            if prev_off < 0: break
            pi = read_u32(data, prev_off)
            pop = pi >> 26; prt = (pi >> 16) & 0x1F; prd = (pi >> 11) & 0x1F; pfunc = pi & 0x3F
            if pop == 0 and pfunc == 0x21 and prd == 8 and (pi >> 21) & 0x1F == 0 and prt == 0:
                t0_info = f" $t0=0 @0x{prev:08X}"
                break
            elif pop == 0x09 and prt == 8:
                simm = (pi & 0xFFFF) if (pi & 0xFFFF) < 0x8000 else (pi & 0xFFFF) - 0x10000
                t0_info = f" $t0=addiu {simm} @0x{prev:08X}"
                break
            elif pop == 0 and pfunc == 0x21 and prd == 8:
                prs = (pi >> 21) & 0x1F
                t0_info = f" $t0=addu {REGS[prs]},{REGS[prt]} @0x{prev:08X}"
                break
            if pop in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x01):
                break
        print(f"  0x{addr:08X} (CW 0x{cw:07X}){t0_info}")

# 2. Dump the parent HUD function and orchestrator
print("\n\n=== PARENT HUD 0x09D6C498 (SLOT 4) ===")
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS:
            marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000:
            marker = " [OVL]"
    if "jalr" in d: marker = " [INDIRECT]"
    if marker or "jr $ra" in d:
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
    if "jr $ra" in d:
        break

# 3. Dump 0x09D62B30 (PER_PLAYER_LOOP2)
print("\n\n=== 0x09D62B30 PER_PLAYER_LOOP2 (SLOT 4) ===")
for addr in range(0x09D62B30, 0x09D62E00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = " [OVL]"
    if "jalr" in d: marker = " [INDIRECT]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
    if "jr $ra" in d:
        break

# 4. Dump 0x09D6309C (PER_PLAYER_LOOP3)
print("\n\n=== 0x09D6309C PER_PLAYER_LOOP3 (SLOT 4) ===")
for addr in range(0x09D6309C, 0x09D63400, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = " [OVL]"
    if "jalr" in d: marker = " [INDIRECT]"
    if marker or "jr $ra" in d or "$t0" in d or "$t1" in d:
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
    if "jr $ra" in d:
        break

print("\nDone!")
