#!/usr/bin/env python3
"""Dump EBOOT function 0x08905F20 and its subcalls."""

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
        if func == 0x19: return f"multu {REGS[rs]}, {REGS[rt]}"
        if func == 0x1A: return f"div {REGS[rs]}, {REGS[rt]}"
        if func == 0x1B: return f"divu {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        if func == 0x26: return f"xor {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x27: return f"nor {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x04: return f"sllv {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
        if func == 0x06: return f"srlv {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
        if func == 0x07: return f"srav {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
        if func == 0x0A: return f"movz {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0B: return f"movn {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
        if rt == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x10: return f"bltzal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11:  # COP1
        if rs == 0x10:  # fmt=S
            if func == 0x00: return f"add.s $f{sa}, $f{rd}, $f{rt}"  # fd=sa area, fs=rd area
            if func == 0x01: return f"sub.s $f{(instr>>6)&0x1F}, $f{rd}, $f{rt}"
            if func == 0x02: return f"mul.s $f{(instr>>6)&0x1F}, $f{rd}, $f{rt}"
            if func == 0x03: return f"div.s $f{(instr>>6)&0x1F}, $f{rd}, $f{rt}"
            if func == 0x06: return f"mov.s $f{(instr>>6)&0x1F}, $f{rd}"
            if func == 0x24: return f"cvt.w.s $f{(instr>>6)&0x1F}, $f{rd}"
            if func == 0x0D: return f"trunc.w.s $f{(instr>>6)&0x1F}, $f{rd}"
            return f"cop1.s func=0x{func:02X} raw=0x{instr:08X}"
        if rs == 0x14:  # fmt=W
            if func == 0x20: return f"cvt.s.w $f{(instr>>6)&0x1F}, $f{rd}"
            return f"cop1.w func=0x{func:02X} raw=0x{instr:08X}"
        if rs == 0x04: return f"mtc1 {REGS[rt]}, $f{rd}"
        if rs == 0x00: return f"mfc1 {REGS[rt]}, $f{rd}"
        if rs == 0x08:
            if rt == 0x01: return f"bc1t 0x{addr + 4 + (simm << 2):08X}"
            if rt == 0x00: return f"bc1f 0x{addr + 4 + (simm << 2):08X}"
        return f"cop1 rs=0x{rs:02X} raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

RENDER_FUNCS = {
    0x08901168: "SPRITE_1168($a3=X,$t0=Y)",
    0x0890112C: "SPRITE_112C($t0=X,$t1=Y)",
    0x08901000: "SPRITE_1000($t0=X,$t1=Y)",
    0x089012D8: "RENDER_12D8",
    0x088FF8F0: "SPRITE_F8F0($t0=X,$t1=Y)",
    0x08901C48: "BAR_1C48",
    0x08900BF0: "BG_BF0($t1=X,$t2=Y)",
    0x088FFF0C: "SPRITE_FF0C",
}

def annotate_target(target):
    """Return annotation string for a call/jump target."""
    if target in RENDER_FUNCS:
        return f" [{RENDER_FUNCS[target]}]"
    if 0x09C50000 <= target <= 0x09DA0000:
        return f" [OVERLAY]"
    if 0x08800000 <= target <= 0x08A00000:
        return f" [EBOOT]"
    return ""

def dump_func(start, max_end, title, jr_limit=2):
    """Dump a function, stopping after jr_limit 'jr $ra' instructions.
    Returns set of jal targets found."""
    print(f"\n{'='*70}")
    print(f"=== {title} ===")
    print(f"{'='*70}")
    jr_count = 0
    targets = set()
    for addr in range(start, max_end, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data):
            break
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""
        if "jal " in d and "jalr" not in d:
            target = (instr & 0x03FFFFFF) << 2
            targets.add(target)
            marker = annotate_target(target)
        if "jalr" in d:
            marker = " [INDIRECT]"
        if d.startswith("j ") or (d.startswith("j 0x") and "jal" not in d):
            target = (instr & 0x03FFFFFF) << 2
            marker = annotate_target(target)
            if target in RENDER_FUNCS:
                marker = f" [TAIL:{RENDER_FUNCS[target]}]"
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
        if "jr $ra" in d:
            jr_count += 1
            if jr_count >= jr_limit:
                break
    return targets

# Phase 1: Dump the main function
print("MAIN FUNCTION: 0x08905F20")
main_targets = dump_func(0x08905F20, 0x08906500, "MAIN: 0x08905F20 (CW 0x105F20)", jr_limit=2)

# Phase 2: Dump subcalls that are NOT already-known render functions
# Only dump EBOOT-range subcalls that aren't in our known set
subcall_targets = set()
for t in sorted(main_targets):
    if t in RENDER_FUNCS:
        continue  # already annotated, skip full dump
    if 0x08800000 <= t <= 0x08A00000:
        sub_targets = dump_func(t, t + 0x800, f"SUBCALL: 0x{t:08X} (CW 0x{t - 0x08800000:07X})", jr_limit=2)
        subcall_targets.update(sub_targets)
    elif 0x09C50000 <= t <= 0x09DA0000:
        sub_targets = dump_func(t, t + 0x800, f"OVERLAY SUBCALL: 0x{t:08X}", jr_limit=2)
        subcall_targets.update(sub_targets)

# Phase 3: Dump 2nd-level subcalls (that aren't already dumped or known)
already_dumped = main_targets | RENDER_FUNCS.keys()
for t in sorted(subcall_targets):
    if t in already_dumped or t in RENDER_FUNCS:
        continue
    if 0x08800000 <= t <= 0x08A00000:
        dump_func(t, t + 0x400, f"SUB-SUBCALL: 0x{t:08X} (CW 0x{t - 0x08800000:07X})", jr_limit=2)
    elif 0x09C50000 <= t <= 0x09DA0000:
        dump_func(t, t + 0x400, f"OVERLAY SUB-SUBCALL: 0x{t:08X}", jr_limit=2)

print("\nDone!")
