#!/usr/bin/env python3
"""Disassemble the item selector render function 0x09D60998 to find
individual element render calls (text, background, icons, etc.)."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    return zstd.ZstdDecompressor().decompress(data[0xB0:], max_output_size=256*1024*1024)

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
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

print("Loading save state...")
data = load_state(STATE)

# Disassemble the item selector render function 0x09D60998
# This is a large function — dump up to 0x800 bytes (512 instructions)
print("=" * 70)
print("=== Item Selector Render Function 0x09D60998 ===")
print("=" * 70)

jal_targets = []
for addr in range(0x09D60998, 0x09D60998 + 0x800, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        m = f" [{loc}]"
        jal_targets.append((addr, target, loc))
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print(f"\n{'='*70}")
print(f"=== All jal calls from render function ===")
print(f"{'='*70}")
for callsite, target, loc in jal_targets:
    print(f"  0x{callsite:08X}: jal 0x{target:08X} [{loc}]")

# Known render functions for reference
known = {
    0x08901168: "SPRITE_RENDER (X/Y offset mechanism)",
    0x088FF1F0: "SPRITE_BASE_RENDER",
    0x088FFF0C: "HP_BAR_RENDER",
    0x0884C6E0: "RENDER_MODE_FUNC",
    0x0890112C: "SPRITE_112C",
}

print(f"\n{'='*70}")
print(f"=== Known function matches ===")
print(f"{'='*70}")
for callsite, target, loc in jal_targets:
    if target in known:
        print(f"  0x{callsite:08X}: jal 0x{target:08X} = {known[target]}")

# Also check sub-functions called from within the render function
# The render function likely calls overlay sub-functions that do the actual drawing
print(f"\n{'='*70}")
print(f"=== Overlay sub-functions (potential element renderers) ===")
print(f"{'='*70}")
overlay_targets = set()
for callsite, target, loc in jal_targets:
    if loc == "OVERLAY" and target not in overlay_targets:
        overlay_targets.add(target)
        # Disassemble first 30 instructions of each sub-function
        print(f"\n--- Sub-function 0x{target:08X} (called from 0x{callsite:08X}) ---")
        for sa in range(target, target + 120, 4):
            soff = psp_to_offset(sa)
            si = read_u32(data, soff)
            sd = disasm(si, sa)
            sm = ""
            if "jal " in sd and "jalr" not in sd:
                st = (si & 0x03FFFFFF) << 2
                if st in known:
                    sm = f" [{known[st]}]"
                else:
                    sl = "EBOOT" if st < 0x09000000 else "OVERLAY"
                    sm = f" [{sl}]"
            if "jr $ra" in sd:
                print(f"    0x{sa:08X}: 0x{si:08X}  {sd} [RETURN]")
                break
            print(f"    0x{sa:08X}: 0x{si:08X}  {sd}{sm}")

print("\nDone!")
