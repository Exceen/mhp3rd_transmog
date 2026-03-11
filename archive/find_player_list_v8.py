#!/usr/bin/env python3
"""Trace the player list rendering code to find X/Y position instructions to patch."""

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
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Dump the function at 0x09D6C90C (the loop caller that reads layout table)
# and its callee where X/Y are loaded from the table
print("=== FUNCTION AT 0x09D6C90C (layout table iterator) ===")
# Find function start
for addr in range(0x09D6C90C, 0x09D6C000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if (instr >> 16) == 0x27BD and (instr & 0xFFFF) >= 0x8000:
        func_start = addr
        break

print(f"Function starts at 0x{func_start:08X}")
for addr in range(func_start, func_start + 300*4, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <== X/Y LOAD?"
    if "addiu" in d and "$zero" in d:
        marker += " [CONST]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Now find what CALLS 0x09D6C90C
print("\n\n=== CALLERS OF THE LAYOUT TABLE ITERATOR ===")
# Search for JAL 0x09D6C90C in overlay
target_jal = (0x03 << 26) | (0x09D6C90C >> 2)
overlay_start = psp_to_offset(0x09C57C80)
overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if instr == target_jal:
        caller = off - MEM_OFFSET + PSP_BASE
        cw = caller - 0x08800000
        print(f"  JAL at 0x{caller:08X} (CW 0x{cw:07X})")

# Now also look for the function that the iterator calls (the one that reads X/Y from entries)
# From v4 analysis, X was loaded via lh $s4, 24($a2) and Y via lh $s5, 26($a2)
# Let me search for these exact instructions
print("\n\n=== SEARCH FOR lh $s4, 24($a2) AND lh $s5, 26($a2) ===")
# lh $s4, 24($a2) = op=0x21, rt=$s4(20), rs=$a2(6), imm=24
instr_lh_s4_24 = (0x21 << 26) | (6 << 21) | (20 << 16) | 24
# lh $s5, 26($a2) = op=0x21, rt=$s5(21), rs=$a2(6), imm=26
instr_lh_s5_26 = (0x21 << 26) | (6 << 21) | (21 << 16) | 26

for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if instr == instr_lh_s4_24 or instr == instr_lh_s5_26:
        addr = off - MEM_OFFSET + PSP_BASE
        cw = addr - 0x08800000
        d = disasm(instr, addr)
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}")

# Also search more broadly for any lh from offset 24 or 26 of any register
print("\n\n=== ANY lh *, 24(*) or lh *, 26(*) IN OVERLAY NEAR RENDER CALLS ===")
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x21:  # lh
        imm = instr & 0xFFFF
        if imm in (24, 26):
            addr = off - MEM_OFFSET + PSP_BASE
            rs = (instr >> 21) & 0x1F
            rt = (instr >> 16) & 0x1F
            # Check for JAL nearby
            has_render = False
            for k in range(-15, 15):
                noff = off + k * 4
                if overlay_start <= noff < overlay_end:
                    ni = read_u32(data, noff)
                    if (ni >> 26) == 0x03:
                        target = (ni & 0x03FFFFFF) << 2
                        if 0x088E0000 <= target <= 0x08910000:
                            has_render = True
                            break
                        if 0x09C50000 <= target <= 0x09DC0000:
                            has_render = True
                            break
            if has_render:
                cw = addr - 0x08800000
                d = disasm(instr, addr)
                print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}")

# Dump the function called by the iterator (from v4: it was around 0x09D63A10 area)
# Actually let's look for where $s4/$s5 are used after loading X/Y
# The cursor setter at 0x088E7008 sets cursor X/Y: sh $a2, 0x122($a0); sh $a1, 0x120($a0)
# So we need to find where $s4/$s5 are passed as $a1/$a2 to the cursor setter

print("\n\n=== SEARCH FOR JAL 0x088E7008 (cursor setter) IN OVERLAY ===")
target_cursor = (0x03 << 26) | (0x088E7008 >> 2)
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if instr == target_cursor:
        addr = off - MEM_OFFSET + PSP_BASE
        cw = addr - 0x08800000
        # Dump context around it
        print(f"\n  Call at 0x{addr:08X} (CW 0x{cw:07X}):")
        for k in range(-10, 10):
            a = addr + k * 4
            o = psp_to_offset(a)
            if o + 4 <= len(data):
                i = read_u32(data, o)
                d = disasm(i, a)
                marker = " <<<" if k == 0 else ""
                print(f"    0x{a:08X}: {d}{marker}")

# Broader: find where SH writes to offset 0x120 or 0x122 in overlay
print("\n\n=== SH to +0x120/+0x122 (cursor X/Y writes) IN OVERLAY ===")
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x29:  # sh
        imm = instr & 0xFFFF
        if imm in (0x120, 0x122):
            addr = off - MEM_OFFSET + PSP_BASE
            rs = (instr >> 21) & 0x1F
            rt = (instr >> 16) & 0x1F
            cw = addr - 0x08800000
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): sh {REGS[rt]}, 0x{imm:X}({REGS[rs]})")

print("\nDone!")
