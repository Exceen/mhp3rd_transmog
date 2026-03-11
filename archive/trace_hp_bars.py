#!/usr/bin/env python3
"""Comprehensive HP bar tracing using save state slot 4."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

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
    0x0890112C: "SPRITE_112C",
    0x08901000: "SPRITE_1000",
    0x08901168: "SPRITE_1168",
    0x089012D8: "RENDER_12D8",
    0x088FF8F0: "SPRITE_F8F0",
    0x08901C48: "BAR_1C48",
    0x08900BF0: "BG_BF0",
    0x088FFF0C: "SPRITE_FF0C",
}

# 1. Dump 0x09D61AEC (pre-render loop function)
print("=== 0x09D61AEC PRE-RENDER LOOP FUNCTION ===")
for addr in range(0x09D61AEC, 0x09D61F84, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = " [OVL]"
    if "jalr" in d: marker = " [INDIRECT]"
    print(f"  0x{addr:08X}: {d}{marker}")
    if "jr $ra" in d:
        break

# 2. Try to find HUD structure - search multiple potential global pointers
print("\n\n=== SEARCHING FOR HUD STRUCTURE ===")
# Known globals from lui instructions in the parent function
potential_globals = [
    (0x09BAE670, "lui 0x09BB, -6544"),
    (0x09BAE674, "lui 0x09BB, -6540"),
    (0x09BAE678, "lui 0x09BB, -6536"),
]

for gaddr, desc in potential_globals:
    off = psp_to_offset(gaddr)
    if off + 4 <= len(data):
        val = read_u32(data, off)
        print(f"  0x{gaddr:08X} ({desc}): 0x{val:08X}")

# 3. Search for the HUD struct by looking at what $s2 gets set to in the parent
# The parent 0x09D6C498 sets $s2 early on. Let's trace it.
print("\n\n=== TRACING $s2 IN PARENT 0x09D6C498 ===")
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    # Show instructions that set $s2 or use offset 384
    if "$s2" in d or "384" in d or "0x180" in d.lower():
        print(f"  0x{addr:08X}: {d}")

# 4. Look at the FULL LOOP2 (0x09D62B30) dump with annotations
print("\n\n=== 0x09D62B30 LOOP2 FULL DUMP (SLOT 4) ===")
for addr in range(0x09D62B30, 0x09D62E00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jalr" in d: marker = " *** INDIRECT CALL ***"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [OVL:0x{target:08X}]"
    print(f"  0x{addr:08X}: {d}{marker}")
    if "jr $ra" in d:
        break

# 5. Search overlay for ALL function pointers that could be in vtables
# Look for pointers to functions that call render funcs
print("\n\n=== SEARCHING OVERLAY DATA FOR VTABLE FUNCTION POINTERS ===")
# First, find all functions that contain render calls
render_callers = set()
for addr in range(0x09C57C80, 0x09DA0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr >> 26 != 0x03: continue
    target = (instr & 0x03FFFFFF) << 2
    if target in RENDER_FUNCS:
        # Find function start by scanning back for prologue
        for k in range(1, 500):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            if prev_off < 0: break
            pi = read_u32(data, prev_off)
            pop = pi >> 26; prt = (pi >> 16) & 0x1F; prs = (pi >> 21) & 0x1F
            if pop == 0x09 and prs == 29 and prt == 29 and (pi & 0xFFFF) >= 0x8000:
                render_callers.add(prev)
                break

print(f"Found {len(render_callers)} functions that call render funcs:")
for fc in sorted(render_callers):
    print(f"  0x{fc:08X}")

# Now search overlay data area AND heap area for pointers to these functions
print("\n\nSearching for vtable entries pointing to render-calling functions...")
# Search a wider area: overlay data + heap
search_ranges = [
    (0x09D70000, 0x09DA0000, "overlay data"),
    (0x09900000, 0x09C00000, "heap area"),
]
for start, end, label in search_ranges:
    found = []
    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        val = read_u32(data, off)
        if val in render_callers:
            found.append((addr, val))
    if found:
        print(f"\n  In {label} (0x{start:08X}-0x{end:08X}):")
        for addr, val in found[:50]:  # limit output
            # Show surrounding entries (likely vtable)
            print(f"    0x{addr:08X}: 0x{val:08X}")
            # Show a few entries around it
            for delta in [-8, -4, 4, 8]:
                noff = psp_to_offset(addr + delta)
                if noff + 4 <= len(data):
                    nval = read_u32(data, noff)
                    tag = ""
                    if nval in render_callers: tag = " [RENDER CALLER]"
                    elif 0x09C50000 <= nval <= 0x09DA0000: tag = " [OVL]"
                    if tag:
                        print(f"      0x{addr+delta:08X}: 0x{nval:08X}{tag}")

# 6. Try an entirely different approach: search for where BAR_1C48 is called
# in the context of LOOP3, and dump LOOP3 fully
print("\n\n=== 0x09D6309C LOOP3 FULL DUMP ===")
for addr in range(0x09D6309C, 0x09D63400, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [OVL:0x{target:08X}]"
    if "jalr" in d: marker = " [INDIRECT]"
    print(f"  0x{addr:08X}: {d}{marker}")
    if "jr $ra" in d:
        break

# 7. Also dump what 0x09D627B4 does (called in player list path)
print("\n\n=== 0x09D627B4 CHECK FUNCTION ===")
for addr in range(0x09D627B4, 0x09D62B30, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS: marker = f" [{RENDER_FUNCS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000: marker = f" [OVL:0x{target:08X}]"
    if "jalr" in d: marker = " [INDIRECT]"
    print(f"  0x{addr:08X}: {d}{marker}")
    if "jr $ra" in d:
        break

print("\nDone!")
