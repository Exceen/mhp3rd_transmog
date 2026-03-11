#!/usr/bin/env python3
"""Check if 0x09D6380C calls sprite render (0x08901168/0x089012D8/0x08901000)
internally, which would explain why background doesn't move.
Also dump 0x09D62B30 to see what the second per-player loop does."""

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

known_funcs = {
    0x08901168: "SPRITE_RENDER",
    0x089012D8: "RENDER_12D8",
    0x08901000: "SPRITE_RENDER2",
    0x088E7008: "CURSOR_SET",
    0x088FF1F0: "SPRITE_CORE",
    0x08901C48: "RENDER_1C48",
}

# Dump 0x09D6380C (names/icons renderer) - just the JAL instructions
print("=== 0x09D6380C RENDER CALLS ===")
for addr in range(0x09D6380C, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        name = known_funcs.get(target, "")
        if not name and 0x088E0000 <= target <= 0x08920000:
            name = f"EBOOT:{target:08X}"
        elif not name and 0x09D50000 <= target <= 0x09DA0000:
            name = f"OVL:{target:08X}"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}  [{name}]")
    elif "jr $ra" in d:
        print(f"  0x{addr:08X}: jr $ra [END OF FUNCTION?]")

# Find all calls to 0x08901168 within 0x09D6380C
print("\n\n=== SPRITE RENDER (0x08901168) CALLS IN 0x09D6380C ===")
target_jal = (0x03 << 26) | (0x08901168 >> 2)
for addr in range(0x09D6380C, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == target_jal:
        cw = addr - 0x08800000
        # Look at nearby instructions to see what $a1 is set to
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jal 0x08901168")
        for k in range(1, 10):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            pi = read_u32(data, prev_off)
            pd = disasm(pi, prev)
            if "$a1" in pd or "$a3" in pd or "$t0" in pd:
                print(f"    -{k}: 0x{prev:08X}: {pd}")

# Also check 0x089012D8 calls
print("\n\n=== RENDER_12D8 (0x089012D8) CALLS IN 0x09D6380C ===")
target_jal2 = (0x03 << 26) | (0x089012D8 >> 2)
for addr in range(0x09D6380C, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == target_jal2:
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jal 0x089012D8")
        for k in range(1, 10):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            pi = read_u32(data, prev_off)
            pd = disasm(pi, prev)
            if "$a0" in pd or "$a1" in pd:
                print(f"    -{k}: 0x{prev:08X}: {pd}")

# Also check 0x08901000 calls
print("\n\n=== SPRITE_RENDER2 (0x08901000) CALLS IN 0x09D6380C ===")
target_jal3 = (0x03 << 26) | (0x08901000 >> 2)
for addr in range(0x09D6380C, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == target_jal3:
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jal 0x08901000")

# Now dump 0x09D62B30 (second per-player loop function)
print("\n\n=== 0x09D62B30 (second per-player loop) ===")
for addr in range(0x09D62B30, 0x09D62F00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in known_funcs:
            marker = f" [{known_funcs[target]}]"
        elif 0x088E0000 <= target <= 0x08920000:
            marker = f" [EBOOT:{target:08X}]"
        elif 0x09D50000 <= target <= 0x09DA0000:
            marker = f" [OVL:{target:08X}]"
    if "24(" in d or "26(" in d:
        marker += " <<< X/Y?"
    if "jr $ra" in d:
        marker = " [RETURN]"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
        break
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Dump the full 0x09D6380C with ALL instructions for the part that uses $s4/$s5 and calls renders
print("\n\n=== 0x09D6380C FULL DUMP (0x09D63900-0x09D63C00) ===")
print("Focus on the X/Y computation and render calls")
for addr in range(0x09D63900, 0x09D63C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "$s4" in d: marker += " [X_REG]"
    if "$s5" in d: marker += " [Y_REG]"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target in known_funcs:
            marker += f" [{known_funcs[target]}]"
        elif 0x088E0000 <= target <= 0x08920000:
            marker += f" [EBOOT:{target:08X}]"
    if "($a2)" in d: marker += " [ENTRY_READ]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

print("\nDone!")
