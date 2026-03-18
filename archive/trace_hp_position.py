#!/usr/bin/env python3
"""Find where HP bar screen position is determined.
The bar render calls are at 0x09D61490-0x09D616A0.
Need to find the parent function and trace how position is set up."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

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
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11: return f"cop1 raw=0x{instr:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Search backwards from 0x09D61400 for a function prologue
print("=== Searching for function prologue before 0x09D61400 ===")
for addr in range(0x09D61400, 0x09D61000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Prologue at 0x{addr:08X}: addiu $sp, $sp, {simm}")
            # Dump from prologue to first bar call
            print(f"\n=== Function from 0x{addr:08X} to first bar call ===")
            for a2 in range(addr, 0x09D614A0, 4):
                o2 = psp_to_offset(a2)
                i2 = read_u32(data, o2)
                d2 = disasm(i2, a2)
                m2 = ""
                if "jal " in d2 and "jalr" not in d2:
                    target = (i2 & 0x03FFFFFF) << 2
                    m2 = f" [-> 0x{target:08X}]"
                if "$s0" in d2 or "$s1" in d2 or "$s2" in d2 or "$s3" in d2:
                    m2 += " [Sx]"
                print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
            break

# Also: let's look at what 0x08900B7C does with position
# This is the innermost render function. Let's dump its first ~40 instructions
print(f"\n=== 0x08900B7C (inner render function) ===")
for addr in range(0x08900B7C, 0x08900B7C + 300, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jr $ra" in d:
        m = " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
        break
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [-> 0x{target:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Search for where bar_scale 0x09DA93A0 is loaded in the rendering chain
# lui $reg, 0x09DB followed by lwc1/lw at offset 0x93A0
print(f"\n=== References to bar scale area (lui 0x09DB) near HP bar rendering ===")
for addr in range(0x08900000, 0x08910000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x0F and imm == 0x09DB:  # lui $reg, 0x09DB
        rt = (instr >> 16) & 0x1F
        print(f"  0x{addr:08X}: lui {REGS[rt]}, 0x09DB")
        # Check next few instructions for 0x93A0 offset
        for i in range(1, 6):
            na = addr + i * 4
            no = psp_to_offset(na)
            ni = read_u32(data, no)
            nd = disasm(ni, na)
            nim = ni & 0xFFFF
            if nim == 0x93A0 or nim == 0x93A4:
                print(f"    0x{na:08X}: {nd}  <<<< BAR SCALE ACCESS")
            else:
                print(f"    0x{na:08X}: {nd}")

# Also search in overlay for bar scale access
for addr in range(0x09D61000, 0x09D62000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x0F and imm == 0x09DB:
        rt = (instr >> 16) & 0x1F
        print(f"  0x{addr:08X}: lui {REGS[rt]}, 0x09DB (overlay)")
        for i in range(1, 6):
            na = addr + i * 4
            no = psp_to_offset(na)
            ni = read_u32(data, no)
            nd = disasm(ni, na)
            nim = ni & 0xFFFF
            if nim == 0x93A0 or nim == 0x93A4:
                print(f"    0x{na:08X}: {nd}  <<<< BAR SCALE ACCESS")
            else:
                print(f"    0x{na:08X}: {nd}")

# Look for the HP bar parent: who calls the function containing 0x09D61490?
# To find the function address, I need to determine where the function starts
# and search for callers of that function
print(f"\n=== Looking for who calls into the HP bar area ===")
# Check: is there a jr $ra between 0x09D61300 and 0x09D61400? (end of previous func)
for addr in range(0x09D61300, 0x09D61410, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    if "jr $ra" in d or ("addiu $sp, $sp" in d and "addiu $sp, $sp, -" not in d):
        print(f"  0x{addr:08X}: {d}")

print("\nDone!")
