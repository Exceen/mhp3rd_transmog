#!/usr/bin/env python3
"""Trace HP bar $a1 setup and sharpness patch context."""

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
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# 1. Dump context before each HP bar 0x08904570 call in the 0x09D61400 area
# to see how $a1 is set up
jal_bar = 0x0C000000 | (0x08904570 >> 2)
print("=== $a1 setup before each HP bar call (0x09D61400-0x09D61700) ===")
bar_calls = [0x09D61490, 0x09D614DC, 0x09D61528, 0x09D61574,
             0x09D615C0, 0x09D6160C, 0x09D616A0]
for call_addr in bar_calls:
    print(f"\n  --- Before call at 0x{call_addr:08X} ---")
    for addr in range(call_addr - 40, call_addr + 8, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        m = ""
        if addr == call_addr: m = " <<<< BAR RENDER CALL"
        if "$a1" in d: m += " [A1]"
        if "$a3" in d: m += " [A3]"
        if "$t0" in d: m += " [T0]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# 2. Dump the sharpness patch area - full function
print("\n\n=== Sharpness overlay area - scanning from 0x09D5E900 ===")
for addr in range(0x09D5E900, 0x09D5EB40, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    sharpness_addrs = [0x09D5EAD0, 0x09D5EAF4, 0x09D5E9EC, 0x09D5E9F0,
                       0x09D5EA20, 0x09D5EA24, 0x09D5EA48, 0x09D5EA4C,
                       0x09D5EA7C, 0x09D5EA80]
    if addr in sharpness_addrs: m = " <<<< SHARPNESS PATCH"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m += f" [-> 0x{target:08X}]"
    if "$a3" in d: m += " [A3]"
    if "$t0" in d: m += " [T0]"
    # Detect function prologue/epilogue
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            m += f" *** FUNC START (frame={-simm}) ***"
    if "jr $ra" in d: m += " [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# 3. Look at 0x0890112C — the function that 0x08904570 calls
# This is the actual low-level bar render. Let's see what args it takes.
print("\n\n=== 0x0890112C (low-level bar render called by 0x08904570) ===")
for addr in range(0x0890112C, 0x0890112C + 64, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jr $ra" in d:
        m = " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# 4. What is the $a1 data structure? 0x08904570 reads 0($a1), 2($a1), 4($a1), 6($a1)
# These are sprite coordinates. The $a1 comes from the overlay caller.
# In the HP bar area, let's see how $a1 is computed
# Let's find the function prologue for the HP bar area
print("\n\n=== Finding HP bar function prologue ===")
for addr in range(0x09D61490, 0x09D61300, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            func_start = addr
            print(f"  HP bar function starts at 0x{addr:08X}: frame={-simm}")
            # Dump the prologue and the first section to see $a1 setup
            for a2 in range(addr, addr + 0x1A0, 4):
                o2 = psp_to_offset(a2)
                i2 = read_u32(data, o2)
                d2 = disasm(i2, a2)
                m2 = ""
                if i2 == jal_bar: m2 = " <<<< BAR RENDER"
                if "$a1" in d2: m2 += " [A1]"
                print(f"  0x{a2:08X}: 0x{i2:08X}  {d2}{m2}")
            break

print("\nDone!")
