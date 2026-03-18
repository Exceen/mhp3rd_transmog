#!/usr/bin/env python3
"""Focused analysis of the parent function's rendering section.

Key findings from trace_item_sel_state.py:
- $s2 = $a0 (parent object)
- $s3 = result of jal 0x088B51B8 (some check)
- $s5 = 0x09BF (lui)
- At 0x09D6C594: bgtz ($s2+8), 0x09D6C6E0
- At 0x09D6C624: beq $v0, $zero, 0x09D6C718

Now let's disassemble 0x09D6C6E0+ and 0x09D6C718+ to see the render dispatch.
Also trace what $s2 points to, and what fields control item selector state.
"""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE_CLOSED = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"
STATE_OPEN   = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"

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
        if func == 0x0A: return f"movz {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0B: return f"movn {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
        rt_v = rt
        if rt_v == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11: return f"cop1 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)
data = mem_c  # Code is same in both

# Dump 0x09D6C6E0 to 0x09D6CA00 (render section of parent)
print("=" * 70)
print("=== Parent function render section 0x09D6C650-0x09D6CA00 ===")
print("=" * 70)
for addr in range(0x09D6C650, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        m = f" [{loc} 0x{target:08X}]"
    if "jalr" in d:
        m = " [INDIRECT]"
    if "jr $ra" in d:
        m = " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
        # Don't break - might not be the final return
        continue
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Now figure out what $s2 points to.
# The function 0x09D6C498 is called with $a0 = parent object
# $s2 = $a0 at 0x09D6C4B8
# We need to find who calls 0x09D6C498

print("\n" + "=" * 70)
print("=== Finding callers of 0x09D6C498 ===")
print("=" * 70)
target_jal = 0x0C000000 | (0x09D6C498 >> 2)  # jal encoding
for addr in range(0x09C57C80, 0x09DE0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == target_jal:
        # Show context: what is $a0?
        print(f"  Found: jal 0x09D6C498 at 0x{addr:08X}")
        # Show 5 instructions before
        for delta in range(-20, 4, 4):
            a2 = addr + delta
            o2 = psp_to_offset(a2)
            i2 = read_u32(data, o2)
            d2 = disasm(i2, a2)
            mark = " <<<<" if delta == 0 else ""
            print(f"    0x{a2:08X}: {d2}{mark}")

# Also check: What about the $s2+0x180 field?
# At 0x09D6C53C: sb $v0, 384($s2) -- stores 1 to $s2+0x180
# This looks like a "rendering active" flag on the parent object
# Let's find the parent object address by checking the caller

# Also, let's look at the state machine function 0x09D6B53C which is called at 0x09D6C55C
# This gets ($s2, $s3) as args - $s2 is parent, $s3 is the check result
print("\n" + "=" * 70)
print("=== State machine 0x09D6B53C (called from parent) ===")
print("=" * 70)
for addr in range(0x09D6B53C, 0x09D6B53C + 400, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# What's at field $s2+0x180 in both states?
# First we need the parent object address. Let's check if $s5=0x09BF is used
# to load it. At 0x09D6C4D0: lw $a0, -20292($s5) = lw $a0, -0x4F44($s5)
# $s5 = 0x09BF0000, so loads from 0x09BF0000 - 0x4F44 = 0x09BEB0BC
# But that's the first arg to jal 0x088FA2B0, not the parent itself.
# The parent is $a0 = $s2, passed in. Let's find caller.

print("\n" + "=" * 70)
print("=== Checking key addresses in both states ===")
print("=" * 70)

# Also check: at 0x09D6C520: lw $v0, 2976($s3) = $s3+0xBA0
# $s3 is from jal 0x088B51B8 at 0x09D6C4F4
# And 0x09D6C524: andi $v0, $v0, 0x0001 -- bit flag check
# This controls whether rendering happens at all

# Let's look at what function 0x09D643B0 does (called at 0x09D6C5B4)
# This is ONE of the sub-render calls. Let's see if it deals with item selector.
print("\n" + "=" * 70)
print("=== Sub-render 0x09D643B0 (item selector render?) ===")
print("=" * 70)
for addr in range(0x09D643B0, 0x09D643B0 + 200, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# And 0x09D645FC (called at 0x09D6C5C4)
print("\n" + "=" * 70)
print("=== Sub-render 0x09D645FC ===")
print("=" * 70)
for addr in range(0x09D645FC, 0x09D645FC + 200, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
