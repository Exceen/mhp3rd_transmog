#!/usr/bin/env python3
"""Trace gate function 0x09D627B4 with known $s3=0x09541310 in both states.

Disassemble the gate function and manually trace execution with actual memory values.
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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return data[off]

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

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

s3 = 0x09541310

# Disassemble 0x09D627B4 fully
print("=" * 70)
print("=== Gate function 0x09D627B4 ===")
print("=" * 70)
for addr in range(0x09D627B4, 0x09D627B4 + 400, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        m = f" [{loc} 0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Check all relevant bytes at $s3+0xBA0 area
print(f"\n{'='*70}")
print(f"=== $s3 (0x{s3:08X}) key offsets ===")
print(f"{'='*70}")

# Check individual bytes around 0xBA0
for off in range(0xB9E, 0xBA8):
    addr = s3 + off
    bc = read_u8(mem_c, psp_to_offset(addr))
    bo = read_u8(mem_o, psp_to_offset(addr))
    d = " ***" if bc != bo else ""
    print(f"  +0x{off:03X} (0x{addr:08X}): C=0x{bc:02X}  O=0x{bo:02X}{d}")

# Check halfwords
for off in [0xBA0, 0xBA2]:
    addr = s3 + off
    hc = read_u16(mem_c, psp_to_offset(addr))
    ho = read_u16(mem_o, psp_to_offset(addr))
    d = " ***" if hc != ho else ""
    print(f"  +0x{off:03X} (hw) (0x{addr:08X}): C=0x{hc:04X}  O=0x{ho:04X}{d}")
    print(f"    bit0={hc&1}/{ho&1} bit1={(hc>>1)&1}/{(ho>>1)&1} bit9={(hc>>9)&1}/{(ho>>9)&1}")

# Check word
wc = read_u32(mem_c, psp_to_offset(s3 + 0xBA0))
wo = read_u32(mem_o, psp_to_offset(s3 + 0xBA0))
print(f"  +0xBA0 (word): C=0x{wc:08X}  O=0x{wo:08X}")
print(f"    binary C: {wc:032b}")
print(f"    binary O: {wo:032b}")

# Check 0x18C area
print(f"\n  +0x18C area:")
for off in [0x18C, 0x18D, 0x18E, 0x18F]:
    addr = s3 + off
    bc = read_u8(mem_c, psp_to_offset(addr))
    bo = read_u8(mem_o, psp_to_offset(addr))
    d = " ***" if bc != bo else ""
    print(f"  +0x{off:03X} (0x{addr:08X}): C=0x{bc:02X}  O=0x{bo:02X}{d}")

hc = read_u16(mem_c, psp_to_offset(s3 + 0x18C))
ho = read_u16(mem_o, psp_to_offset(s3 + 0x18C))
print(f"  +0x18C (hw): C=0x{hc:04X}  O=0x{ho:04X}")

wc = read_u32(mem_c, psp_to_offset(s3 + 0x18C))
wo = read_u32(mem_o, psp_to_offset(s3 + 0x18C))
print(f"  +0x18C (word): C=0x{wc:08X}  O=0x{wo:08X}")

# Also check $s2. $s2 = first arg to 0x09D6C498 = $s5+0xC0 from caller
# The caller at 0x09C5ED88 does: addiu $a0, $s5, 192 (=0xC0)
# We need to find $s5. From the caller's caller...
# Let's check the $s2+0x180 area and also find $s2 from the save state.
# Actually $s2 should be on the stack or in a register at the save state point.
# Better approach: search for what address is passed to 0x09D627B4.
# From the parent 0x09D6C498: $s2 = $a0 (first arg), $s3 = result of jal 0x088B51B8

# Let's scan for the $s2 object by looking at what *(0x09BEE670) points to:
print(f"\n{'='*70}")
print(f"=== Finding $s2 (parent object) ===")
print(f"{'='*70}")
# $s2 = $a0 of 0x09D6C498
# Caller: 0x09C5ED88: jal 0x09D6C498 with $a0 = $s5 + 0xC0
# $s5 is set in that caller. Let's find it.
# Actually, we know *(0x09BEE670) = 0x09BEE674 from trace_item_sel_state3.py
# And the gate at 0x09D627B4 loads *(0x09BEE670) to get the arg for 0x0891F1CC.
# But $s2 is the first arg to the gate function. Let me check.

# Actually let me just look at the gate function code carefully.
# The gate gets ($a0=$s2, $a1=$s3). Let's trace through with both states.

# Dump wider area of $s3 for completeness
print(f"\n{'='*70}")
print(f"=== $s3 object scan for ALL byte differences ===")
print(f"{'='*70}")
diffs = []
for off in range(0, 0xC00):
    addr = s3 + off
    state_off = psp_to_offset(addr)
    if state_off + 1 > len(mem_c) or state_off + 1 > len(mem_o):
        break
    bc = mem_c[state_off]
    bo = mem_o[state_off]
    if bc != bo:
        diffs.append((off, addr, bc, bo))

print(f"Total byte differences in $s3 object (0xC00 bytes): {len(diffs)}")
for off, addr, bc, bo in diffs:
    print(f"  +0x{off:03X} (0x{addr:08X}): C=0x{bc:02X}  O=0x{bo:02X}")

print("\nDone!")
