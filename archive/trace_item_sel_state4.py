#!/usr/bin/env python3
"""Trace the actual item selector gate function 0x09D627B4.

Flow in the parent:
1. During quest, $s2+0x180 is forced to 1 (clock + player list always render)
2. At 0x09D6C7D0: jal 0x09D627B4($s2, $s3)
3. If returns non-zero → go to 0x09D6C978 (extra item selector render)
4. Then continues to render clock + player list either way

So 0x09D627B4 is THE function that checks whether the item selector is active.
Let's disassemble it and find what state it reads.

Also: check byte at 0x09BEF556 in both states, and the parent object address.
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
        rt_v = rt
        if rt_v == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
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

# First check: byte at 0x09BEF556 in both states
for name, mem in [("CLOSED", mem_c), ("OPEN", mem_o)]:
    off = psp_to_offset(0x09BEF556)
    val = mem[off]
    val2 = mem[off+1]  # Also check +0x8E3
    print(f"  Byte at 0x09BEF556 ({name}): {val}")
    print(f"  Byte at 0x09BEF557 ({name}): {val2}")

# Disassemble 0x09D627B4 — the item selector gate function
print(f"\n{'='*70}")
print(f"=== Item selector gate 0x09D627B4 ===")
print(f"{'='*70}")
data = mem_c
for addr in range(0x09D627B4, 0x09D627B4 + 300, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
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

# Also disassemble 0x09D69938 and 0x09D60D88 (the extra item selector render calls)
print(f"\n{'='*70}")
print(f"=== Extra render 0x09D69938 ===")
print(f"{'='*70}")
for addr in range(0x09D69938, 0x09D69938 + 200, 4):
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

# Now find the parent object address.
# The caller of 0x09D6C498 is at 0x09C5EC18.
# $s5 = $a0 of the caller's caller. Let's find that caller.
print(f"\n{'='*70}")
print(f"=== Finding caller of 0x09C5EC18 ===")
print(f"{'='*70}")
target_jal = 0x0C000000 | (0x09C5EC18 >> 2)
for addr in range(0x09C57C80, 0x09DE0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == target_jal:
        print(f"  Found: jal 0x09C5EC18 at 0x{addr:08X}")
        for delta in range(-28, 8, 4):
            a2 = addr + delta
            o2 = psp_to_offset(a2)
            i2 = read_u32(data, o2)
            d2 = disasm(i2, a2)
            mark = " <<<<" if delta == 0 else ""
            print(f"    0x{a2:08X}: {d2}{mark}")

# Also check if we can find the parent object by searching for known patterns.
# The parent object at $s5+0xC0 has: +0x180 = flag byte, +0x716 = state byte
# Let's look at the state machine state ($s3+0x716) in both saves
# We need $s3 = $s2 = parent object address first.

# Alternative approach: just check 0x09D627B4 return value and find what it reads.
# That's the actual gate function.

# Also check: what does jal 0x09D62384 do at 0x09D6C720?
# It's called right before the $s2+0x180 check.
print(f"\n{'='*70}")
print(f"=== Init function 0x09D62384 ===")
print(f"{'='*70}")
for addr in range(0x09D62384, 0x09D62384 + 200, 4):
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
