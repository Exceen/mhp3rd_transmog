#!/usr/bin/env python3
"""Check key addresses in both save states to find the item selector flag.

Target addresses from code analysis:
1. 0x09BEE678 (object+4): blocking flag #1
2. 0x09BEF605 (object+0xB91): blocking flag #2
   0x0891F1CC returns 0 (allow render) when BOTH are 0

Also: find $s3 by checking 0x088B51B8's behavior, and check $s3+0xBA0 flags.

And: do a focused scan of the object at 0x09BEE674 (size ~0xC00) for differences.
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

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Check key addresses
print("=" * 70)
print("=== Key flag addresses ===")
print("=" * 70)

addrs = [
    ("0x09BEE678 (object+4, flag1)", 0x09BEE678),
    ("0x09BEF605 (object+0xB91, flag2)", 0x09BEF605),
    ("0x09BEF556 (object+0x8E2, from 0x08922370)", 0x09BEF556),
    ("0x09BEF557 (object+0x8E3, from 0x08922380)", 0x09BEF557),
]

for name, addr in addrs:
    off = psp_to_offset(addr)
    bc = mem_c[off]
    bo = mem_o[off]
    diff = " ***DIFFERENT***" if bc != bo else ""
    print(f"  {name}: CLOSED={bc}  OPEN={bo}{diff}")

# Scan entire object at 0x09BEE674 for byte differences (0→non-zero or non-zero→0)
print("\n" + "=" * 70)
print("=== Object 0x09BEE674 byte differences (size ~0xC00) ===")
print("=" * 70)
obj_base = 0x09BEE674
interesting = []
for off in range(0, 0xC00):
    addr = obj_base + off
    state_off = psp_to_offset(addr)
    if state_off >= len(mem_c) or state_off >= len(mem_o): break
    bc = mem_c[state_off]
    bo = mem_o[state_off]
    if bc != bo:
        interesting.append((off, addr, bc, bo))

print(f"  Total byte differences: {len(interesting)}")
print(f"\n  Differences where one value is 0 and other is 1-10:")
for off, addr, bc, bo in interesting:
    if (bc == 0 and 1 <= bo <= 10) or (bo == 0 and 1 <= bc <= 10):
        print(f"    +0x{off:03X} (0x{addr:08X}): CLOSED={bc}  OPEN={bo}")

print(f"\n  ALL differences:")
for off, addr, bc, bo in interesting:
    if abs(bc - bo) < 100:  # Skip large changes (likely pointers/floats)
        print(f"    +0x{off:03X} (0x{addr:08X}): CLOSED={bc}  OPEN={bo}")

# Now let's also try to find the $s3 object.
# At the parent function 0x09D6C498:
# 0x09D6C4E4: lw $a0, 31360($v1) where $v1 = 0x09BB0000 → *(0x09BB7A80)
# 0x09D6C4EC: lbu $a1, 38($a2) where $a2 = *(0x08AACE80)
# 0x09D6C4F0: addiu $a2, $zero, 1
# 0x09D6C4F4: jal 0x088B51B8
# Returns $s3

print("\n" + "=" * 70)
print("=== Finding $s3 (return of 0x088B51B8) ===")
print("=" * 70)

# Args to 0x088B51B8:
a0_ptr = 0x09BB7A80
a0_val_c = read_u32(mem_c, psp_to_offset(a0_ptr))
a0_val_o = read_u32(mem_o, psp_to_offset(a0_ptr))
print(f"  *(0x09BB7A80): CLOSED=0x{a0_val_c:08X}  OPEN=0x{a0_val_o:08X}")

a2_ptr = 0x08AACE80
a2_val = read_u32(mem_c, psp_to_offset(a2_ptr))
print(f"  *(0x08AACE80): 0x{a2_val:08X}")
if a2_val != 0:
    a1_off = psp_to_offset(a2_val + 38)
    if a1_off < len(mem_c):
        a1_val = mem_c[a1_off]
        print(f"  *(0x{a2_val:08X}+38) = $a1 = {a1_val}")

# Let's disassemble 0x088B51B8 to understand what it returns
print("\n  Disassembling 0x088B51B8:")
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
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"raw=0x{instr:08X}"

for addr in range(0x088B51B8, 0x088B51B8 + 100, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d: m = f" [CALL]"
    if "jr $ra" in d:
        print(f"    0x{addr:08X}: {d} [RETURN]")
        break
    print(f"    0x{addr:08X}: {d}{m}")

print("\nDone!")
