#!/usr/bin/env python3
"""Find the $s3 object address and check its flags.

$s3 = return value of jal 0x088B51B8($a0=*(0x09BB7A80), $a1=0, $a2=1)
The gate function 0x09D627B4 checks $s3+0xBA0 for bits that control item selector.

Also: disassemble 0x088B51B8 fully (including the $a2==1 path at 0x088B520C).
Then check $s3+0x18C and $s3+0xBA0 in both states.
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
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} rd={REGS[rd]} rs={REGS[rs]} rt={REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
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
    return f"raw=0x{instr:08X}"

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Disassemble 0x088B51B8 fully
print("=" * 70)
print("=== 0x088B51B8 full disassembly ===")
print("=" * 70)
seen_returns = 0
for addr in range(0x088B51B8, 0x088B5280, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jr $ra" in d:
        m = " [RETURN]"
        seen_returns += 1
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
    if seen_returns >= 3:
        break

# Now trace the execution with known args:
# $a0 = *(0x09BB7A80) = 0x09BB7A84
# $a1 = 0
# $a2 = 1
print("\n" + "=" * 70)
print("=== Manual trace of 0x088B51B8($a0=0x09BB7A84, $a1=0, $a2=1) ===")
print("=" * 70)

a0 = 0x09BB7A84  # *(0x09BB7A80) from save state
a1 = 0
a2 = 1

# Instruction by instruction:
# 0x088B51B8: addiu $sp, $sp, -16
# 0x088B51BC: 0x2CA20006 = sltiu $v0, $a1, 6 → sltiu(0, 6) = 1 (0 < 6)
v0 = 1
print(f"  sltiu $v0, $a1(={a1}), 6 → $v0 = {v0}")

# 0x088B51C4: andi $a2, $a2, 0x00FF → a2 = 1 & 0xFF = 1
a2_masked = a2 & 0xFF
print(f"  andi $a2, $a2, 0xFF → $a2 = {a2_masked}")

# $s1 = $a0 = 0x09BB7A84
s1 = a0
print(f"  $s1 = $a0 = 0x{s1:08X}")

# 0x088B51D4: beq $v0, $zero, 0x088B5224 → v0=1, not taken
print(f"  beq $v0(={v0}), $zero → NOT taken")

# 0x088B51DC: addiu $v0, $zero, 1
v0_check = 1

# 0x088B51E0: sll $s0, $a1, 2 → s0 = 0 << 2 = 0
s0 = a1 << 2
print(f"  $s0 = $a1(={a1}) << 2 = {s0}")

# 0x088B51E4: beq $a2, $v0(=1), 0x088B520C → a2=1, v0=1, TAKEN
print(f"  beq $a2(={a2_masked}), $v0(={v0_check}) → TAKEN (go to 0x088B520C)")

# Now disassemble from 0x088B520C
print(f"\n  Continuing from 0x088B520C:")
for addr in range(0x088B520C, 0x088B5260, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jr $ra" in d:
        m = " [RETURN]"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    print(f"    0x{addr:08X}: 0x{instr:08X}  {d}{m}")
    if "jr $ra" in d:
        break

# Now compute $s3 based on the path taken
# From the disassembly, figure out what 0x088B520C returns
# s0 = 0, s1 = 0x09BB7A84
# The code at 0x088B520C likely does: $v0 = *(s1 + s0 + SOME_OFFSET)

# Let me also check what's at 0x09BB7A84 + offsets
print(f"\n" + "=" * 70)
print(f"=== Data at 0x09BB7A84 (the $s1 object) ===")
print(f"=" * 70)
for off in range(0, 0x20, 4):
    addr = 0x09BB7A84 + off
    vc = read_u32(mem_c, psp_to_offset(addr))
    vo = read_u32(mem_o, psp_to_offset(addr))
    d = " ***" if vc != vo else ""
    is_ptr = 0x08000000 <= vc <= 0x0A000000
    tag = " PTR" if is_ptr else ""
    print(f"  +0x{off:02X} (0x{addr:08X}): C=0x{vc:08X}  O=0x{vo:08X}{d}{tag}")

# Wider: check +0x00 to +0xC00 since $s3+0xBA0 is accessed
print(f"\n=== Data at 0x09BB7A84 + large offsets ===")
for off_name, off_val in [("0x18C", 0x18C), ("0xBA0", 0xBA0), ("0xBDC", 0xBDC)]:
    addr = 0x09BB7A84 + off_val
    vc = read_u32(mem_c, psp_to_offset(addr))
    vo = read_u32(mem_o, psp_to_offset(addr))
    d = " ***" if vc != vo else ""
    print(f"  +{off_name} (0x{addr:08X}): C=0x{vc:08X}  O=0x{vo:08X}{d}")

# If 0x088B51B8 returns *(s1 + s0 + 0x0C) = *(0x09BB7A84 + 0 + 0x0C) = *(0x09BB7A90)
# Or maybe *(s1 + s0 + 4) where s0=0, s1 was saved
# Let me just check various likely return values
print(f"\n=== Potential $s3 values ===")
for off_name, off_val in [("s1+s0+8=0x09BB7A8C", 0x8), ("s1+s0+0xC=0x09BB7A90", 0xC),
                          ("s1+s0+4=0x09BB7A88", 0x4), ("s1+0=0x09BB7A84", 0x0)]:
    addr = 0x09BB7A84 + off_val
    val_c = read_u32(mem_c, psp_to_offset(addr))
    val_o = read_u32(mem_o, psp_to_offset(addr))
    is_ptr = 0x08000000 <= val_c <= 0x0A000000
    print(f"  {off_name}: C=0x{val_c:08X}  O=0x{val_o:08X}  {'PTR' if is_ptr else ''}")
    if is_ptr and val_c == val_o:
        # Follow the pointer and check key offsets
        s3_candidate = val_c
        for s3_off_name, s3_off in [("0x18C", 0x18C), ("0xBA0", 0xBA0), ("0x062", 0x062)]:
            s3_addr = s3_candidate + s3_off
            s3vc = read_u32(mem_c, psp_to_offset(s3_addr))
            s3vo = read_u32(mem_o, psp_to_offset(s3_addr))
            d = " ***DIFF***" if s3vc != s3vo else ""
            print(f"    {off_name} → 0x{s3_candidate:08X}+{s3_off_name}: C=0x{s3vc:08X}  O=0x{s3vo:08X}{d}")

print("\nDone!")
