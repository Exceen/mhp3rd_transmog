#!/usr/bin/env python3
"""Trace the HP/Stamina bar rendering chain to find position control points.
The bars are rendered by overlay code that calls eboot sprite functions.
We need to find where X/Y positions are set for patching."""

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

# The HP bar overlay rendering is around 0x09D61000-0x09D61840
# We know these functions call 0x08904570 with $a3=X_offset and various other args
# Let's find the PARENT function that sets up the HP bar rendering context

# First, find all callers of 0x08904570 in the overlay
print("=== Callers of 0x08904570 (bar render) in overlay ===")
bar_jal = 0x0C000000 | (0x08904570 >> 2)
callers = []
for addr in range(0x09C50000, 0x09DC0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == bar_jal:
        callers.append(addr)
        print(f"  0x{addr:08X}: jal 0x08904570  (return: 0x{addr+8:08X})")

# Now look at the function 0x089011C8 which IS in a vtable and loads X/Y from entry data
# It uses $a3 from entry+24 (lh $a3, 24($v0)) and $t0 from entry+26 (lh $t0, 26($v0))
# The entry is pointed to by $a1->+4
# So the X/Y positions come from a data structure passed to this function

# Let's find who calls 0x089011C8 (which IS in vtable at 0x0896B478)
# The vtable entry is at offset +0x10 from the vtable base
# So the call pattern is: lw $v0, 0x10($vtable); jalr $v0
# To find callers, search for lw + jalr patterns near overlay HP bar code

# Also search for the vtable base 0x0896B468
print(f"\n=== References to vtable base 0x0896B468 area ===")
# vtable for 0x089011C8 at 0x0896B478 → base ~0x0896B468
# The object would store a pointer to this vtable
# Search for 0x0896B468 as data pointer
vtable_addr = 0x0896B468
for addr in range(0x08800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == vtable_addr:
        print(f"  0x{addr:08X}: points to vtable 0x{vtable_addr:08X}")

# Also check the second vtable
vtable_addr2 = 0x0896B318
for addr in range(0x08800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == vtable_addr2:
        print(f"  0x{addr:08X}: points to vtable 0x{vtable_addr2:08X}")

# Let's look at what 0x08904570 does - it's the bar rendering function
print(f"\n=== 0x08904570 (bar render function) entry ===")
for addr in range(0x08904570, 0x089046A0, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "$a3" in d: marker += " [a3_X]"
    if "$t0" in d: marker += " [t0]"
    if "sw " in d and "$sp" in d: marker += " [STACK]"
    if "$ra" in d: marker += " [RA]"
    op = instr >> 26
    if op == 0x09 and ((instr >> 21) & 0x1F) == 29 and ((instr >> 16) & 0x1F) == 29:
        simm = (instr & 0xFFFF)
        if simm >= 0x8000: simm -= 0x10000
        if simm < 0:
            marker += f" *** FUNC START (frame={-simm}) ***"
    if "jr $ra" in d:
        marker += " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Let's also look at the PARENT function of the HP bar rendering.
# The function at 0x09D614EC-0x09D61640 renders HP bars.
# Let's find its parent (who calls it).
# Search for jal with the function start address
# We need to find the start of the function that contains the HP bar sprite calls
# From the dump, function ends at 0x09D61640 (jr $ra) with prologue at some earlier address
# Let's scan back to find it
print(f"\n=== Scanning for HP bar function prologue ===")
for addr in range(0x09D61500, 0x09D61000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:  # addiu
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Function prologue at 0x{addr:08X}: addiu $sp, $sp, {simm}")
            # Show first few instructions
            for a2 in range(addr, addr + 32, 4):
                o2 = psp_to_offset(a2)
                i2 = read_u32(data, o2)
                print(f"    0x{a2:08X}: {disasm(i2, a2)}")
            break

# Search for callers of this function in the overlay
func_start = 0x09D612C4  # approximate, will verify
# Actually let me check the dump output to find the real start
# From our HP bar dump, the function has frame size 80 and lots of saved regs
# Let's search more carefully

print(f"\n=== Looking for function containing 0x09D61514 ===")
# The function at 0x09D614EC area starts somewhere before 0x09D61500
# Scan back for addiu $sp, $sp, -80 (0x27BDFFD0? -80 = 0xFFB0)
for addr in range(0x09D61500, 0x09D61200, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            func_start = addr
            print(f"  Function at 0x{addr:08X}: frame={-simm}")
            # Check if this function is called from overlay
            jal_func = 0x0C000000 | (addr >> 2)
            for ca in range(0x09C50000, 0x09DC0000, 4):
                co = psp_to_offset(ca)
                if co + 4 > len(data): break
                ci = read_u32(data, co)
                if ci == jal_func:
                    print(f"    Called from 0x{ca:08X}")
            break

# Now let's look at the entry table structure
# Function 0x089011C8 loads X/Y from (($a1)+4)+24 and (($a1)+4)+26
# $a1 points to an entry structure where:
#   +0: pointer to sprite data
#   +4: pointer to position data (or null)
#     position+24: X offset (s16)
#     position+26: Y offset (s16)
# These position pointers might be in the layout table at 0x09D92CB0

# From memory notes: "Layout table: 0x09D92CB0, 36-byte entries, X@+24(s16), Y@+26(s16)"
# Let's dump some entries
print(f"\n=== Layout table at 0x09D92CB0 (36-byte entries) ===")
for i in range(20):
    entry_addr = 0x09D92CB0 + i * 36
    off = psp_to_offset(entry_addr)
    if off + 36 > len(data): break
    # Read X at +24, Y at +26
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)
    # Also read first few fields
    f0 = read_u32(data, off)
    f4 = read_u32(data, off + 4)
    f8 = read_u32(data, off + 8)
    flags = struct.unpack_from('<H', data, off + 22)[0]
    w = read_s16(data, off + 28)
    h = read_s16(data, off + 30)
    print(f"  [{i:2d}] 0x{entry_addr:08X}: X={x:5d} Y={y:5d} W={w:5d} H={h:5d}  flags=0x{flags:04X}  f0=0x{f0:08X}")

print("\nDone!")
