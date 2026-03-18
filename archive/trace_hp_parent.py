#!/usr/bin/env python3
"""Find the parent function of HP bar rendering by looking for function boundaries."""

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

# Search for ALL function prologues/epilogues from 0x09D60000 to 0x09D62000
print("=== Function boundaries 0x09D60000-0x09D62000 ===")
for addr in range(0x09D60000, 0x09D62000, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    op = instr >> 26
    # Prologue: addiu $sp, $sp, -N
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  PROLOGUE 0x{addr:08X}: addiu $sp, $sp, {simm} (frame={-simm})")
    # Epilogue: jr $ra
    if instr & 0xFFFF == 0:  # potential jr $ra
        if (instr >> 26) == 0 and ((instr >> 21) & 0x1F) == 31 and (instr & 0x3F) == 0x08:
            print(f"  RETURN  0x{addr:08X}: jr $ra")

# Look at 0x088FF8F0 - the final rendering function
print(f"\n=== 0x088FF8F0 (final sprite render) - first 100 instructions ===")
for addr in range(0x088FF8F0, 0x088FF8F0 + 400, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "$t0" in d or "$t1" in d:
        m = " [T0/T1]"
    if "$a2" in d:
        m += " [A2]"
    if "jr $ra" in d:
        m += " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
        break
    if "jal " in d:
        target = (instr & 0x03FFFFFF) << 2
        m += f" [-> 0x{target:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Check: what if position comes from the $a2 data (0x09DC0164)?
# The data at 0x09DC0164 has x1=0,y1=0,x2=430,y2=14
# and at +24: values 20,70 (could be X,Y position offsets?)
# Let's also check: what is at 0x08B268DC (SPRITE_INFO from sharpness indicator)?
# And at 0x0896B378 (the data pointer loaded by 0x08904570)
print(f"\n=== Data at 0x0896B378 (bar render data pointer) ===")
for addr in range(0x0896B360, 0x0896B3C0, 4):
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{val:08X}")

# Let's look at the HP bar Y=17 for stamina - where does 17 come from?
# And the X=4 - where does 4 come from?
# These values might be in the function's hardcoded addiu instructions
# Let's scan the HP bar function area for small immediate values
print(f"\n=== addiu with small values (0-30) in HP bar area ===")
jal_bar = 0x0C000000 | (0x08904570 >> 2)
for addr in range(0x09D61300, 0x09D61700, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:  # addiu
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 0 and 1 <= simm <= 30:  # addiu $reg, $zero, small_value
            d = disasm(instr, addr)
            print(f"  0x{addr:08X}: {d}")

# Also look at what $s0 contains when the HP bar function is active
# $s0 is set from $a0 in the overlay code
# Let's look at the function 0x09D617B0 and trace $s0
# From earlier: $s0 = $a0 at 0x09D617BC
# And HP bar area uses $s0 as $a0 for the bar render call
# Let's check what the render context address is
print(f"\n=== Render context pointer ===")
# 0x09BEB0BC = 0x09BF0000 + (-0x4F44)
render_ctx_addr = 0x09BEB0BC  # this is where the render context ptr is stored
off = psp_to_offset(render_ctx_addr)
if off + 4 <= len(data):
    ctx_ptr = read_u32(data, off)
    print(f"  *(0x09BEB0BC) = 0x{ctx_ptr:08X}")
    # Dump what's at the context
    ctx_off = psp_to_offset(ctx_ptr)
    if ctx_off + 100 <= len(data):
        print(f"  Context at 0x{ctx_ptr:08X}:")
        for i in range(0, 64, 4):
            val = read_u32(data, ctx_off + i)
            print(f"    +{i:3d}: 0x{val:08X}")

# Also try: search for 0x088FF1F0 - this was mentioned earlier as the function
# that does: final_X = $a3 + entry_X, final_Y = $t0 + entry_Y
# Let's check if 0x08904570's chain eventually calls 0x088FF1F0
jal_f1f0 = 0x0C000000 | (0x088FF1F0 >> 2)
print(f"\n=== Does 0x088FF8F0 call 0x088FF1F0? ===")
for addr in range(0x088FF8F0, 0x088FFA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == jal_f1f0:
        print(f"  YES: 0x{addr:08X}: jal 0x088FF1F0")

print("\nDone!")
