#!/usr/bin/env python3
"""Dump the HP/stamina bar data structures at 0x09DC01xx and the sharpness render path."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

# HP bar $a1 addresses from the trace:
# Call 1: lui 0x09DC + addiu 0x188 = 0x09DC0188
# Call 2: lui 0x09DC + addiu 0x1D0 = 0x09DC01D0
# Call 3: lui 0x09DC + addiu 0x23C = 0x09DC023C
# Call 4: lui 0x09DC + addiu 0x1F4 = 0x09DC01F4
# Call 5: lui 0x09DC + addiu 0x260 = 0x09DC0260
# Call 6: lui 0x09DC + addiu 0x284 = 0x09DC0284
# Call 7: lui 0x09DC + addiu 0x1AC = 0x09DC01AC
# $t0:   lui 0x09DC + addiu 0x164 = 0x09DC0164 (or $s2 + 0x164)

# 0x08904570 reads from $a1:
# lhu $t7, 0($a1) - x1
# lhu $t6, 2($a1) - y1
# lhu $t5, 4($a1) - x2
# lhu $t4, 6($a1) - y2
# Then: width = x2 - x1, height = y2 - y1

bar_addrs = {
    0x09DC0188: "Bar call 1",
    0x09DC01D0: "Bar call 2",
    0x09DC023C: "Bar call 3",
    0x09DC01F4: "Bar call 4",
    0x09DC0260: "Bar call 5",
    0x09DC0284: "Bar call 6",
    0x09DC01AC: "Bar call 7 (stamina?)",
    0x09DC0164: "$t0 data",
}

print("=== HP/Stamina bar data structures ===")
for addr, label in sorted(bar_addrs.items()):
    off = psp_to_offset(addr)
    if off + 8 > len(data):
        print(f"  {label} @ 0x{addr:08X}: OUT OF RANGE")
        continue
    x1 = read_u16(data, off)
    y1 = read_u16(data, off + 2)
    x2 = read_u16(data, off + 4)
    y2 = read_u16(data, off + 6)
    w = x2 - x1
    h = y2 - y1
    # Also show more fields
    extra = []
    for i in range(8, 24, 2):
        if off + i + 2 <= len(data):
            extra.append(f"0x{read_u16(data, off + i):04X}")
    print(f"  {label} @ 0x{addr:08X}: x1={x1} y1={y1} x2={x2} y2={y2} (w={w} h={h})")
    print(f"    Extra: {' '.join(extra)}")

# Dump broader context: 0x09DC0160 - 0x09DC02C0
print("\n=== Full bar data area 0x09DC0160-0x09DC02C0 (hex dump) ===")
for addr in range(0x09DC0160, 0x09DC02C0, 8):
    off = psp_to_offset(addr)
    if off + 8 > len(data): break
    x1 = read_u16(data, off)
    y1 = read_u16(data, off + 2)
    x2 = read_u16(data, off + 4)
    y2 = read_u16(data, off + 6)
    raw = read_u32(data, off)
    raw2 = read_u32(data, off + 4)
    label = ""
    for ba, bl in bar_addrs.items():
        if ba == addr:
            label = f" <<<< {bl}"
    print(f"  0x{addr:08X}: 0x{raw:08X} 0x{raw2:08X}  ({x1:5d} {y1:5d} {x2:5d} {y2:5d}){label}")

# Now check: what's at the $t0 address? 0x08904570 does:
# addu $a2, $t0, $zero  → $a2 = $t0 value
# So $t0 is passed as $a2 to 0x0890112C
# Let's see what 0x0890112C does with $a2
# From the trace: sw $a2, 4($sp) — stores on stack

# Let's look at 0x09DC0164 more broadly
print("\n=== $t0 data area 0x09DC0160-0x09DC0180 ===")
for addr in range(0x09DC0160, 0x09DC0180, 4):
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{val:08X}")

# Now let's find the sharpness bar rendering
# Sharpness uses 0x08904570 as well — let's find callers near 0x09D5E000-0x09D5EC00
jal_bar = 0x0C000000 | (0x08904570 >> 2)
print("\n=== Callers of 0x08904570 near sharpness area 0x09D5D000-0x09D5F000 ===")
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_bar:
        print(f"  0x{addr:08X}: jal 0x08904570")

# Also check for 0x088C926C callers (the function called from sharpness area)
jal_926c = 0x0C000000 | (0x088C926C >> 2)
print(f"\n=== Callers of 0x088C926C near sharpness area ===")
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_926c:
        print(f"  0x{addr:08X}: jal 0x088C926C")

# Let's dump 0x088C926C to understand it
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
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

print(f"\n=== 0x088C926C function entry ===")
for addr in range(0x088C926C, 0x088C926C + 120, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [-> 0x{target:08X}]"
    if "jr $ra" in d:
        m = " [RETURN]"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Also look at the rendering function at 0x09D5E418 (where sharpness jumps to)
print(f"\n=== 0x09D5E418 (sharpness jump target) ===")
for addr in range(0x09D5E410, 0x09D5E450, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if instr == jal_bar: m = " <<<< BAR RENDER"
    if "jal " in d:
        target = (instr & 0x03FFFFFF) << 2
        m += f" [-> 0x{target:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
