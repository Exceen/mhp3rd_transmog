#!/usr/bin/env python3
"""Trace what function pointers the jalr instructions in the sharpness area call."""

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

data = decompress_ppst(PPST_FILE)

# For each jalr in the sharpness area, look backwards to find the function pointer source
print("=== jalr targets in sharpness area (0x09D5D000-0x09D5F000) ===")
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    func = instr & 0x3F
    if op == 0 and func == 0x09:  # jalr
        rs = (instr >> 21) & 0x1F
        print(f"\n  jalr at 0x{addr:08X} (via {REGS[rs]}):")
        # Show 8 instructions before and the delay slot
        for a in range(addr - 32, addr + 8, 4):
            o = psp_to_offset(a)
            i = read_u32(data, o)
            d = disasm(i, a)
            marker = " <<<<" if a == addr else ""
            print(f"    0x{a:08X}: 0x{i:08X}  {d}{marker}")

        # Try to find the lw that loads the function pointer
        # Common pattern: lw $v0, offset($reg) then jalr $v0
        for a in range(addr - 4, addr - 40, -4):
            o = psp_to_offset(a)
            i = read_u32(data, o)
            iop = i >> 26
            irt = (i >> 16) & 0x1F
            if iop == 0x23 and irt == rs:  # lw into the jalr register
                irs = (i >> 21) & 0x1F
                isimm = i & 0xFFFF
                if isimm >= 0x8000: isimm -= 0x10000
                print(f"    -> loaded via: lw {REGS[rs]}, {isimm}({REGS[irs]}) at 0x{a:08X}")
                # If loading from a known address, try to resolve it
                # Check if we can find a lui + lw pattern
                break

# Also: let's look at what vtable/function pointer tables might contain render functions
# Search for 0x089012D8 as a data value in memory (function pointer in vtable)
print(f"\n=== Searching for 0x089012D8 as data value (function pointer) ===")
target_val = 0x089012D8
for addr in range(0x08800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == target_val:
        print(f"  0x{addr:08X}: contains 0x{target_val:08X}")

# Search for other render functions as data values
print(f"\n=== Searching for render function pointers in vtables ===")
render_funcs = [0x08901168, 0x088FF8F0, 0x088FF1F0, 0x08904570, 0x0890112C,
                0x08900B7C, 0x089012D8, 0x08900464, 0x088FA2B0, 0x08902688,
                0x089035C0, 0x08902E04]
for func in render_funcs:
    for addr in range(0x08800000, 0x09E00000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        val = read_u32(data, off)
        if val == func:
            # Check if this looks like a vtable (surrounded by other code pointers)
            context = []
            for i in range(-2, 3):
                co = psp_to_offset(addr + i*4)
                cv = read_u32(data, co)
                context.append(f"0x{cv:08X}")
            print(f"  0x{func:08X} found at 0x{addr:08X} context: {' '.join(context)}")

print("\nDone!")
