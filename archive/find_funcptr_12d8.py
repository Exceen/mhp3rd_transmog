#!/usr/bin/env python3
"""Find all references to 0x089012D8 as a function pointer in memory,
and trace the actual call chain for HP bars."""

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
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

TARGET = 0x089012D8

# Search for 0x089012D8 as a 32-bit value in eboot data region
print(f"=== Searching for 0x{TARGET:08X} as function pointer ===")
for addr in range(0x08800000, 0x08A20000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == TARGET:
        # Check if it's in a data table (not code)
        print(f"  0x{addr:08X}: 0x{TARGET:08X}")
        # Show surrounding context
        for ctx in range(addr - 16, addr + 20, 4):
            coff = psp_to_offset(ctx)
            if coff + 4 <= len(data):
                cv = read_u32(data, coff)
                marker = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{cv:08X}{marker}")

# Also search in overlay
for addr in range(0x09C50000, 0x09DC0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == TARGET:
        print(f"  0x{addr:08X}: 0x{TARGET:08X} (overlay)")

# Now search for the OTHER function 0x089011C8 (the one with data-loaded X/Y)
print(f"\n=== Searching for 0x089011C8 as function pointer ===")
for addr in range(0x08800000, 0x08A20000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == 0x089011C8:
        print(f"  0x{addr:08X}: 0x089011C8")
        for ctx in range(addr - 16, addr + 20, 4):
            coff = psp_to_offset(ctx)
            if coff + 4 <= len(data):
                cv = read_u32(data, coff)
                marker = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{cv:08X}{marker}")

# Also search for 0x0890128C (the function between)
print(f"\n=== Searching for 0x0890128C as function pointer ===")
for addr in range(0x08800000, 0x08A20000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == 0x0890128C:
        print(f"  0x{addr:08X}: 0x0890128C")
        for ctx in range(addr - 16, addr + 20, 4):
            coff = psp_to_offset(ctx)
            if coff + 4 <= len(data):
                cv = read_u32(data, coff)
                marker = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{cv:08X}{marker}")

# Now, let's find the function table containing these sprite render wrappers
# Search for a vtable-like structure with these known functions
print(f"\n=== Searching for vtable with sprite render entries ===")
known_funcs = [0x08901168, 0x089011C8, 0x0890128C, 0x089012D8, 0x08901000, 0x08901380]
for func in known_funcs:
    for addr in range(0x08960000, 0x08A00000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        val = read_u32(data, off)
        if val == func:
            print(f"  0x{addr:08X}: 0x{func:08X} (in data section)")

print("\nDone!")
