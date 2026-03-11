#!/usr/bin/env python3
"""Dump BG_BF0 data tables for item selector call #6 (13 elements)."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    if off + 4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

data = decompress_ppst(PPST_FILE)

# BG_BF0 #6 parameters:
# $a1 = lui 0x09D9, addiu -3080 = 0x09D90000 - 3080 = 0x09D90000 - 0xC08 = 0x09D8F3F8
# $a2 = lui 0x09D9, addiu -3116 = 0x09D90000 - 3116 = 0x09D90000 - 0xC2C = 0x09D8F3D4
# $a3 = 13

a1_addr = 0x09D90000 - 3080  # 0x09D8F3F8
a2_addr = 0x09D90000 - 3116  # 0x09D8F3D4
count = 13

print(f"BG_BF0 #6: $a1=0x{a1_addr:08X}, $a2=0x{a2_addr:08X}, $a3={count}")

# First, let's examine the BG_BF0 function itself to understand table format
# Dump BG_BF0 (0x08900BF0) to understand how it reads the tables
print("\n=== BG_BF0 FUNCTION (0x08900BF0) first 100 instructions ===")

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

jr_count = 0
for addr in range(0x08900BF0, 0x08900BF0 + 400, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: {d}")
    if "jr $ra" in d:
        jr_count += 1
        if jr_count >= 1:
            break

# Dump $a1 table data (raw bytes) for all calls
print("\n\n=== ALL BG_BF0 CALL PARAMETERS ===")
calls = [
    (1, 0x09D90000 - 2576, 0x09D90000 - 2612, 4),
    (2, 0x09D90000 - 1964, None, 3),  # $a2 = $s1 + 2820 (dynamic)
    (3, 0x09D90000 - 2108, None, 3),  # $a2 = $s1 + 2732
    (4, 0x09D90000 - 2252, None, 3),  # $a2 = $s1 + 2644
    (5, 0x09D90000 - 2396, None, 3),  # $a2 = $s1 + 2556
    (6, 0x09D90000 - 3080, 0x09D90000 - 3116, 13),
    (7, 0x09D90000 - 1820, None, 2),  # $a2 = $s1 + 2908
    (8, 0x09D90000 - 1712, None, 2),  # $a2 = $s1 + 2996
]

for idx, a1, a2, a3 in calls:
    print(f"\n--- BG_BF0 #{idx}: $a1=0x{a1:08X}, $a2={'dynamic' if a2 is None else f'0x{a2:08X}'}, $a3={a3} ---")

# Dump $a1 table raw data
print(f"\n\n=== $a1 TABLE FOR CALL #6 (0x{a1_addr:08X}, {count} elements) ===")
# Try different entry sizes to find the structure
for entry_size in [4, 8, 12, 16, 20, 24, 28, 32, 36]:
    print(f"\n  Entry size = {entry_size} bytes:")
    for i in range(min(count, 15)):
        entry_addr = a1_addr + i * entry_size
        off = psp_to_offset(entry_addr)
        if off + entry_size > len(data): break
        raw = data[off:off+entry_size]
        hex_str = ' '.join(f'{b:02X}' for b in raw)
        # Also try to read as halfwords
        halfs = []
        for j in range(0, entry_size, 2):
            if j + 2 <= entry_size:
                halfs.append(read_s16(data, off + j))
        print(f"    [{i:2d}] 0x{entry_addr:08X}: {hex_str}  halfs={halfs}")

# Also dump $a2 table
print(f"\n\n=== $a2 TABLE FOR CALL #6 (0x{a2_addr:08X}) ===")
for entry_size in [4, 8, 12, 16, 20, 24, 28, 32, 36]:
    print(f"\n  Entry size = {entry_size} bytes:")
    for i in range(min(count, 15)):
        entry_addr = a2_addr + i * entry_size
        off = psp_to_offset(entry_addr)
        if off + entry_size > len(data): break
        raw = data[off:off+entry_size]
        hex_str = ' '.join(f'{b:02X}' for b in raw)
        halfs = []
        for j in range(0, entry_size, 2):
            if j + 2 <= entry_size:
                halfs.append(read_s16(data, off + j))
        print(f"    [{i:2d}] 0x{entry_addr:08X}: {hex_str}  halfs={halfs}")

print("\nDone!")
