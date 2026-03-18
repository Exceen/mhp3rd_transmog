#!/usr/bin/env python3
"""Search all PSP memory for 0x089012D8 as a function pointer."""

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

data = decompress_ppst(PPST_FILE)
max_addr = PSP_BASE + len(data) - MEM_OFFSET

TARGET = 0x089012D8
print(f"Searching all memory ({len(data)} bytes) for 0x{TARGET:08X}...")
count = 0
for off in range(MEM_OFFSET, len(data) - 3, 4):
    val = struct.unpack_from('<I', data, off)[0]
    if val == TARGET:
        addr = PSP_BASE + off - MEM_OFFSET
        count += 1
        # Show context
        print(f"\n  0x{addr:08X}: 0x{TARGET:08X}")
        for ctx_off in range(max(MEM_OFFSET, off - 16), min(len(data) - 3, off + 20), 4):
            cv = struct.unpack_from('<I', data, ctx_off)[0]
            ca = PSP_BASE + ctx_off - MEM_OFFSET
            marker = " <<<" if ctx_off == off else ""
            print(f"    0x{ca:08X}: 0x{cv:08X}{marker}")

print(f"\nFound {count} references to 0x{TARGET:08X}")

# Also check: are there any jalr patterns that could call 0x089012D8
# via register loading? Check for lui 0x0890 in overlay
print(f"\n=== lui $v0, 0x0890 in overlay (potential indirect calls) ===")
lui_0890 = 0x3C020890  # lui $v0, 0x0890
for addr in range(0x09C50000, 0x09DC0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    # Check for any lui with 0x0890
    if (instr & 0xFFFF0000) == 0x3C000000 | (0x0890 << 0):
        pass  # wrong encoding
    op = instr >> 26
    rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF
    if op == 0x0F and imm == 0x0890:  # lui $rt, 0x0890
        print(f"  0x{addr:08X}: lui {['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3','$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7','$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7','$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra'][rt]}, 0x0890")
        # Check next instruction for addiu/ori
        next_off = psp_to_offset(addr + 4)
        if next_off + 4 <= len(data):
            next_instr = read_u32(data, next_off)
            next_op = next_instr >> 26
            next_rs = (next_instr >> 21) & 0x1F
            next_rt2 = (next_instr >> 16) & 0x1F
            next_imm = next_instr & 0xFFFF
            if next_op == 0x09:  # addiu
                full = (0x0890 << 16) + (next_imm if next_imm < 0x8000 else next_imm - 0x10000)
                print(f"    -> addiu: full addr = 0x{full:08X}")
            elif next_op == 0x0D:  # ori
                full = (0x0890 << 16) | next_imm
                print(f"    -> ori: full addr = 0x{full:08X}")

print("\nDone!")
