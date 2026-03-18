#!/usr/bin/env python3
"""Dump first instructions of 0x08901168 for hooking."""
import struct, zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
PSP_BASE = 0x08000000; MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        return zstd.ZstdDecompressor().decompress(f.read(), max_output_size=64*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

for addr in range(0x08901168, 0x08901168 + 20, 4):
    off = addr - PSP_BASE + MEM_OFFSET
    instr = read_u32(data, off)
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if op == 0x09:
        print(f"  0x{addr:08X}: 0x{instr:08X}  addiu {REGS[rt]}, {REGS[rs]}, {simm}")
    elif op == 0x2B:
        print(f"  0x{addr:08X}: 0x{instr:08X}  sw {REGS[rt]}, {simm}({REGS[rs]})")
    else:
        print(f"  0x{addr:08X}: 0x{instr:08X}  op=0x{op:02X}")
