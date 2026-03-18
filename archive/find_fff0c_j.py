#!/usr/bin/env python3
"""Find j (jump, not jal) instructions targeting 0x088FFF0C — tail calls."""

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

target = 0x088FFF0C
# j instruction: opcode 0x02, target >> 2
j_instr = (0x02 << 26) | (target >> 2)
print(f"Looking for j 0x{target:08X} = instruction 0x{j_instr:08X}")

# Search eboot
print("\n=== j 0x088FFF0C in EBOOT (0x08800000-0x089FFFFF) ===")
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == j_instr:
        print(f"  0x{addr:08X}: j 0x{target:08X}")

# Search overlay
print("\n=== j 0x088FFF0C in OVERLAY (0x09C50000-0x09E00000) ===")
for addr in range(0x09C50000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == j_instr:
        print(f"  0x{addr:08X}: j 0x{target:08X}")

# Also search for j/jal to 0x088FF8F0 (the inner function)
target2 = 0x088FF8F0
j_instr2 = (0x02 << 26) | (target2 >> 2)
jal_instr2 = (0x03 << 26) | (target2 >> 2)
print(f"\n=== j 0x088FF8F0 (tail calls to inner function) ===")
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == j_instr2:
        print(f"  EBOOT 0x{addr:08X}: j 0x{target2:08X}")
for addr in range(0x09C50000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == j_instr2:
        print(f"  OVERLAY 0x{addr:08X}: j 0x{target2:08X}")

print("\nDone!")
