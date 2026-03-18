#!/usr/bin/env python3
"""Find all callers of 0x089012D8 in eboot and overlay."""

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

# jal 0x089012D8 -> target = 0x089012D8 >> 2 = 0x022404B6
# instruction = 0x0C000000 | 0x022404B6 = 0x0C2404B6
TARGET_FUNC = 0x089012D8
jal_instr = 0x0C000000 | (TARGET_FUNC >> 2)
j_instr = 0x08000000 | (TARGET_FUNC >> 2)
print(f"Searching for jal 0x{TARGET_FUNC:08X} (0x{jal_instr:08X})")
print(f"Searching for j 0x{TARGET_FUNC:08X} (0x{j_instr:08X})")

# Search eboot (0x08800000 - 0x08A00000)
print("\n=== Eboot callers ===")
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_instr:
        # Return address is addr + 8
        print(f"  0x{addr:08X}: jal 0x{TARGET_FUNC:08X}  (return addr: 0x{addr+8:08X})")
    elif instr == j_instr:
        print(f"  0x{addr:08X}: j 0x{TARGET_FUNC:08X}")

# Search overlay (0x09C50000 - 0x09DB0000)
print("\n=== Overlay callers ===")
for addr in range(0x09C50000, 0x09DB0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_instr:
        print(f"  0x{addr:08X}: jal 0x{TARGET_FUNC:08X}  (return addr: 0x{addr+8:08X})")
    elif instr == j_instr:
        print(f"  0x{addr:08X}: j 0x{TARGET_FUNC:08X}")

# Also find callers of function 0x08901168 (sprite render) directly from overlay
print(f"\n=== Direct callers of 0x08901168 (sprite render) ===")
sprite_jal = 0x0C000000 | (0x08901168 >> 2)
sprite_j = 0x08000000 | (0x08901168 >> 2)
for addr in range(0x09C50000, 0x09DB0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == sprite_jal:
        print(f"  0x{addr:08X}: jal 0x08901168  (return addr: 0x{addr+8:08X})")
    elif instr == sprite_j:
        print(f"  0x{addr:08X}: j 0x08901168")

# Also check indirect callers - look for jalr usage patterns near 0x089012D8 calls
# And check what function 0x08901000 is (SPRITE_1000)
print(f"\n=== Callers of 0x08901000 (SPRITE_1000) ===")
s1000_jal = 0x0C000000 | (0x08901000 >> 2)
for addr in range(0x09C50000, 0x09DB0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == s1000_jal:
        print(f"  0x{addr:08X}: jal 0x08901000  (return addr: 0x{addr+8:08X})")

print("\nDone!")
