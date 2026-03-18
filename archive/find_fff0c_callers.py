#!/usr/bin/env python3
"""Find ALL callers of 0x088FFF0C (jal and jalr) in eboot and overlay."""

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

# jal 0x088FFF0C encoding
target = 0x088FFF0C
jal_instr = 0x0C000000 | (target >> 2)
print(f"Looking for jal 0x{target:08X} = instruction 0x{jal_instr:08X}")

# Search eboot area (0x08800000 - 0x089FFFFF)
print("\n=== jal 0x088FFF0C in EBOOT (0x08800000-0x089FFFFF) ===")
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_instr:
        print(f"  0x{addr:08X}: jal 0x{target:08X}")

# Search overlay area (0x09C50000 - 0x09E00000)
print("\n=== jal 0x088FFF0C in OVERLAY (0x09C50000-0x09E00000) ===")
for addr in range(0x09C50000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_instr:
        print(f"  0x{addr:08X}: jal 0x{target:08X}")

# Also find all eboot functions that contain jal 0x088FFF0C
# by looking for the nearest function prologue before each caller
print("\n=== Eboot functions containing jal 0x088FFF0C ===")
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_instr:
        # Scan backwards for function prologue (addiu $sp, $sp, -N)
        for probe in range(addr - 4, addr - 0x400, -4):
            poff = psp_to_offset(probe)
            if poff < 0: break
            pi = read_u32(data, poff)
            op = pi >> 26
            rs = (pi >> 21) & 0x1F
            rt = (pi >> 16) & 0x1F
            simm = pi & 0xFFFF
            if simm >= 0x8000: simm -= 0x10000
            if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
                print(f"  Caller at 0x{addr:08X} is in function 0x{probe:08X} (frame={-simm})")
                break

print("\nDone!")
