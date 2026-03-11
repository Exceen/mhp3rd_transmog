#!/usr/bin/env python3
"""Find all addu $a3,$zero,$zero and addu $t0,$zero,$zero in 0x09D60280 function."""

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

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

# addu $a3, $zero, $zero = 0x00003821
# addu $t0, $zero, $zero = 0x00004021
TARGET_A3 = 0x00003821
TARGET_T0 = 0x00004021

print("=== addu $a3/$t0, $zero, $zero in 0x09D60280-0x09D60620 ===")
a3_addrs = []
t0_addrs = []
for addr in range(0x09D60280, 0x09D60620, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    cw = addr - 0x08800000
    if instr == TARGET_A3:
        a3_addrs.append(addr)
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $a3, $zero, $zero")
    elif instr == TARGET_T0:
        t0_addrs.append(addr)
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0, $zero, $zero")

print(f"\nTotal $a3 zero-sets: {len(a3_addrs)}")
print(f"Total $t0 zero-sets: {len(t0_addrs)}")

# Also check 0x09D6172C
print("\n=== addu $a3/$t0, $zero, $zero in 0x09D6172C-0x09D61800 ===")
for addr in range(0x09D6172C, 0x09D61800, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    cw = addr - 0x08800000
    if instr == TARGET_A3:
        a3_addrs.append(addr)
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $a3, $zero, $zero")
    elif instr == TARGET_T0:
        t0_addrs.append(addr)
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): addu $t0, $zero, $zero")

# Generate CWCheat lines for X offset = 98 (0x62)
X_OFFSET = 98
print(f"\n=== CWCheat lines for X offset {X_OFFSET} ===")
print(f"# addiu $a3, $zero, {X_OFFSET} = 0x{0x24070000 | (X_OFFSET & 0xFFFF):08X}")
for addr in a3_addrs:
    cw = addr - 0x08800000
    new_instr = 0x24070000 | (X_OFFSET & 0xFFFF)
    print(f"_L 0xD1457C90 0x00005FA0")
    print(f"_L 0x2{cw:07X} 0x{new_instr:08X}")

print(f"\n# Default (restore) lines:")
for addr in a3_addrs:
    cw = addr - 0x08800000
    print(f"_L 0xD1457C90 0x00005FA0")
    print(f"_L 0x2{cw:07X} 0x00003821")
for addr in t0_addrs:
    cw = addr - 0x08800000
    print(f"_L 0xD1457C90 0x00005FA0")
    print(f"_L 0x2{cw:07X} 0x00004021")

print("\nDone!")
