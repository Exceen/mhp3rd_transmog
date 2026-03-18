#!/usr/bin/env python3
"""Find all memory locations containing 0x088FFF0C as a function pointer."""

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

target_val = 0x088FFF0C
print(f"Searching for 0x{target_val:08X} in memory...")

# Search entire PSP memory range
for addr in range(0x08800000, 0x0A000000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val == target_val:
        # Check what's around it (vtable?)
        context = []
        for delta in range(-16, 20, 4):
            coff = psp_to_offset(addr + delta)
            if 0 <= coff and coff + 4 <= len(data):
                cv = read_u32(data, coff)
                marker = " <<<" if delta == 0 else ""
                context.append(f"    0x{addr+delta:08X}: 0x{cv:08X}{marker}")

        region = "EBOOT" if addr < 0x09000000 else "OVERLAY/RAM"
        print(f"\n  Found at 0x{addr:08X} ({region}):")
        for line in context:
            print(line)

print("\nDone!")
