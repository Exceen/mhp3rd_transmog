#!/usr/bin/env python3
"""Read the $ra circular buffer from the most recent save states."""

import struct
import zstandard as zstd

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

# Check multiple recent save states
for idx in [5, 2, 3]:
    path = f"/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_{idx}.ppst"
    print(f"\n{'='*60}")
    print(f"=== Save state index {idx} ===")
    data = decompress_ppst(path)

    # First verify the hook is in place
    hook_off = psp_to_offset(0x088FFF0C)
    hook_val = read_u32(data, hook_off)
    print(f"  0x088FFF0C = 0x{hook_val:08X} (expect 0x0A200140 if hooked)")

    # Check code cave
    cave_off = psp_to_offset(0x08800500)
    cave_val = read_u32(data, cave_off)
    print(f"  0x08800500 = 0x{cave_val:08X} (expect 0x3C010880 if cave installed)")

    # Read counter
    counter_off = psp_to_offset(0x088001FC)
    counter = read_u32(data, counter_off)
    print(f"  Counter at 0x088001FC = {counter}")

    # Read buffer
    from collections import Counter
    ra_values = []
    for i in range(64):
        addr = 0x08800200 + i * 4
        off = psp_to_offset(addr)
        val = read_u32(data, off)
        ra_values.append(val)

    counts = Counter(v for v in ra_values if v != 0)
    if counts:
        print(f"  Unique $ra values:")
        for val, cnt in counts.most_common():
            region = "EBOOT" if val < 0x09000000 else "OVERLAY"
            print(f"    0x{val:08X} ({region}) — {cnt} times")
    else:
        print(f"  Buffer is EMPTY")
        # Check if buffer area has any non-zero data nearby
        print(f"  Checking 0x08800100-0x08800300 for any data:")
        for addr in range(0x08800100, 0x08800300, 4):
            off = psp_to_offset(addr)
            val = read_u32(data, off)
            if val != 0:
                print(f"    0x{addr:08X} = 0x{val:08X}")

print("\nDone!")
