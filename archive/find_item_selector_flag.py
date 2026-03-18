#!/usr/bin/env python3
"""Diff two save states to find the item selector active flag.
State 5 = no item selector, State 6 = item selector open."""

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

def read_u8(data, off):
    return data[off]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data_off = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")
data_on = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

# Search key areas for byte-level diffs
# Focus on areas likely to hold UI state
search_ranges = [
    ("HUD object area (0x09DD0C00-0x09DD1000)", 0x09DD0C00, 0x09DD1000),
    ("HUD ptr area (0x09BF5200-0x09BF5400)", 0x09BF5200, 0x09BF5400),
    ("Overlay data near UI (0x09D90000-0x09D92000)", 0x09D90000, 0x09D92000),
    ("Game state area (0x09BB7A00-0x09BB7C00)", 0x09BB7A00, 0x09BB7C00),
    ("Overlay globals (0x09DA9000-0x09DAA000)", 0x09DA9000, 0x09DAA000),
]

for label, start, end in search_ranges:
    diffs = []
    for addr in range(start, end):
        off = psp_to_offset(addr)
        if off >= len(data_off) or off >= len(data_on):
            break
        v_off = data_off[off]
        v_on = data_on[off]
        if v_off != v_on:
            diffs.append((addr, v_off, v_on))

    if diffs:
        print(f"\n=== {label}: {len(diffs)} byte diffs ===")
        for addr, v_off, v_on in diffs[:50]:  # limit output
            # Check if this looks like a simple flag (0→1 or 0→nonzero)
            flag_marker = ""
            if v_off == 0 and v_on == 1: flag_marker = " *** POSSIBLE FLAG (0→1) ***"
            elif v_off == 0 and v_on != 0: flag_marker = f" (0→{v_on})"
            elif v_off == 1 and v_on == 0: flag_marker = " (1→0, inverted flag?)"
            print(f"  0x{addr:08X}: {v_off:3d} → {v_on:3d} (0x{v_off:02X}→0x{v_on:02X}){flag_marker}")
        if len(diffs) > 50:
            print(f"  ... and {len(diffs) - 50} more")
    else:
        print(f"\n=== {label}: NO diffs ===")

# Also check the HUD object flag at +0x54 mentioned in memory
print("\n=== HUD object 0x09DD0CF0 + 0x54 = 0x09DD0D44 ===")
for data, label in [(data_off, "OFF"), (data_on, "ON")]:
    off = psp_to_offset(0x09DD0D44)
    val = read_u32(data, off)
    print(f"  {label}: 0x{val:08X}")

# Check broader area around HUD object
print("\n=== HUD object 0x09DD0CF0-0x09DD0E00 (32-bit values) ===")
for addr in range(0x09DD0CF0, 0x09DD0E00, 4):
    off = psp_to_offset(addr)
    v_off = read_u32(data_off, off)
    v_on = read_u32(data_on, off)
    if v_off != v_on:
        delta = f"+0x{addr - 0x09DD0CF0:02X}"
        print(f"  0x{addr:08X} ({delta}): 0x{v_off:08X} → 0x{v_on:08X}")

print("\nDone!")
