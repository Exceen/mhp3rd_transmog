#!/usr/bin/env python3
"""Broader search for item selector flag — find all 0→1 byte diffs."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data_off = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")
data_on = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

# Search for clean 0→1 flags across game memory
# Skip eboot code area (0x08800000-0x089FFFFF) as that's code not data
# Focus on data areas
search_ranges = [
    # Game data / globals
    (0x09800000, 0x09C00000, "Game data 0x098-0x09C"),
    # Overlay data (loaded during quest)
    (0x09C50000, 0x09E00000, "Overlay + data 0x09C5-0x09E0"),
]

for start, end, label in search_ranges:
    flags_01 = []
    for addr in range(start, end):
        off = psp_to_offset(addr)
        if off >= len(data_off) or off >= len(data_on):
            break
        v_off = data_off[off]
        v_on = data_on[off]
        if v_off == 0 and v_on == 1:
            flags_01.append(addr)

    print(f"\n=== {label}: {len(flags_01)} bytes changed 0→1 ===")
    for addr in flags_01:
        # Check if it's 4-byte aligned and looks like a standalone flag
        off = psp_to_offset(addr)
        # Check surrounding bytes for context
        ctx_off = [data_off[off-1] if off > 0 else -1,
                   data_off[off+1] if off+1 < len(data_off) else -1]
        ctx_on = [data_on[off-1] if off > 0 else -1,
                  data_on[off+1] if off+1 < len(data_on) else -1]
        aligned = "ALIGNED" if addr % 4 == 0 else f"+{addr%4}"
        # Check if this is part of button state (skip known button addresses)
        if 0x09BB7A60 <= addr <= 0x09BB7A80:
            note = " [BUTTON STATE - skip]"
        else:
            note = ""
        print(f"  0x{addr:08X} ({aligned}){note}")

# Also search for 0→nonzero (not just 0→1) in a narrower range
print("\n\n=== All 0→nonzero diffs in 0x09BB0000-0x09BD0000 ===")
for addr in range(0x09BB0000, 0x09BD0000):
    off = psp_to_offset(addr)
    if off >= len(data_off) or off >= len(data_on):
        break
    v_off = data_off[off]
    v_on = data_on[off]
    if v_off == 0 and v_on != 0:
        if 0x09BB7A60 <= addr <= 0x09BB7A80:
            continue  # skip button state
        print(f"  0x{addr:08X}: 0→{v_on} (0x{v_on:02X})")

# Search for 0→nonzero in overlay data area
print("\n=== All 0→nonzero diffs in 0x09D80000-0x09DC0000 (overlay data) ===")
count = 0
for addr in range(0x09D80000, 0x09DC0000):
    off = psp_to_offset(addr)
    if off >= len(data_off) or off >= len(data_on):
        break
    v_off = data_off[off]
    v_on = data_on[off]
    if v_off == 0 and v_on != 0:
        count += 1
        if count <= 100:
            print(f"  0x{addr:08X}: 0→{v_on} (0x{v_on:02X})")
if count > 100:
    print(f"  ... {count} total")

print("\nDone!")
