#!/usr/bin/env python3
"""Diff two save states to find the item selector active flag.
Usage: python3 diff_save_states.py <closed_state.ppst> <open_state.ppst>
Looks for bytes that are 0 in closed state and non-zero in open state,
or that change between known selector state values (3->4/5/6).
"""

import struct
import sys
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_addr(offset):
    return offset - MEM_OFFSET + PSP_BASE

if len(sys.argv) < 3:
    print("Usage: python3 diff_save_states.py <closed.ppst> <open.ppst>")
    sys.exit(1)

closed_path = sys.argv[1]
open_path = sys.argv[2]

print(f"Loading closed state: {closed_path}")
closed = decompress_ppst(closed_path)
print(f"Loading open state: {open_path}")
opened = decompress_ppst(open_path)

min_len = min(len(closed), len(opened))
print(f"Decompressed sizes: closed={len(closed)}, open={len(opened)}")
print(f"Comparing {min_len} bytes...\n")

# Regions of interest (static data, likely to contain flags)
regions = [
    ("Eboot BSS 0x08A00000-0x08C60000", 0x08A00000, 0x08C60000),
    ("Overlay BSS 0x09B40000-0x09BC0000", 0x09B40000, 0x09BC0000),
    ("Overlay Data 0x09D80000-0x09DA0000", 0x09D80000, 0x09DA0000),
    ("Heap 0x09400000-0x09600000", 0x09400000, 0x09600000),
    ("Heap 0x09900000-0x09B40000", 0x09900000, 0x09B40000),
]

# Search pattern 1: byte 0->1 (boolean flag)
# Search pattern 2: byte 3->4, 3->5, 3->6, 3->10 (state byte)
# Search pattern 3: halfword 0->1 (16-bit flag)

for region_name, start, end in regions:
    start_off = start - PSP_BASE + MEM_OFFSET
    end_off = end - PSP_BASE + MEM_OFFSET
    if end_off > min_len:
        end_off = min_len

    matches_01 = []  # byte 0->1
    matches_state = []  # byte 3->4/5/6/10
    matches_hw = []  # halfword 0->1

    for off in range(start_off, end_off):
        c = closed[off]
        o = opened[off]
        if c == 0 and o == 1:
            addr = psp_to_addr(off)
            matches_01.append(addr)
        if c == 3 and o in (4, 5, 6, 10):
            addr = psp_to_addr(off)
            matches_state.append((addr, o))

    # 16-bit scan
    for off in range(start_off, end_off - 1, 2):
        c = struct.unpack_from('<H', closed, off)[0]
        o = struct.unpack_from('<H', opened, off)[0]
        if c == 0 and o == 1:
            addr = psp_to_addr(off)
            matches_hw.append(addr)

    if matches_01 or matches_state or matches_hw:
        print(f"=== {region_name} ===")
        if matches_01:
            print(f"  Byte 0->1 ({len(matches_01)} matches):")
            for addr in matches_01[:50]:
                cw = addr - 0x08800000
                print(f"    0x{addr:08X} (CW 0x{cw:07X})")
            if len(matches_01) > 50:
                print(f"    ... and {len(matches_01)-50} more")
        if matches_state:
            print(f"  Byte 3->state ({len(matches_state)} matches):")
            for addr, val in matches_state[:50]:
                cw = addr - 0x08800000
                print(f"    0x{addr:08X} (CW 0x{cw:07X}) -> {val}")
            if len(matches_state) > 50:
                print(f"    ... and {len(matches_state)-50} more")
        if matches_hw:
            print(f"  Halfword 0->1 ({len(matches_hw)} matches):")
            for addr in matches_hw[:50]:
                cw = addr - 0x08800000
                print(f"    0x{addr:08X} (CW 0x{cw:07X})")
            if len(matches_hw) > 50:
                print(f"    ... and {len(matches_hw)-50} more")
        print()

# Also do a general diff count per region
print("\n=== DIFF SUMMARY (total changed bytes per region) ===")
for region_name, start, end in regions:
    start_off = start - PSP_BASE + MEM_OFFSET
    end_off = min(end - PSP_BASE + MEM_OFFSET, min_len)
    changed = sum(1 for off in range(start_off, end_off) if closed[off] != opened[off])
    print(f"  {region_name}: {changed} bytes changed")

print("\nDone!")
