#!/usr/bin/env python3
"""Read the sharpness indicator data entries referenced by the render function."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

# Data addresses referenced by the sharpness render function at 0x09D71F38:
# These are computed as lui 0x09DC + addiu negative
data_addrs = {
    "BB18 (a2 common)": 0x09DBBB18,   # addiu $a2, $s6, -17640 (lui $s6, 0x09DC)
    "BB3C (a1 call1)":  0x09DBBB3C,   # addiu $a1, $a1, -17604
    "BBA8 (a1 call2)":  0x09DBBBA8,   # addiu $a1, $a1, -17496
    "BBF0 (a1 call3)":  0x09DBBBF0,   # addiu $a1, $a1, -17424
    "BCEC (a1 bar1)":   0x09DBBCEC,   # addiu $a1, $a1, -17172
    "BAF4 (a1 bar2)":   0x09DBBAF4,   # addiu $a1, $a1, -17676
    "BA64 (data table)": 0x09DBBA64,  # addiu $a0, $v0, -17820
    "BCBC (loop data)":  0x09DBBCBC,  # addiu $s2, $v0, -17220
}

for label, addr in data_addrs.items():
    off = psp_to_offset(addr)
    if off + 36 > len(data):
        print(f"\n=== {label} at 0x{addr:08X}: OUT OF RANGE ===")
        continue
    print(f"\n=== {label} at 0x{addr:08X} ===")
    # Dump as 36-byte entry (like HP bar entries)
    for i in range(0, 36, 2):
        val = read_u16(data, off + i)
        sval = read_s16(data, off + i)
        label2 = ""
        if i == 0: label2 = "x1 (texture)"
        elif i == 2: label2 = "y1 (texture)"
        elif i == 4: label2 = "x2 (texture)"
        elif i == 6: label2 = "y2 (texture)"
        elif i == 24: label2 = "X POSITION <<<<<<"
        elif i == 26: label2 = "Y POSITION <<<<<<"
        elif i == 28: label2 = "field_28"
        elif i == 30: label2 = "field_30"
        print(f"  +{i:2d} (0x{addr+i:08X}): 0x{val:04X} ({sval:6d})  {label2}")

# Also dump a few more entries after BCBC to see the loop data
print(f"\n=== Multiple entries starting at 0x09DBBCBC (36-byte stride) ===")
for entry_idx in range(5):
    addr = 0x09DBBCBC + entry_idx * 36
    off = psp_to_offset(addr)
    if off + 36 > len(data): break
    x_pos = read_s16(data, off + 24)
    y_pos = read_s16(data, off + 26)
    x1 = read_s16(data, off + 0)
    y1 = read_s16(data, off + 2)
    x2 = read_s16(data, off + 4)
    y2 = read_s16(data, off + 6)
    print(f"  Entry {entry_idx} at 0x{addr:08X}: tex({x1},{y1})-({x2},{y2}) pos=({x_pos},{y_pos})")

# Also check the broader data area for patterns
print(f"\n=== Scanning 0x09DBB900-0x09DBBE00 for position-like values at +24/+26 ===")
for addr in range(0x09DBB900, 0x09DBBE00, 36):
    off = psp_to_offset(addr)
    if off + 36 > len(data): break
    x_pos = read_s16(data, off + 24)
    y_pos = read_s16(data, off + 26)
    x1 = read_u16(data, off + 0)
    y1 = read_u16(data, off + 2)
    x2 = read_u16(data, off + 4)
    y2 = read_u16(data, off + 6)
    if x1 != 0 or y1 != 0 or x2 != 0 or y2 != 0 or x_pos != 0 or y_pos != 0:
        print(f"  0x{addr:08X}: tex({x1},{y1})-({x2},{y2}) pos=({x_pos},{y_pos})")

print("\nDone!")
