#!/usr/bin/env python3
"""Read the 13-element sprite data table used by call #6 (0x09D60EA8).
$a1 = 0x09D9F3F8 (sprite table), 36 bytes per entry, 13 entries.
Also read the position table at $a2 = 0x09D9F3D4."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48
STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    return zstd.ZstdDecompressor().decompress(data[0xB0:], max_output_size=256*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = load_state(STATE)

SPRITE_TABLE = 0x09D9F3F8
ENTRY_SIZE = 36
COUNT = 13

print("=" * 70)
print(f"=== Call #6 sprite table at 0x{SPRITE_TABLE:08X} ({COUNT} entries, {ENTRY_SIZE}B each) ===")
print("=" * 70)

for i in range(COUNT):
    base = SPRITE_TABLE + i * ENTRY_SIZE
    off = psp_to_offset(base)

    # Read all fields
    type_val = read_u32(data, off)
    words = [read_u32(data, off + j*4) for j in range(ENTRY_SIZE // 4)]
    halves = [read_s16(data, off + j*2) for j in range(ENTRY_SIZE // 2)]

    print(f"\n  Element #{i} at 0x{base:08X}:")
    print(f"    Type (word 0): {type_val} (0x{type_val:08X})")
    print(f"    Words: {' '.join(f'0x{w:08X}' for w in words)}")
    print(f"    Halves: {' '.join(f'{h:6d}' for h in halves)}")

    # Highlight key fields
    # Byte at +0x0D seems to be checked in some handlers
    byte_0d = data[off + 0x0D]
    print(f"    Byte @+0x0D: {byte_0d}")

# Also read position table
POS_TABLE = 0x09D9F3D4
print(f"\n{'='*70}")
print(f"=== Position table at 0x{POS_TABLE:08X} ===")
print(f"{'='*70}")
# This is the $a2 parameter — likely a smaller table
for i in range(COUNT):
    off = psp_to_offset(POS_TABLE + i * 4)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    print(f"  [{i}] 0x{val:08X}")

# The $a2 might not be per-element. Let me dump raw bytes around it
print(f"\n  Raw bytes around 0x{POS_TABLE:08X}:")
off = psp_to_offset(POS_TABLE)
for i in range(0, 64, 16):
    hexes = ' '.join(f'{data[off+i+j]:02X}' for j in range(16))
    print(f"    0x{POS_TABLE+i:08X}: {hexes}")

print("\nDone!")
