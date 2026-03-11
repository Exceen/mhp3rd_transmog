#!/usr/bin/env python3
"""Read the clock sprite data entries to understand the layout table structure."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
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

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

data = decompress_ppst(PPST_FILE)

# Layout table base from code: lui 0x09D9, addiu 11440 → 0x09D92CB0
LAYOUT_BASE = 0x09D92CB0

# Sprite data addresses used in CLOCK1
clock_sprites = {
    "CLOCK1_frame1": 0x09D92CF8,   # addiu 11512
    "CLOCK1_frame2": 0x09D92D1C,   # addiu 11548
    "CLOCK1_flash2": 0x09D92E84,   # addiu 11908
    "CLOCK1_flash3": 0x09D92D40,   # addiu 11584
    "CLOCK1_flash3b": 0x09D92E98,  # addiu 11944 (estimated)
    "CLOCK1_mode1_1": 0x09D92D40,  # addiu 11584
    "CLOCK1_mode1_2": 0x09D92D7C,  # addiu 11644 (estimated)
    "CLOCK1_mode1_3": 0x09D92D98,  # addiu 11672 (estimated)
}

# Let me just dump entries around the base
print("=== LAYOUT TABLE ENTRIES (0x09D92CB0+) ===")
print("Each entry: 36 bytes")
print(f"{'Entry':>5} {'Addr':>12} | bytes 0-3 | bytes 4-7 | ... | +24(X?) | +26(Y?) | +28-35")
print("-" * 100)

for i in range(30):
    addr = LAYOUT_BASE + i * 36
    off = psp_to_offset(addr)
    if off + 36 > len(data): break

    # Read key fields
    w0 = read_u32(data, off)
    w1 = read_u32(data, off + 4)
    w2 = read_u32(data, off + 8)
    w3 = read_u32(data, off + 12)
    w4 = read_u32(data, off + 16)
    w5 = read_u32(data, off + 20)
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)
    w7 = read_u32(data, off + 28)
    w8 = read_u32(data, off + 32)

    # Calculate CW addr for X field
    x_addr = addr + 24
    cw_x = x_addr - 0x08800000

    marker = ""
    if addr in clock_sprites.values():
        for name, a in clock_sprites.items():
            if a == addr:
                marker = f" ← {name}"
                break

    print(f"  [{i:2d}] 0x{addr:08X}: "
          f"{w0:08X} {w1:08X} {w2:08X} {w3:08X} {w4:08X} {w5:08X} "
          f"X={x:4d} Y={y:4d} {w7:08X} {w8:08X}{marker}"
          f"  (X@CW 0x{cw_x:07X})")

# Also read the specific addresses from CLOCK1 code
print("\n\n=== CLOCK1 SPRITE DATA ADDRESSES ===")
sprite_addrs = [
    (0x09D92CF8, "frame1 (addiu 11512)"),
    (0x09D92D1C, "frame2 (addiu 11548)"),
    (0x09D92E84, "flash_mode2 (addiu 11908)"),
    (0x09D92D40, "mode3_sub (addiu 11584)"),
    (0x09D92E98, "flash_mode3 (addiu 11944)"),
    (0x09D92D7C, "mode1_sub2 (addiu 11620)"),
    (0x09D92D98, "mode1_sub3 (addiu 11656)"),
    (0x09D92E54, "mode1_flash (addiu 11860)"),
    (0x09D92EBC, "mode1_flash2 (addiu 11980)"),
    (0x09D92DAC, "mode3_sub2 (addiu 11692)"),
]

for addr, name in sprite_addrs:
    off = psp_to_offset(addr)
    if off + 36 > len(data):
        print(f"  0x{addr:08X} ({name}): OUT OF BOUNDS")
        continue
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)
    w0 = read_u32(data, off)
    entry_idx = (addr - LAYOUT_BASE) / 36
    cw_x = (addr + 24) - 0x08800000
    print(f"  0x{addr:08X} ({name:20s}): entry={entry_idx:5.1f}  X={x:4d} Y={y:4d}  (X@CW 0x{cw_x:07X})")

# Also read the CLOCK2 table
print("\n\n=== CLOCK2 DIGIT TABLE ===")
# CLOCK2: $s0 = lui 0x09D9, addiu -8016 = 0x09D90000 + (-8016) = 0x09D8E0B0
# Wait, addiu with negative: 0x09D90000 + 0xFFFFE0B0 = 0x09D8E0B0? No...
# lui 0x09D9 = 0x09D90000, addiu -8016 = 0x09D90000 + (-8016) = 0x09D90000 - 8016
# 8016 = 0x1F50, so 0x09D90000 - 0x1F50 = 0x09D8E0B0
CLOCK2_TABLE = 0x09D8E0B0
print(f"CLOCK2 digit table at 0x{CLOCK2_TABLE:08X}")
for i in range(8):
    addr = CLOCK2_TABLE + i * 4
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    h0 = read_s16(data, off)
    h1 = read_s16(data, off + 2)
    print(f"  [{i}] 0x{addr:08X}: 0x{val:08X} (h0={h0}, h1={h1})")

print("\nDone!")
