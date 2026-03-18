#!/usr/bin/env python3
"""Check item selector flag candidates from both save states.
Index 5 = selector OPEN, Index 6 = selector CLOSED."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        return zstd.ZstdDecompressor().decompress(f.read(), max_output_size=64*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return data[off]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data_closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")
data_open = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Check specific candidates from earlier
candidates = [0x09BE9F80, 0x09BE9F5C, 0x09BB6730]

for addr in candidates:
    off = psp_to_offset(addr)
    v_closed_32 = read_u32(data_closed, off)
    v_open_32 = read_u32(data_open, off)
    v_closed_8 = read_u8(data_closed, off)
    v_open_8 = read_u8(data_open, off)
    v_closed_16 = read_u16(data_closed, off)
    v_open_16 = read_u16(data_open, off)
    cw_off = addr - 0x08800000
    print(f"0x{addr:08X} (CW offset 0x{cw_off:07X}):")
    print(f"  byte:  closed={v_closed_8:#04x} open={v_open_8:#04x}")
    print(f"  half:  closed={v_closed_16:#06x} open={v_open_16:#06x}")
    print(f"  word:  closed={v_closed_32:#010x} open={v_open_32:#010x}")
    print(f"  D-type byte:  _L 0xD0{cw_off:07X} 0x000000{v_open_8:02X}")
    print(f"  D-type half:  _L 0xD1{cw_off:07X} 0x0000{v_open_16:04X}")
    print(f"  D-type word:  _L 0xD2{cw_off:07X} 0x{v_open_32:08X}")
    print()

# Also dump context around 0x09BE9F80 to understand the data structure
print("=== Context around 0x09BE9F80 (16 words before/after) ===")
for addr in range(0x09BE9F40, 0x09BE9FC0, 4):
    off = psp_to_offset(addr)
    vc = read_u32(data_closed, off)
    vo = read_u32(data_open, off)
    diff = " ***" if vc != vo else ""
    print(f"  0x{addr:08X}: closed=0x{vc:08X} open=0x{vo:08X}{diff}")

# Search for state-machine-like values (0→1, 0→2, 0→3, etc.) in HUD area
# Focus on 0x09BE0000-0x09BF0000 (game state area)
print("\n=== State machine candidates in 0x09BD0000-0x09BF0000 ===")
print("  (word: closed=0 → open=1-10)")
for addr in range(0x09BD0000, 0x09BF0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_closed) or off + 4 > len(data_open): break
    vc = read_u32(data_closed, off)
    vo = read_u32(data_open, off)
    if vc == 0 and 1 <= vo <= 10:
        cw_off = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw_off:07X}): 0 → {vo}")

# Also check for values where open has a different small value
print("\n=== State machine: both non-zero, different (1-20) in 0x09BD0000-0x09BF0000 ===")
for addr in range(0x09BD0000, 0x09BF0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_closed) or off + 4 > len(data_open): break
    vc = read_u32(data_closed, off)
    vo = read_u32(data_open, off)
    if 1 <= vc <= 20 and 1 <= vo <= 20 and vc != vo:
        cw_off = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw_off:07X}): {vc} → {vo}")

print("\nDone!")
