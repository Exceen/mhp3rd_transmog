#!/usr/bin/env python3
"""Check which save states have the quest overlay loaded and dump 0x09D62B30."""

import struct
import zstandard as zstd
import glob

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

files = sorted(glob.glob("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_*.ppst"))

for f in files:
    try:
        data = decompress_ppst(f)
        # Check sentinel at 0x09C57C90
        sentinel_off = psp_to_offset(0x09C57C90)
        sentinel = read_u32(data, sentinel_off)
        has_overlay = (sentinel & 0xFFFF) == 0x5FA0

        # Check 0x09D62B30
        func_off = psp_to_offset(0x09D62B30)
        func_instr = read_u32(data, func_off)

        # Check HUD pointer
        hud_off = psp_to_offset(0x09BAE670)
        hud_ptr = read_u32(data, hud_off)

        # Check player count if HUD ptr valid
        count = -1
        if 0x08000000 <= hud_ptr <= 0x0A000000:
            count_off = psp_to_offset(hud_ptr + 8)
            if count_off + 4 <= len(data):
                count = read_u32(data, count_off)

        name = f.split('/')[-1]
        overlay_str = "YES" if has_overlay else "NO"
        func_str = f"0x{func_instr:08X}"
        if func_instr == 0x03E00008:
            func_str += " (jr $ra!)"
        elif (func_instr >> 26) == 0x09 and ((func_instr >> 16) & 0x1F) == 29:
            func_str += " (addiu $sp - FUNC PROLOGUE)"

        print(f"{name}: overlay={overlay_str}, 0x09D62B30={func_str}, HUD=0x{hud_ptr:08X}, count={count}")
    except Exception as e:
        print(f"{f.split('/')[-1]}: ERROR {e}")

print("\nDone!")
