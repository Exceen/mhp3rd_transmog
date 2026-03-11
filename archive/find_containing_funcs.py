#!/usr/bin/env python3
"""Find which functions contain the unattributed render calls.
Scan backwards from each call site to find function prologue (addiu $sp, $sp, -N)."""

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

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

def find_func_start(addr):
    """Scan backwards to find function prologue: addiu $sp, $sp, -N"""
    for a in range(addr, addr - 0x2000, -4):
        off = psp_to_offset(a)
        if off < 0: break
        instr = read_u32(data, off)
        # addiu $sp, $sp, -N: op=0x09, rs=29, rt=29, imm is negative (>= 0x8000)
        op = instr >> 26
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if op == 0x09 and rs == 29 and rt == 29 and imm >= 0x8000:
            return a
    return None

# Unattributed render calls from the first scan
unattributed = [
    # sprite_render_1000
    (0x09D61290, "sprite_render_1000"),
    (0x09D615E4, "sprite_render_1000"),
    (0x09D61654, "sprite_render_1000"),
    (0x09D619B0, "sprite_render_1000"),
    (0x09D61A6C, "sprite_render_1000"),
    (0x09D61ADC, "sprite_render_1000"),
    (0x09D622D4, "sprite_render_1000"),
    # sprite_render_1168
    (0x09D5F4D4, "sprite_render_1168"),
    (0x09D5F65C, "sprite_render_1168"),
    (0x09D5F73C, "sprite_render_1168"),
    (0x09D602B0, "sprite_render_1168"),
    (0x09D615C0, "sprite_render_1168"),
    (0x09D61630, "sprite_render_1168"),
    (0x09D617C0, "sprite_render_1168"),
    # bg_render_BF0 (just a few from different areas)
    (0x09D60710, "bg_render_BF0"),
    (0x09D60CB8, "bg_render_BF0"),
    (0x09D61520, "bg_render_BF0"),
    (0x09D618D4, "bg_render_BF0"),
    # sprite_F8F0
    (0x09D621B8, "sprite_F8F0"),
    (0x09D62258, "sprite_F8F0"),
    (0x09D73154, "sprite_F8F0"),
    # render_12D8
    (0x09D603AC, "render_12D8"),
    (0x09D61828, "render_12D8"),
]

# Find containing functions
func_map = {}
for call_addr, render_name in unattributed:
    func_start = find_func_start(call_addr)
    if func_start:
        key = func_start
        if key not in func_map:
            func_map[key] = []
        func_map[key].append((call_addr, render_name))

print("=== FUNCTIONS CONTAINING RENDER CALLS ===\n")
for func_start in sorted(func_map.keys()):
    calls = func_map[func_start]
    cw = func_start - 0x08800000
    print(f"Function 0x{func_start:08X} (CW 0x{cw:07X}):")
    for call_addr, name in calls:
        print(f"  0x{call_addr:08X}: {name}")

    # Show what calls this function
    # Search for JAL to this function
    target_jal = (0x03 << 26) | (func_start >> 2)
    callers = []
    for addr in range(0x09C57C80, 0x09DA0000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == target_jal:
            callers.append(addr)
    if callers:
        print(f"  Called from:")
        for c in callers:
            ccw = c - 0x08800000
            print(f"    0x{c:08X} (CW 0x{ccw:07X})")
    else:
        print(f"  No direct callers found (indirect call?)")
    print()

print("Done!")
