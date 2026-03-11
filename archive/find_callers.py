#!/usr/bin/env python3
"""Find callers of key functions to understand the HP bar call chain."""

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

# Search for callers of these functions
targets = [
    0x09D62B30,  # per-player loop #2
    0x09D6380C,  # per-player loop #1 (names/icons) - for reference
    0x09D6309C,  # per-player loop #3
    0x09D62384,  # switch dispatcher
    0x09D61838,  # HP_BAR_SUB (3x sprite_1000 + bg)
    0x09D61558,  # HP_BAR_SUB2 (2x sprite_1000 + 2x sprite_1168)
    0x09D614EC,  # BG_SUB (bg_BF0)
    0x09D61248,  # sprite_1000_direct
]

NAMES = {
    0x09D62B30: "PER_PLAYER_LOOP2",
    0x09D6380C: "PER_PLAYER_LOOP1",
    0x09D6309C: "PER_PLAYER_LOOP3",
    0x09D62384: "SWITCH_DISPATCHER",
    0x09D61838: "HP_BAR_SUB",
    0x09D61558: "HP_BAR_SUB2",
    0x09D614EC: "BG_SUB",
    0x09D61248: "SPRITE_1000_DIRECT",
}

for target in targets:
    jal_opcode = (0x03 << 26) | (target >> 2)
    callers = []
    # Search both overlay and eboot
    for addr in range(0x08800000, 0x089A0000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_opcode:
            callers.append(addr)
    for addr in range(0x09C57C80, 0x09DA0000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_opcode:
            callers.append(addr)
    print(f"0x{target:08X} ({NAMES.get(target, '?')}):")
    if callers:
        for c in callers:
            cw = c - 0x08800000
            loc = "EBOOT" if c < 0x09C00000 else "OVL"
            print(f"  Called from 0x{c:08X} (CW 0x{cw:07X}) [{loc}]")
    else:
        print(f"  No JAL callers found (indirect only?)")
    print()

# Also search for J (jump) instructions to these targets (tail calls)
print("=== TAIL CALLS (J instruction) ===")
for target in targets:
    j_opcode = (0x02 << 26) | (target >> 2)
    jumpers = []
    for addr in range(0x09C57C80, 0x09DA0000, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == j_opcode:
            jumpers.append(addr)
    if jumpers:
        print(f"0x{target:08X} ({NAMES.get(target, '?')}):")
        for j in jumpers:
            cw = j - 0x08800000
            print(f"  J from 0x{j:08X} (CW 0x{cw:07X})")
        print()

print("Done!")
