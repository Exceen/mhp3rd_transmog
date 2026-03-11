#!/usr/bin/env python3
"""Check if the selector object pointer is stable across save states."""

import struct
import zstandard as zstd
import os

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
    if off + 4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    if off + 1 > len(data): return None
    return struct.unpack_from('<B', data, off)[0]

state_dir = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"
states = sorted([f for f in os.listdir(state_dir) if f.startswith("ULJM05800") and f.endswith(".ppst") and "undo" not in f])

print("=== POINTER CHAIN STABILITY CHECK ===")
print(f"Chain: *(0x09BB7A80) -> ptr1, *(ptr1+8) -> ptr2, byte@(ptr2+98) = state")
print()

for fname in states:
    path = os.path.join(state_dir, fname)
    try:
        d = decompress_ppst(path)
        p1 = read_u32(d, psp_to_offset(0x09BB7A80))
        p2 = None
        state_byte = None
        if p1 and 0x08000000 <= p1 <= 0x0A000000:
            p2 = read_u32(d, psp_to_offset(p1 + 8))
            if p2 and 0x08000000 <= p2 <= 0x0A000000:
                state_byte = read_u8(d, psp_to_offset(p2 + 98))
        p1_str = "0x{:08X}".format(p1) if p1 else "NULL"
        p2_str = "0x{:08X}".format(p2) if p2 else "NULL"
        state_str = str(state_byte) if state_byte is not None else "?"
        print(f"  {fname}: ptr1={p1_str}, ptr2={p2_str}, state={state_str}")

        # Also check the overlay sentinel to see if we're in quest
        sentinel = read_u32(d, psp_to_offset(0x08C57C90))
        sent_str = "0x{:04X}".format(sentinel & 0xFFFF) if sentinel else "?"
        in_quest = "YES" if sentinel and (sentinel & 0xFFFF) != 0x5FA0 else "NO"
        print(f"    sentinel=0x{sentinel:08X}, in_quest={in_quest}")
    except Exception as e:
        print(f"  {fname}: ERROR: {e}")

# Also check if 0x09541310 is at a fixed offset from the overlay base
print("\n\n=== ALTERNATIVE: CHECK OVERLAY CONTEXT POINTERS ===")
# The overlay base is 0x09C57C80
# Maybe the UI context is at a fixed offset in overlay data?
d = decompress_ppst(os.path.join(state_dir, "ULJM05800_1.02_4.ppst"))

# Scan overlay data area for pointer 0x09541310
print("Scanning 0x09D80000-0x09DA0000 for pointer 0x09541310:")
target = 0x09541310
for addr in range(0x09D80000, 0x09DA0000, 4):
    off = psp_to_offset(addr)
    val = read_u32(d, off)
    if val == target:
        print(f"  FOUND: 0x{addr:08X} contains 0x{target:08X}")

# Scan wider area
print("Scanning 0x09B40000-0x09BC0000 for pointer 0x09541310:")
for addr in range(0x09B40000, 0x09BC0000, 4):
    off = psp_to_offset(addr)
    val = read_u32(d, off)
    if val == target:
        print(f"  FOUND: 0x{addr:08X} contains 0x{target:08X}")

# Also check: does the item selector function 0x09D60D88's caller pass
# the UI context from a known static location?
# Let's check the parent function 0x09D6C498 area
print("\n\n=== CHECKING PARENT FUNCTION 0x09D6C498 FOR CONTEXT LOADING ===")
# This function renders the HUD. It calls 0x09D60D88 somewhere.
# Let's find where and trace $a0
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(d, off)
    if instr is None: break
    # Check for jal 0x09D60D88
    if (instr >> 26) == 0x03:
        target_func = (instr & 0x03FFFFFF) << 2
        if target_func == 0x09D60D88:
            print(f"  Found call at 0x{addr:08X}")
            # Show surrounding instructions
            for back in range(8, 0, -1):
                ba = addr - back * 4
                bo = psp_to_offset(ba)
                bi = read_u32(d, bo)
                from find_selector_flag2 import disasm
                bd = disasm(bi, ba)
                print(f"    0x{ba:08X}: {bd}")
            bi = read_u32(d, psp_to_offset(addr))
            bd = disasm(bi, addr)
            print(f"    0x{addr:08X}: {bd} [*** CALL ***]")

print("\nDone!")
