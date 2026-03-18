#!/usr/bin/env python3
"""Find the item selector flag by reading $s2 from 0x088000FC and scanning the HUD object."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE_CLOSED = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
STATE_OPEN   = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    return zstd.ZstdDecompressor().decompress(data[0xB0:], max_output_size=256*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Read $s2 from 0x088000FC
s2_c = read_u32(mem_c, psp_to_offset(0x088000FC))
s2_o = read_u32(mem_o, psp_to_offset(0x088000FC))
print(f"$s2 address: CLOSED=0x{s2_c:08X}  OPEN=0x{s2_o:08X}")

# Also read the flag byte at 0x088000F8
flag_c = mem_c[psp_to_offset(0x088000F8)]
flag_o = mem_o[psp_to_offset(0x088000F8)]
print(f"Flag at 0x088000F8: CLOSED={flag_c}  OPEN={flag_o}")

if s2_c == 0 and s2_o == 0:
    print("\nERROR: $s2 not stored! The overlay hook might not have run.")
    print("Check that 'Item Sel State Flag (overlay hook)' is enabled.")
    exit(1)

s2 = s2_c if s2_c != 0 else s2_o
print(f"\nUsing $s2 = 0x{s2:08X}")

# Check key offsets mentioned in the code
print(f"\n{'='*70}")
print(f"=== Key $s2 offsets ===")
print(f"{'='*70}")
key_offsets = [
    (0x008, "$s2+0x008 (player count?)"),
    (0x180, "$s2+0x180 (HUD mode flag)"),
    (0x347C, "$s2+0x347C (render path selector)"),
    (0x347D, "$s2+0x347D (cleared by render)"),
    (0x3474, "$s2+0x3474 (position X)"),
    (0x3476, "$s2+0x3476 (position Y)"),
    (0x3488, "$s2+0x3488 (sprite data)"),
    (0x348A, "$s2+0x348A (sprite data)"),
    (0x348C, "$s2+0x348C (sprite data)"),
    (0x348E, "$s2+0x348E (sprite data)"),
    (0x34A0, "$s2+0x34A0"),
    (0x34A2, "$s2+0x34A2"),
    (0x3DA0, "$s2+0x3DA0 (render enable)"),
    (0x716, "$s2+0x716 (state machine state)"),
    (0x1ABC, "$s2+0x1ABC (sub-state 1)"),
    (0x1B20, "$s2+0x1B20 (sub-state 2)"),
    (0x1B80, "$s2+0x1B80 (sub-state 3)"),
]

for off, name in key_offsets:
    addr = s2 + off
    state_off = psp_to_offset(addr)
    if state_off + 4 > len(mem_c) or state_off + 4 > len(mem_o):
        print(f"  {name}: OUT OF RANGE")
        continue
    bc = mem_c[state_off]
    bo = mem_o[state_off]
    wc = read_u32(mem_c, state_off)
    wo = read_u32(mem_o, state_off)
    hc = read_u16(mem_c, state_off)
    ho = read_u16(mem_o, state_off)
    d = " ***" if bc != bo else ""
    wd = " ***" if wc != wo else ""
    print(f"  {name} (0x{addr:08X}):")
    print(f"    byte: C={bc}  O={bo}{d}")
    print(f"    half: C=0x{hc:04X}  O=0x{ho:04X}")
    print(f"    word: C=0x{wc:08X}  O=0x{wo:08X}{wd}")

# Full byte scan of $s2 object (size ~0x4000 based on offsets)
print(f"\n{'='*70}")
print(f"=== Full byte scan of $s2 object (0x4000 bytes) ===")
print(f"{'='*70}")
diffs = []
for off in range(0, 0x4000):
    addr = s2 + off
    state_off = psp_to_offset(addr)
    if state_off + 1 > len(mem_c) or state_off + 1 > len(mem_o):
        break
    bc = mem_c[state_off]
    bo = mem_o[state_off]
    if bc != bo:
        diffs.append((off, addr, bc, bo))

print(f"Total byte differences: {len(diffs)}")

# Show small/clean differences (likely flags, not floats/animations)
print(f"\n  Clean flag-like differences (one is 0, other is 0-10):")
for off, addr, bc, bo in diffs:
    if (bc == 0 and 1 <= bo <= 10) or (bo == 0 and 1 <= bc <= 10):
        print(f"    +0x{off:04X} (0x{addr:08X}): C={bc}  O={bo}")

print(f"\n  Small differences (delta < 5):")
for off, addr, bc, bo in diffs:
    if abs(bc - bo) <= 4 and abs(bc - bo) > 0:
        print(f"    +0x{off:04X} (0x{addr:08X}): C={bc}  O={bo}")

print(f"\n  All differences:")
for off, addr, bc, bo in diffs:
    print(f"    +0x{off:04X} (0x{addr:08X}): C=0x{bc:02X}  O=0x{bo:02X}")

print("\nDone!")
