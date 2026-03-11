#!/usr/bin/env python3
"""Find a stable flag for the item selector by:
1. Checking 3 save states: closed, open, and a 3rd state (different context)
2. Looking for addresses that change ONLY between closed/open
3. Checking the eboot BSS mirror 0x08A321DB and surroundings
4. Looking for addresses where closed=0 and open=non-zero that are NOT in the overlay BSS cycling region
"""

import struct
import os
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

state_dir = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"

# Load save states
closed = decompress_ppst(os.path.join(state_dir, "ULJM05800_1.02_1.ppst"))
opened = decompress_ppst(os.path.join(state_dir, "ULJM05800_1.02_2.ppst"))

# Check if there are more save states for cross-reference
states = sorted([f for f in os.listdir(state_dir)
                 if f.startswith("ULJM05800") and f.endswith(".ppst") and "undo" not in f])
print("Available save states:", states)

# 1. Check eboot BSS mirror and surroundings
print("\n=== EBOOT BSS AROUND 0x08A321DB ===")
for addr in range(0x08A321D0, 0x08A321F0):
    c = read_u8(closed, psp_to_offset(addr))
    o = read_u8(opened, psp_to_offset(addr))
    marker = " ***" if c != o else ""
    cw = addr - 0x08800000
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): closed={c} open={o}{marker}")

# 2. Find ALL bytes in eboot BSS that are 3 when closed and 4+ when open
print("\n=== EBOOT BSS 0x08A00000-0x08C60000: bytes 3->4/5/6/10 ===")
eboot_candidates = []
for addr in range(0x08A00000, 0x08C60000):
    c = read_u8(closed, psp_to_offset(addr))
    o = read_u8(opened, psp_to_offset(addr))
    if c == 3 and o in (4, 5, 6, 10):
        cw = addr - 0x08800000
        eboot_candidates.append((addr, c, o))
        if len(eboot_candidates) <= 30:
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): {c}->{o}")

if len(eboot_candidates) > 30:
    print(f"  ... and {len(eboot_candidates)-30} more (total: {len(eboot_candidates)})")
elif len(eboot_candidates) == 0:
    print("  (none found)")

# 3. Find bytes that are 0 when closed and exactly 1 when open in eboot BSS
# These are boolean flags - potentially more stable
print("\n=== EBOOT BSS: bytes 0->1 (boolean flags) ===")
bool_candidates = []
for addr in range(0x08A00000, 0x08C60000):
    c = read_u8(closed, psp_to_offset(addr))
    o = read_u8(opened, psp_to_offset(addr))
    if c == 0 and o == 1:
        cw = addr - 0x08800000
        bool_candidates.append(addr)
        if len(bool_candidates) <= 30:
            print(f"  0x{addr:08X} (CW 0x{cw:07X})")

if len(bool_candidates) > 30:
    print(f"  ... and {len(bool_candidates)-30} more (total: {len(bool_candidates)})")
elif len(bool_candidates) == 0:
    print("  (none found)")

# 4. Check the pointer chain in the current save states
print("\n=== POINTER CHAIN CHECK ===")
for name, data in [("closed", closed), ("open", opened)]:
    p1 = read_u32(data, psp_to_offset(0x09BB7A80))
    if 0x08000000 <= p1 <= 0x0A000000:
        p2 = read_u32(data, psp_to_offset(p1 + 8))
        if 0x08000000 <= p2 <= 0x0A000000:
            state = read_u8(data, psp_to_offset(p2 + 98))
            state_addr = p2 + 98
            cw = state_addr - 0x08800000
            print(f"  {name}: ptr1=0x{p1:08X}, ptr2=0x{p2:08X}, state@0x{state_addr:08X}(CW 0x{cw:07X})={state}")
        else:
            print(f"  {name}: ptr1=0x{p1:08X}, ptr2=0x{p2:08X} (out of range)")
    else:
        print(f"  {name}: ptr1=0x{p1:08X} (out of range)")

# 5. Look at the specific object structure around the state byte
# The UI object has state at +98 (0x62). Check if there's a more stable field
# that indicates the object is "visible" or "active" separately from the state machine
print("\n=== UI OBJECT FIELDS (from pointer chain) ===")
for name, data in [("closed", closed), ("open", opened)]:
    p1 = read_u32(data, psp_to_offset(0x09BB7A80))
    if 0x08000000 <= p1 <= 0x0A000000:
        p2 = read_u32(data, psp_to_offset(p1 + 8))
        if 0x08000000 <= p2 <= 0x0A000000:
            print(f"  {name} (object at 0x{p2:08X}):")
            # Check various offsets that might be flags
            for off in range(0, 256, 4):
                val = read_u32(data, psp_to_offset(p2 + off))
                if val != 0:
                    print(f"    +0x{off:03X}: 0x{val:08X}")

# 6. Cross-reference: use 3rd save state if available
if len(states) >= 3:
    third_name = states[2]
    print(f"\n=== CROSS-REFERENCE WITH {third_name} ===")
    third = decompress_ppst(os.path.join(state_dir, third_name))

    # Check the 3->4 candidates: which ones are also 3 in the third state?
    print("Eboot BSS 3->4 candidates check:")
    for addr, c, o in eboot_candidates[:30]:
        t = read_u8(third, psp_to_offset(addr))
        cw = addr - 0x08800000
        marker = " (stable base)" if t == c else f" (third={t})"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): state1={c} state2={o} state3={t}{marker}")

# 7. Check if there's a count or timer field that indicates open duration
print("\n=== POTENTIAL TIMER/COUNTER FIELDS ===")
# Look for 16-bit values in eboot BSS that go from 0 to a small positive number
timer_candidates = []
for addr in range(0x08A00000, 0x08C60000, 2):
    c = read_u16(closed, psp_to_offset(addr))
    o = read_u16(opened, psp_to_offset(addr))
    if c == 0 and 1 < o < 1000:
        timer_candidates.append((addr, o))

print(f"  16-bit 0->N (1<N<1000): {len(timer_candidates)} candidates")
for addr, val in timer_candidates[:20]:
    cw = addr - 0x08800000
    print(f"    0x{addr:08X} (CW 0x{cw:07X}): 0->{val}")

print("\nDone!")
