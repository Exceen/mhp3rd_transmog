#!/usr/bin/env python3
"""Check all bytes in the item selector's eboot BSS entry (0x120 bytes starting
near 0x08A321DB) to find stable sub-fields that distinguish closed vs open."""

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

state_dir = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"
states = sorted([f for f in os.listdir(state_dir)
                 if f.startswith("ULJM05800") and f.endswith(".ppst") and "undo" not in f])

# Load all states
all_data = {}
for fname in states:
    all_data[fname] = decompress_ppst(os.path.join(state_dir, fname))

# State byte at 0x08A321DB = entry 0's state
# Entry base is somewhere before 0x08A321DB
# Check from 0x08A32170 to 0x08A322FA (entry 0's full range)
# Entry stride = 0x120, so entry goes from state_byte - X to state_byte + (0x120 - X)

# Let's just check the full 0x120 bytes centered around the state byte
entry_start = 0x08A321DB - 0xDB  # Guess: state at offset 0xDB? Let's try from -0x80
scan_start = 0x08A32100  # well before entry start
scan_end = 0x08A322FB    # next entry's state byte

print(f"=== ITEM SELECTOR ENTRY FIELDS (0x{scan_start:08X} - 0x{scan_end:08X}) ===")
print(f"State byte at 0x08A321DB")
print(f"Next entry state at 0x08A322FB")
print()

# Identify which save states have selector closed vs open vs other
# From previous: state 3=closed, 4+=active, 0=not loaded
state_labels = {}
for fname in states:
    val = read_u8(all_data[fname], psp_to_offset(0x08A321DB))
    if val == 3:
        state_labels[fname] = "CLOSED"
    elif val in (4, 5, 6, 10):
        state_labels[fname] = "OPEN"
    elif val == 0:
        state_labels[fname] = "UNLOADED"
    else:
        state_labels[fname] = f"OTHER({val})"

print("Save state classification:")
for fname in states:
    print(f"  {fname}: {state_labels[fname]}")

# Find bytes that are CONSISTENTLY different between CLOSED and OPEN states
closed_states = [f for f in states if state_labels[f] == "CLOSED"]
open_states = [f for f in states if state_labels[f] == "OPEN"]

print(f"\nClosed states: {len(closed_states)}, Open states: {len(open_states)}")

if closed_states and open_states:
    print(f"\n=== BYTES THAT DIFFER BETWEEN CLOSED AND OPEN ===")
    for addr in range(scan_start, scan_end):
        closed_vals = set()
        open_vals = set()
        for f in closed_states:
            closed_vals.add(read_u8(all_data[f], psp_to_offset(addr)))
        for f in open_states:
            open_vals.add(read_u8(all_data[f], psp_to_offset(addr)))

        if closed_vals & open_vals:
            continue  # overlapping values, not discriminating

        if len(closed_vals) == 1 and len(open_vals) == 1:
            cv = list(closed_vals)[0]
            ov = list(open_vals)[0]
            off = addr - 0x08A321DB
            cw = addr - 0x08800000
            print(f"  0x{addr:08X} (CW 0x{cw:07X}, off={off:+d}): closed={cv} open={ov}")

            # Show all states for this address
            for fname in states:
                val = read_u8(all_data[fname], psp_to_offset(addr))
                print(f"    {fname}: {val} ({state_labels[fname]})")

# Also specifically look for bytes where:
# - ALL closed states have value X
# - ALL open states have value Y != X
# - UNLOADED/OTHER states don't matter (we'll use sentinel guard)
print(f"\n=== DISCRIMINATING BYTES (closed-consistent vs open-consistent) ===")
discriminating = []
for addr in range(scan_start, scan_end):
    closed_vals = set()
    open_vals = set()
    for f in closed_states:
        closed_vals.add(read_u8(all_data[f], psp_to_offset(addr)))
    for f in open_states:
        open_vals.add(read_u8(all_data[f], psp_to_offset(addr)))

    # Single consistent value for closed, single consistent for open, different
    if len(closed_vals) == 1 and len(open_vals) == 1 and closed_vals != open_vals:
        cv = list(closed_vals)[0]
        ov = list(open_vals)[0]
        off = addr - 0x08A321DB
        cw = addr - 0x08800000

        # Check unloaded/other values
        other_vals = {}
        for f in states:
            if f not in closed_states and f not in open_states:
                other_vals[state_labels[f]] = read_u8(all_data[f], psp_to_offset(addr))

        discriminating.append((addr, cv, ov, other_vals))
        print(f"  0x{addr:08X} (CW 0x{cw:07X}, off={off:+d}): closed={cv} open={ov} others={other_vals}")

# Also check the overlay BSS entry for comparison
print(f"\n=== OVERLAY BSS AROUND 0x09BB5CA7 ===")
for addr in range(0x09BB5C00, 0x09BB5D20):
    closed_vals = set()
    open_vals = set()
    for f in closed_states:
        closed_vals.add(read_u8(all_data[f], psp_to_offset(addr)))
    for f in open_states:
        open_vals.add(read_u8(all_data[f], psp_to_offset(addr)))

    if len(closed_vals) == 1 and len(open_vals) == 1 and closed_vals != open_vals:
        cv = list(closed_vals)[0]
        ov = list(open_vals)[0]
        off = addr - 0x09BB5CA7
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x{cw:07X}, off={off:+d}): closed={cv} open={ov}")

print("\nDone!")
