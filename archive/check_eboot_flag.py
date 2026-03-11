#!/usr/bin/env python3
"""Check 0x08A321DB and related eboot BSS candidates across ALL save states.
Also look at the 0x08B68A79 array pattern and boolean flags."""

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
states = sorted([f for f in os.listdir(state_dir)
                 if f.startswith("ULJM05800") and f.endswith(".ppst") and "undo" not in f])

# Key addresses to check
addrs = {
    "0x08A321DB (eboot BSS mirror)": 0x08A321DB,
    "0x08A322FB (eboot BSS +0x120)": 0x08A322FB,
    "0x09BB5CA7 (overlay BSS orig)": 0x09BB5CA7,
    "0x08B68A79 (array elem 0)": 0x08B68A79,
    "0x08B68A7D (array elem 1)": 0x08B68A7D,
    "0x08B68A81 (array elem 2)": 0x08B68A81,
}

# Also check the structure around 0x08A321DB
# Offset from some base: 0x08A321DB - 0x08A321D0 = 0xB
# At +0xB from some structure base. In the callers, +98 (0x62) is the state byte.
# But 0xB != 0x62, so this is a different structure layout.

# Check if 0x08A321DB is at offset +0x62 from some base
# Base would be 0x08A321DB - 0x62 = 0x08A32179
# Or maybe it's part of an array with different entry size
# 0x08A322FB - 0x08A321DB = 0x120 = 288 bytes between entries

print("=== KEY ADDRESSES ACROSS ALL SAVE STATES ===")
print(f"{'State':<30}", end="")
for label in addrs:
    short = label.split("(")[0].strip()
    print(f" {short:>14}", end="")
print()

for fname in states:
    data = decompress_ppst(os.path.join(state_dir, fname))
    print(f"{fname:<30}", end="")
    for label, addr in addrs.items():
        val = read_u8(data, psp_to_offset(addr))
        print(f" {val:>14}", end="")
    print()

# Check the structure containing 0x08A321DB
print("\n=== STRUCTURE AT 0x08A321DB - look for pattern ===")
# entry_size = 0x120 = 288 bytes
# Check if entries repeat at this stride
base = 0x08A321DB
stride = 0x120
data = decompress_ppst(os.path.join(state_dir, states[0]))  # closed state
data2 = decompress_ppst(os.path.join(state_dir, states[1] if len(states) > 1 else states[0]))

print(f"Entry stride = 0x{stride:X} = {stride} bytes")
print(f"Checking entries at base + N*stride:")
for i in range(20):
    addr = base + i * stride
    if addr > 0x08C60000:
        break
    v1 = read_u8(data, psp_to_offset(addr))
    v2 = read_u8(data2, psp_to_offset(addr))
    cw = addr - 0x08800000
    marker = " ***" if v1 != v2 else ""
    print(f"  Entry {i}: 0x{addr:08X} (CW 0x{cw:07X}): state1={v1} state2={v2}{marker}")

# Check the boolean flag candidates more carefully
print("\n=== BOOLEAN FLAGS IN EBOOT BSS ===")
bool_addrs = [0x08A332D5, 0x08A332D7, 0x08A339B8, 0x08A33A94, 0x08A33C78, 0x08A33E04]
print(f"{'Address':<18} {'CW':<12}", end="")
for fname in states[:4]:
    print(f" {fname[:20]:>20}", end="")
print()
for addr in bool_addrs:
    cw = addr - 0x08800000
    print(f"0x{addr:08X}  CW 0x{cw:07X}", end="")
    for fname in states[:4]:
        d = decompress_ppst(os.path.join(state_dir, fname))
        val = read_u8(d, psp_to_offset(addr))
        print(f" {val:>20}", end="")
    print()

# What's the context around 0x08A332D5?
print("\n=== CONTEXT AROUND 0x08A332D5 (first boolean) ===")
for off in range(-16, 32):
    addr = 0x08A332D5 + off
    v1 = read_u8(data, psp_to_offset(addr))
    v2 = read_u8(data2, psp_to_offset(addr))
    marker = " ***" if v1 != v2 else ""
    print(f"  0x{addr:08X}: state1={v1:3d} state2={v2:3d}{marker}")

print("\nDone!")
