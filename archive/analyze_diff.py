#!/usr/bin/env python3
"""Analyze the diff candidates to find the actual selector flag."""

import struct
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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_1.ppst")
opened = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst")

# 1. Check pointer chain in both states
print("=== POINTER CHAIN ===")
for name, data in [("closed", closed), ("open", opened)]:
    p1 = read_u32(data, psp_to_offset(0x09BB7A80))
    p2 = read_u32(data, psp_to_offset(p1 + 8)) if 0x08000000 <= p1 <= 0x0A000000 else 0
    state = read_u8(data, psp_to_offset(p2 + 98)) if 0x08000000 <= p2 <= 0x0A000000 else -1
    print(f"  {name}: ptr1=0x{p1:08X}, ptr2=0x{p2:08X}, state_byte@+98={state}")
    # Also check the flag at various offsets from ptr2
    if 0x08000000 <= p2 <= 0x0A000000:
        for off in [96, 97, 98, 99, 100]:
            val = read_u8(data, psp_to_offset(p2 + off))
            print(f"    ptr2+{off} = {val}")

# 2. Check overlay BSS candidates more closely
print("\n=== OVERLAY BSS CANDIDATES ===")
candidates = [0x09BB5CA7, 0x09BB5DA7, 0x09BB7285, 0x09BB74E1, 0x09BB74E3, 0x09BB74E5, 0x09BB75C9, 0x09BB7791]
for addr in candidates:
    c = read_u8(closed, psp_to_offset(addr))
    o = read_u8(opened, psp_to_offset(addr))
    cw = addr - 0x08800000
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): closed={c} open={o}")
    # Check surrounding bytes
    for delta in [-2, -1, 0, 1, 2]:
        vc = read_u8(closed, psp_to_offset(addr + delta))
        vo = read_u8(opened, psp_to_offset(addr + delta))
        if vc != vo:
            print(f"    +{delta}: {vc}->{vo}")

# 3. Check the UI context pointer and +1814 flag
print("\n=== UI CONTEXT + 1814 CHECK ===")
# The call at 0x09D6C988 passes $s2 as $a0 to 0x09D60D88
# $s2 = $a0 of function 0x09D6C498
# The function is called from the main render loop with the UI context as $a0
# Let's find the UI context by searching for pointers where +1814 changes 0->1
print("Searching for UI context where byte at +1814 changes 0->1:")
for scan_addr in range(0x09BB0000, 0x09BC0000, 4):
    off = psp_to_offset(scan_addr)
    val_c = read_u32(closed, off)
    val_o = read_u32(opened, off)
    if val_c == val_o and val_c != 0 and 0x08000000 <= val_c <= 0x0A000000:
        try:
            flag_c = read_u8(closed, psp_to_offset(val_c + 1814))
            flag_o = read_u8(opened, psp_to_offset(val_c + 1814))
            if flag_c == 0 and flag_o == 1:
                flag_addr = val_c + 1814
                cw = flag_addr - 0x08800000
                print(f"  0x{scan_addr:08X} -> 0x{val_c:08X}, flag@+1814 = 0x{flag_addr:08X} (CW 0x{cw:07X}): {flag_c}->{flag_o} ***")
        except:
            pass

# Also scan eboot BSS
print("Searching eboot BSS 0x08A00000-0x08C00000:")
for scan_addr in range(0x08A00000, 0x08C00000, 4):
    off = psp_to_offset(scan_addr)
    val_c = read_u32(closed, off)
    val_o = read_u32(opened, off)
    if val_c == val_o and val_c != 0 and 0x09000000 <= val_c <= 0x0A000000:
        try:
            flag_c = read_u8(closed, psp_to_offset(val_c + 1814))
            flag_o = read_u8(opened, psp_to_offset(val_c + 1814))
            if flag_c == 0 and flag_o == 1:
                flag_addr = val_c + 1814
                cw = flag_addr - 0x08800000
                print(f"  0x{scan_addr:08X} -> 0x{val_c:08X}, flag@+1814 = 0x{flag_addr:08X} (CW 0x{cw:07X}): {flag_c}->{flag_o} ***")
        except:
            pass

# 4. Check the specific 3->4 candidates at 0x08B68Axx
print("\n=== EBOOT 0x08B68A70-0x08B68AB0 PATTERN ===")
for addr in range(0x08B68A70, 0x08B68AB0):
    c = read_u8(closed, psp_to_offset(addr))
    o = read_u8(opened, psp_to_offset(addr))
    if c != o:
        print(f"  0x{addr:08X}: {c}->{o}")

# 5. Check the 0x09BB5CA7 candidate more carefully
# 0x09BB5CA7 - 98 = 0x09BB5C45
print("\n=== CONTEXT AROUND 0x09BB5CA7 ===")
base = 0x09BB5CA7 - 98  # possible object base
print(f"Possible object at 0x{base:08X}:")
for off in [0, 4, 8, 96, 97, 98, 99, 100]:
    vc = read_u8(closed, psp_to_offset(base + off))
    vo = read_u8(opened, psp_to_offset(base + off))
    print(f"  +{off}: closed={vc} open={vo}")

# Check if 0x09BB5C45 is pointed to by anything
for scan_addr in range(0x09BB0000, 0x09BC0000, 4):
    off = psp_to_offset(scan_addr)
    val = read_u32(closed, off)
    if val == base:
        print(f"  Pointed to by 0x{scan_addr:08X}")

print("\nDone!")
