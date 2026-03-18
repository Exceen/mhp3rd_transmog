#!/usr/bin/env python3
"""Compare HUD object fields using $s2/$s3 stored by code cave.
Slot 3 (index 2) = closed, Slot 4 (index 3) = open.
$s2 at 0x088000F0, $s3 at 0x088000F4."""

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

data_closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst")
data_open = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst")

# Read stored register values
s2_c = read_u32(data_closed, psp_to_offset(0x088000F0))
s3_c = read_u32(data_closed, psp_to_offset(0x088000F4))
v0_c = read_u32(data_closed, psp_to_offset(0x088000FC))
s2_o = read_u32(data_open, psp_to_offset(0x088000F0))
s3_o = read_u32(data_open, psp_to_offset(0x088000F4))
v0_o = read_u32(data_open, psp_to_offset(0x088000FC))

print(f"=== Stored registers ===")
print(f"$s2 (HUD obj): closed=0x{s2_c:08X} open=0x{s2_o:08X}")
print(f"$s3 (state):   closed=0x{s3_c:08X} open=0x{s3_o:08X}")
print(f"$v0 (vis chk): closed={v0_c} open={v0_o}")

if s2_c == 0 and s2_o == 0:
    print("\nWARNING: $s2 is 0 in both states — cave may not have executed!")
    print("Check if the cheat is enabled and overlay is loaded.")
    exit()

# Use the open state's $s2 as the HUD base
s2 = s2_o if s2_o else s2_c
s3 = s3_o if s3_o else s3_c
print(f"\nUsing $s2=0x{s2:08X}, $s3=0x{s3:08X}")

# Check $s3+0xBA0 flags
if s3:
    flags_c = read_u32(data_closed, psp_to_offset(s3 + 0xBA0))
    flags_o = read_u32(data_open, psp_to_offset(s3 + 0xBA0))
    print(f"\n$s3+0xBA0 flags: closed=0x{flags_c:08X} open=0x{flags_o:08X}")
    print(f"  bit0={flags_c&1}/{flags_o&1} bit1={(flags_c>>1)&1}/{(flags_o>>1)&1} bit9={(flags_c>>9)&1}/{(flags_o>>9)&1}")

# Scan the HUD object for ALL 4-byte-aligned diffs
print(f"\n=== ALL diffs in HUD object ($s2=0x{s2:08X}, scanning 0x4000 bytes) ===")
diffs = []
for off_val in range(0, 0x4000, 4):
    addr = s2 + off_val
    a_off = psp_to_offset(addr)
    if a_off + 4 > len(data_closed) or a_off + 4 > len(data_open): break
    vc = read_u32(data_closed, a_off)
    vo = read_u32(data_open, a_off)
    if vc != vo:
        diffs.append((off_val, addr, vc, vo))

print(f"Found {len(diffs)} diffs")
for off_val, addr, vc, vo in diffs[:80]:
    vc_b = read_u8(data_closed, psp_to_offset(addr))
    vo_b = read_u8(data_open, psp_to_offset(addr))
    # Classify the diff
    note = ""
    if vc == 0 and 1 <= vo <= 10: note = " *** STATE CANDIDATE (0→small)"
    elif vo == 0 and 1 <= vc <= 10: note = " *** STATE CANDIDATE (small→0)"
    elif 1 <= vc <= 20 and 1 <= vo <= 20 and vc != vo: note = " *** STATE CHANGE"
    cw_off = addr - 0x08800000
    print(f"  +0x{off_val:04X} (0x{addr:08X}, CW 0x{cw_off:07X}): "
          f"closed=0x{vc:08X} open=0x{vo:08X} (byte: {vc_b:#04x}→{vo_b:#04x}){note}")

if len(diffs) > 80:
    print(f"  ... showing first 80 of {len(diffs)}")

# Also scan $s3 object for diffs (smaller, 0x1000 bytes)
if s3:
    print(f"\n=== ALL diffs in $s3 object (0x{s3:08X}, scanning 0x1000 bytes) ===")
    s3_diffs = []
    for off_val in range(0, 0x1000, 4):
        addr = s3 + off_val
        a_off = psp_to_offset(addr)
        if a_off + 4 > len(data_closed) or a_off + 4 > len(data_open): break
        vc = read_u32(data_closed, a_off)
        vo = read_u32(data_open, a_off)
        if vc != vo:
            s3_diffs.append((off_val, addr, vc, vo))
    print(f"Found {len(s3_diffs)} diffs")
    for off_val, addr, vc, vo in s3_diffs[:40]:
        note = ""
        if vc == 0 and 1 <= vo <= 10: note = " *** STATE CANDIDATE"
        elif vo == 0 and 1 <= vc <= 10: note = " *** STATE CANDIDATE"
        cw_off = addr - 0x08800000
        print(f"  +0x{off_val:04X} (0x{addr:08X}, CW 0x{cw_off:07X}): "
              f"closed=0x{vc:08X} open=0x{vo:08X}{note}")

print("\nDone!")
