#!/usr/bin/env python3
"""Compare HUD object fields between open/closed item selector states.
The HUD object pointer may be at 0x09BF524C (from memory notes)."""

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

data_closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")
data_open = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Check the pointer at 0x09BF524C
ptr_c = read_u32(data_closed, psp_to_offset(0x09BF524C))
ptr_o = read_u32(data_open, psp_to_offset(0x09BF524C))
print(f"*(0x09BF524C): closed=0x{ptr_c:08X} open=0x{ptr_o:08X}")

# Also check *(0x09DB17E8) — loaded in caller
ptr2_c = read_u32(data_closed, psp_to_offset(0x09DB17E8))
ptr2_o = read_u32(data_open, psp_to_offset(0x09DB17E8))
print(f"*(0x09DB17E8): closed=0x{ptr2_c:08X} open=0x{ptr2_o:08X}")

# The caller does: $s5 = $a0, then $a0 = $s5 + 0xC0 for the HUD function.
# So HUD_obj = caller_arg + 0xC0
# If the caller's $a0 is from another function, we need to trace further.
# But let's try the pointer at 0x09BF524C first.

hud_ptr = ptr_o  # Use the open state pointer
if hud_ptr == ptr_c:
    print(f"HUD pointer is stable: 0x{hud_ptr:08X}")
else:
    print(f"WARNING: HUD pointer differs between states!")

# The HUD object might be at hud_ptr or at some offset
# Let's check known fields:
# $s2 + 0x3DA0: should be 1 (HUD active flag)
# $s2 + 0x0180: should be 1
# $s2 + 0x347C: animation flag (checked in update function)
# $s2 + 0x0008: number of items

# Try hud_ptr as $s2 directly
for base_name, base_addr in [("hud_ptr", hud_ptr),
                               ("hud_ptr+0xC0", hud_ptr + 0xC0),
                               ("hud_ptr-0xC0", hud_ptr - 0xC0)]:
    off_c = psp_to_offset(base_addr)
    off_o = psp_to_offset(base_addr)
    if off_c + 0x4000 > len(data_closed) or off_o + 0x4000 > len(data_open):
        print(f"\n{base_name} (0x{base_addr:08X}): out of range")
        continue

    print(f"\n=== Checking {base_name} (0x{base_addr:08X}) ===")
    # Check known offsets
    for off_name, off_val, size in [
        ("+0x08 (num_items)", 0x08, 4),
        ("+0x0180 (active?)", 0x180, 1),
        ("+0x347C (anim_flag)", 0x347C, 1),
        ("+0x347D (cleared)", 0x347D, 1),
        ("+0x3474 (pos_sh)", 0x3474, 2),
        ("+0x3476 (pos_sh)", 0x3476, 2),
        ("+0x3488", 0x3488, 2),
        ("+0x348A", 0x348A, 2),
        ("+0x348C", 0x348C, 2),
        ("+0x348E", 0x348E, 2),
        ("+0x34A0", 0x34A0, 2),
        ("+0x34A2", 0x34A2, 2),
        ("+0x3DA0 (hud_active)", 0x3DA0, 1),
        ("+0x0716 (render_check)", 0x716, 1),
    ]:
        addr = base_addr + off_val
        a_off = psp_to_offset(addr)
        if a_off + 4 > len(data_closed): continue
        if size == 1:
            vc = read_u8(data_closed, a_off)
            vo = read_u8(data_open, a_off)
        elif size == 2:
            vc = read_u16(data_closed, a_off)
            vo = read_u16(data_open, a_off)
        else:
            vc = read_u32(data_closed, a_off)
            vo = read_u32(data_open, a_off)
        diff = " ***" if vc != vo else ""
        print(f"  {off_name}: closed={vc:#x} open={vo:#x}{diff}")

# Scan the HUD object for ALL differences between open/closed states
# Use hud_ptr as the base for a broad scan
print(f"\n=== ALL diffs in HUD object area ({hud_ptr:#x} to {hud_ptr+0x4000:#x}) ===")
count = 0
for off_val in range(0, 0x4000, 4):
    addr = hud_ptr + off_val
    a_off = psp_to_offset(addr)
    if a_off + 4 > len(data_closed) or a_off + 4 > len(data_open): break
    vc = read_u32(data_closed, a_off)
    vo = read_u32(data_open, a_off)
    if vc != vo:
        count += 1
        if count <= 60:
            # Show as byte, halfword, word
            vc_b = read_u8(data_closed, a_off)
            vo_b = read_u8(data_open, a_off)
            print(f"  +0x{off_val:04X} (0x{addr:08X}): closed=0x{vc:08X} open=0x{vo:08X} (byte: {vc_b:#x}→{vo_b:#x})")
if count > 60:
    print(f"  ... {count} total diffs")
elif count == 0:
    print("  No differences found!")

# Also scan hud_ptr + 0xC0 area
base2 = hud_ptr + 0xC0
print(f"\n=== ALL diffs in HUD+0xC0 area ({base2:#x} to {base2+0x4000:#x}) ===")
count = 0
for off_val in range(0, 0x4000, 4):
    addr = base2 + off_val
    a_off = psp_to_offset(addr)
    if a_off + 4 > len(data_closed) or a_off + 4 > len(data_open): break
    vc = read_u32(data_closed, a_off)
    vo = read_u32(data_open, a_off)
    if vc != vo:
        count += 1
        if count <= 60:
            vc_b = read_u8(data_closed, a_off)
            vo_b = read_u8(data_open, a_off)
            print(f"  +0x{off_val:04X} (0x{addr:08X}): closed=0x{vc:08X} open=0x{vo:08X} (byte: {vc_b:#x}→{vo_b:#x})")
if count > 60:
    print(f"  ... {count} total diffs")
elif count == 0:
    print("  No differences found!")

print("\nDone!")
