#!/usr/bin/env python3
"""Read the vtable at 0x09DCAE60 and find the function at offset 0xD8."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

vtable_addr = 0x09DCAE60
print(f"=== Vtable at 0x{vtable_addr:08X} ===")
off = psp_to_offset(vtable_addr)
for i in range(0, 0x200, 4):
    if off + i + 4 > len(data): break
    val = read_u32(data, off + i)
    loc = ""
    if 0x08800000 <= val < 0x08A00000:
        loc = "EBOOT"
    elif 0x09C00000 <= val < 0x09E00000:
        loc = "OVERLAY"
    elif val == 0:
        loc = "NULL"
    else:
        loc = f"DATA?"
    marker = ""
    if i == 0xD8: marker = " <<<< RENDER METHOD"
    if i == 0xDC: marker = " <<<< +0xDC"
    if i == 0x44: marker = " <<<< +0x44"
    if i == 0xAC: marker = " <<<< +0xAC"
    if i == 0xE0: marker = " <<<< +0xE0"
    if i == 0xE4: marker = " <<<< +0xE4"
    if i == 0xFC: marker = " <<<< +0xFC"
    if i == 0x15C: marker = " <<<< +0x15C"
    if i == 0x1D4: marker = " <<<< +0x1D4"
    if i == 0x1D8: marker = " <<<< +0x1D8"
    print(f"  [0x{i:03X}] 0x{val:08X} ({loc}){marker}")
    # Stop if we hit a large gap of non-pointer values
    if i > 0x20 and val == 0 and read_u32(data, off + i - 4) == 0:
        # Check next few
        all_zero = all(read_u32(data, off + i + j*4) == 0 for j in range(4))
        if all_zero:
            print(f"  ... (zeros, stopping)")
            break

# Also find the object that uses this vtable
print(f"\n=== Objects using vtable 0x{vtable_addr:08X} ===")
# The code at 0x09D5D8F0 does: sw $s0, 21068($v1) where $v1 = 0x09BF0000
# So 0x09BF0000 + 21068 = 0x09BF524C stores the object pointer
obj_ptr_addr = 0x09BF524C
obj_ptr_off = psp_to_offset(obj_ptr_addr)
if obj_ptr_off + 4 <= len(data):
    obj_addr = read_u32(data, obj_ptr_off)
    print(f"  *(0x{obj_ptr_addr:08X}) = 0x{obj_addr:08X}")
    if obj_addr != 0:
        obj_off = psp_to_offset(obj_addr)
        vtable_ptr = read_u32(data, obj_off)
        print(f"  Object at 0x{obj_addr:08X}, vtable ptr = 0x{vtable_ptr:08X}")
        if vtable_ptr == vtable_addr:
            print(f"  CONFIRMED: this object uses our vtable!")
        # Dump object data
        print(f"  Object data:")
        for i in range(0, 0x100, 4):
            if obj_off + i + 4 > len(data): break
            val = read_u32(data, obj_off + i)
            print(f"    +0x{i:03X}: 0x{val:08X}")

print("\nDone!")
