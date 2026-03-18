#!/usr/bin/env python3
"""Compare two MHP3rd save states - investigate memory layout differences."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE_CLOSED = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"
STATE_OPEN   = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    compressed = data[0xB0:]
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)

def read_u32(mem, psp_addr):
    off = psp_addr - PSP_BASE + MEM_OFFSET
    return struct.unpack_from("<I", mem, off)[0]

def get_bytes(mem, psp_addr, length):
    off = psp_addr - PSP_BASE + MEM_OFFSET
    return mem[off:off+length]

def main():
    print("Loading states...")
    mem_closed = load_state(STATE_CLOSED)
    mem_open = load_state(STATE_OPEN)
    print(f"  CLOSED size: {len(mem_closed)}")
    print(f"  OPEN size:   {len(mem_open)}")
    print(f"  Difference:  {len(mem_open) - len(mem_closed)} bytes")

    # The decompressed sizes differ. Let's check if the save state format
    # has multiple sections. Let's look at what's around offset 0x48 area.

    # First, let's check if the PSP memory region is at a fixed offset
    # or if there's a section header we need to parse.

    # Check the header area
    print("\n--- Header bytes (first 0x100) ---")
    print("CLOSED:")
    for i in range(0, 0x100, 16):
        hexdump = " ".join(f"{mem_closed[i+j]:02X}" for j in range(min(16, len(mem_closed)-i)))
        print(f"  {i:04X}: {hexdump}")
    print("OPEN:")
    for i in range(0, 0x100, 16):
        hexdump = " ".join(f"{mem_open[i+j]:02X}" for j in range(min(16, len(mem_open)-i)))
        print(f"  {i:04X}: {hexdump}")

    # Look for the vtable value 0x09DCAE60 in both states to find the real offset
    vtable_bytes = struct.pack("<I", 0x09DCAE60)

    # Search in CLOSED state around expected area
    ptr_addr = 0x09BF524C
    expected_obj = 0x09DD0CF0
    expected_file_off = expected_obj - PSP_BASE + MEM_OFFSET

    print(f"\n--- Searching for vtable 0x09DCAE60 ---")
    print(f"Expected file offset: 0x{expected_file_off:X}")

    # Search in a range around expected offset in CLOSED
    search_start = max(0, expected_file_off - 0x100000)
    search_end = min(len(mem_closed), expected_file_off + 0x100000)

    pos = search_start
    closed_hits = []
    while pos < search_end:
        idx = mem_closed.find(vtable_bytes, pos, search_end)
        if idx == -1:
            break
        closed_hits.append(idx)
        pos = idx + 1

    print(f"CLOSED: found vtable at file offsets: {['0x%X' % h for h in closed_hits[:20]]}")

    pos = search_start
    search_end_o = min(len(mem_open), expected_file_off + 0x100000)
    open_hits = []
    while pos < search_end_o:
        idx = mem_open.find(vtable_bytes, pos, search_end_o)
        if idx == -1:
            break
        open_hits.append(idx)
        pos = idx + 1

    print(f"OPEN:   found vtable at file offsets: {['0x%X' % h for h in open_hits[:20]]}")

    # The CLOSED state had the vtable at the expected location. Let's verify.
    print(f"\nAt expected offset 0x{expected_file_off:X}:")
    print(f"  CLOSED: 0x{struct.unpack_from('<I', mem_closed, expected_file_off)[0]:08X}")
    if expected_file_off < len(mem_open):
        print(f"  OPEN:   0x{struct.unpack_from('<I', mem_open, expected_file_off)[0]:08X}")

    # Check: maybe PPSSPP state format has variable-length sections before the PSP RAM
    # Let's look for a known PSP memory signature. The game code at 0x08804000 should be stable.
    # Let's check a known static value.

    # Check the pointer itself
    print(f"\n--- Pointer at 0x09BF524C ---")
    ptr_c = read_u32(mem_closed, 0x09BF524C)
    ptr_o = read_u32(mem_open, 0x09BF524C)
    print(f"  CLOSED: 0x{ptr_c:08X}")
    print(f"  OPEN:   0x{ptr_o:08X}")

    # Let's check if the CLOSED state's object actually has the vtable
    if ptr_c != 0:
        vt_c = read_u32(mem_closed, ptr_c)
        print(f"  CLOSED obj vtable: 0x{vt_c:08X}")

    if ptr_o != 0:
        vt_o = read_u32(mem_open, ptr_o)
        print(f"  OPEN obj vtable: 0x{vt_o:08X}")

    # Since CLOSED state had all zeros at the object, maybe the pointer was null
    # or the object wasn't allocated yet. Let's check a wider area.

    # Let's try a different approach: search for the pointer value itself
    ptr_val_bytes = struct.pack("<I", 0x09DD0CF0)

    # Also let's check if there's a state_offset in the ppst format header
    # The .ppst format: 0xB0 header is in the raw file, then zstd compressed data
    # After decompression, offset 0x48 = PSP memory base
    # But wait - maybe not. Let's check what's at offset 0 of decompressed data

    print(f"\n--- Decompressed data structure ---")
    # Check first few u32s
    for i in range(0, 0x60, 4):
        vc = struct.unpack_from("<I", mem_closed, i)[0]
        vo = struct.unpack_from("<I", mem_open, i)[0]
        marker = " *" if vc != vo else ""
        print(f"  +0x{i:02X}: CLOSED=0x{vc:08X}  OPEN=0x{vo:08X}{marker}")

    # Let's verify our offset by checking a known static address
    # The equipment jump table at 0x08966184 should be consistent
    test_addr = 0x08966184
    test_off = test_addr - PSP_BASE + MEM_OFFSET
    vc = struct.unpack_from("<I", mem_closed, test_off)[0]
    vo = struct.unpack_from("<I", mem_open, test_off)[0]
    print(f"\nKnown static at 0x{test_addr:08X}:")
    print(f"  CLOSED: 0x{vc:08X}")
    print(f"  OPEN:   0x{vo:08X}")

    # Check the armor table HEAD=0x089825AC
    test_addr2 = 0x089825AC
    test_off2 = test_addr2 - PSP_BASE + MEM_OFFSET
    vc2 = struct.unpack_from("<I", mem_closed, test_off2)[0]
    vo2 = struct.unpack_from("<I", mem_open, test_off2)[0]
    print(f"\nArmor HEAD table at 0x{test_addr2:08X}:")
    print(f"  CLOSED: 0x{vc2:08X}")
    print(f"  OPEN:   0x{vo2:08X}")

if __name__ == "__main__":
    main()
