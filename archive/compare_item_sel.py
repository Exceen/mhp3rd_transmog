#!/usr/bin/env python3
"""Compare two MHP3rd save states to find the item selector active flag on the HUD object."""

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

def read_u16(mem, psp_addr):
    off = psp_addr - PSP_BASE + MEM_OFFSET
    return struct.unpack_from("<H", mem, off)[0]

def read_u8(mem, psp_addr):
    off = psp_addr - PSP_BASE + MEM_OFFSET
    return mem[off]

def get_bytes(mem, psp_addr, length):
    off = psp_addr - PSP_BASE + MEM_OFFSET
    return mem[off:off+length]

def main():
    print("Loading CLOSED state...")
    mem_closed = load_state(STATE_CLOSED)
    print(f"  Decompressed size: {len(mem_closed)} bytes")

    print("Loading OPEN state...")
    mem_open = load_state(STATE_OPEN)
    print(f"  Decompressed size: {len(mem_open)} bytes")

    ptr_addr = 0x09BF524C
    ptr_closed = read_u32(mem_closed, ptr_addr)
    ptr_open = read_u32(mem_open, ptr_addr)

    print(f"\nPointer at 0x{ptr_addr:08X}:")
    print(f"  CLOSED: 0x{ptr_closed:08X}")
    print(f"  OPEN:   0x{ptr_open:08X}")
    if ptr_closed != ptr_open:
        print("  ** POINTERS DIFFER! **")
    else:
        print("  (same)")

    # Use the pointer from each state
    hud_closed = ptr_closed
    hud_open = ptr_open

    # Check vtable
    vt_closed = read_u32(mem_closed, hud_closed)
    vt_open = read_u32(mem_open, hud_open)
    print(f"\nVtable pointer (+0x00):")
    print(f"  CLOSED: 0x{vt_closed:08X}")
    print(f"  OPEN:   0x{vt_open:08X}")
    expected_vt = 0x09DCAE60
    if vt_closed == expected_vt:
        print(f"  CLOSED matches expected 0x{expected_vt:08X}")
    else:
        print(f"  CLOSED does NOT match expected 0x{expected_vt:08X}")
    if vt_open == expected_vt:
        print(f"  OPEN matches expected 0x{expected_vt:08X}")
    else:
        print(f"  OPEN does NOT match expected 0x{expected_vt:08X}")

    # Check specific offsets
    for label, off in [("+0x34 (state machine)", 0x34), ("+0x54 (suspected flag)", 0x54)]:
        v_c = read_u32(mem_closed, hud_closed + off)
        v_o = read_u32(mem_open, hud_open + off)
        print(f"\n{label}:")
        print(f"  CLOSED: 0x{v_c:08X} ({v_c})")
        print(f"  OPEN:   0x{v_o:08X} ({v_o})")
        if v_c != v_o:
            print(f"  ** DIFFERS **")

    # Full comparison +0x00 to +0x200
    dump_size = 0x200
    data_closed = get_bytes(mem_closed, hud_closed, dump_size)
    data_open = get_bytes(mem_open, hud_open, dump_size)

    print(f"\n{'='*70}")
    print(f"Byte-by-byte comparison of HUD object (+0x00 to +0x{dump_size:03X}):")
    print(f"  CLOSED base: 0x{hud_closed:08X}")
    print(f"  OPEN base:   0x{hud_open:08X}")
    print(f"{'='*70}")

    diffs = []
    for i in range(dump_size):
        bc = data_closed[i]
        bo = data_open[i]
        if bc != bo:
            diffs.append((i, bc, bo))

    if not diffs:
        print("  No differences found!")
    else:
        print(f"  Found {len(diffs)} differing bytes:\n")
        print(f"  {'Offset':>8s}  {'PSP Addr (C)':>14s}  {'PSP Addr (O)':>14s}  {'Closed':>8s}  {'Open':>8s}")
        print(f"  {'-'*8}  {'-'*14}  {'-'*14}  {'-'*8}  {'-'*8}")
        for off, vc, vo in diffs:
            addr_c = hud_closed + off
            addr_o = hud_open + off
            print(f"  +0x{off:04X}    0x{addr_c:08X}      0x{addr_o:08X}      0x{vc:02X}      0x{vo:02X}")

    # Also show 32-bit aligned view of diffs
    print(f"\n{'='*70}")
    print("32-bit aligned diff view:")
    print(f"{'='*70}")
    diff_words = set()
    for off, _, _ in diffs:
        diff_words.add(off & ~3)
    for word_off in sorted(diff_words):
        vc = struct.unpack_from("<I", data_closed, word_off)[0]
        vo = struct.unpack_from("<I", data_open, word_off)[0]
        print(f"  +0x{word_off:04X}  CLOSED=0x{vc:08X}  OPEN=0x{vo:08X}")

if __name__ == "__main__":
    main()
