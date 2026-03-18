#!/usr/bin/env python3
"""Deep dive on top candidates for item selector flag."""

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

def psp_to_off(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(mem, addr):
    return struct.unpack_from("<I", mem, psp_to_off(addr))[0]

def read_u8(mem, addr):
    return mem[psp_to_off(addr)]

def dump_region_full(label, mem_c, mem_o, start, count):
    print(f"\n{'='*70}")
    print(f"{label}")
    print(f"{'='*70}")
    for i in range(0, count, 4):
        addr = start + i
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        marker = " ***" if vc != vo else ""
        print(f"  0x{addr:08X} (+0x{i:03X}): C=0x{vc:08X}  O=0x{vo:08X}{marker}")

def main():
    print("Loading states...")
    mem_c = load_state(STATE_CLOSED)
    mem_o = load_state(STATE_OPEN)

    # CANDIDATE 1: 0x09DA9754 (0->1)
    # This is in the overlay data area, near 0x09DA93EC (map scale).
    # The surrounding data at 0x09DA9740 has floats (44480000 = 800.0, 40000000 = 2.0,
    # 44D2E000 = 1687.0) which could be UI widget positions.
    # 0x09DA9754 = 1, 0x09DA9758 = 0x32 (50 decimal) could be count/index.
    # This looks like a UI rendering structure, not a simple flag.

    # CANDIDATE 2: 0x09BF5AF0 (0->1)
    # Near 0x09BF524C (HUD object pointer). 0x09BF5AF4 also changes (0->0x00010001).
    # Surrounded by texture/buffer pointers. Could be a render manager flag.

    # CANDIDATE 3: 0x09BADAA8 (0->1)
    # Part of what looks like an object list (0x42=type, 0x101=flags, etc.)
    # Timer-like fields (0x4E18 = 20000). Could be quest/timer object.

    # Let me look at the broader structure around 0x09BF5AF0
    dump_region_full("0x09BF5A00-0x09BF5C00 (near HUD manager)", mem_c, mem_o, 0x09BF5A00, 0x200)

    # Let me also look at what's between the HUD pointer (0x09BF524C) and 0x09BF5AF0
    # There might be a UI state structure
    dump_region_full("0x09BF5240-0x09BF5300 (HUD ptr region)", mem_c, mem_o, 0x09BF5240, 0xC0)

    # Check 0x09DA9700 area more - is this a render list or UI state?
    # The overlay base is 0x09C57C80, so 0x09DA9700 - 0x09C57C80 = 0x151A80
    # This would be deep in the overlay data section
    print(f"\n0x09DA9754 offset from overlay base: 0x{0x09DA9754-0x09C57C80:X}")
    print(f"0x09BF5AF0 is BELOW overlay base (0x09C57C80), so it's in heap/dynamic memory")

    # Let's also check: what's the structure at 0x09BF5AC0?
    # It has 0xFF (alpha), pointers to 0x096EA060, 0x09F2A4A0... looks like a render context
    # 0x09BF5AF0 being 0->1 with 0x09BF5AF4 going 0->0x10001 is interesting

    # Let's look at what CHANGED in a broader sweep around 0x09BF5AF0
    # to understand the structure size
    print("\n=== Changes around 0x09BF5A80 - 0x09BF5B80 ===")
    for addr in range(0x09BF5A80, 0x09BF5B80, 4):
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        if vc != vo:
            print(f"  0x{addr:08X}: C=0x{vc:08X} O=0x{vo:08X}")

    # What about byte-level inspection of 0x09BF5AF0?
    print("\n=== Byte-level around 0x09BF5AF0 ===")
    for addr in range(0x09BF5AE0, 0x09BF5B00):
        bc = read_u8(mem_c, addr)
        bo = read_u8(mem_o, addr)
        marker = " ***" if bc != bo else ""
        print(f"  0x{addr:08X}: C=0x{bc:02X}  O=0x{bo:02X}{marker}")

    # KEY INSIGHT: The HUD object at 0x09DD0CF0 in CLOSED state is almost entirely zeros
    # (only the vtable pointer is set). This means it's a minimal/inactive object.
    # When the item selector OPENS, the object memory gets OVERWRITTEN with widget data.
    # The vtable 0x09DCAE60 being absent in OPEN means a DIFFERENT object type was allocated there.

    # So the approach should be:
    # 1. The HUD object vtable presence IS the flag (vtable=0x09DCAE60 means closed)
    # 2. Or there's a separate boolean somewhere

    # Let's check: is the data at 0x09DD0CF0 in OPEN state an item selector object?
    # What vtable does it have? 0x00000008 - not a valid pointer, it's part of the data.
    # So the object was likely freed and the memory reused.

    # Alternative: the item selector might be managed by a PARENT task
    # Let's check the game_task overlay code area for cross-references

    # Actually, let me check a very specific thing: the object at 0x09DD0CF0 in CLOSED
    # is nearly empty. But in OPEN, it has sprite data. What if the HUD allocates
    # sprite data AT its own address when the item selector opens?
    # i.e., the vtable gets overwritten by the first sprite entry.

    # Let's look at what object sits BEFORE 0x09DD0CF0 in both states
    dump_region_full("Before HUD object (0x09DD0C00)", mem_c, mem_o, 0x09DD0C00, 0x100)

    # Let's check 0x09DD0A3C which went 1->0 (interesting!)
    dump_region_full("Around 0x09DD0A3C (1->0)", mem_c, mem_o, 0x09DD0A00, 0x80)

if __name__ == "__main__":
    main()
