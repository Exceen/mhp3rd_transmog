#!/usr/bin/env python3
"""Final analysis: check which candidate is the item selector flag."""

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

def main():
    print("Loading states...")
    mem_c = load_state(STATE_CLOSED)
    mem_o = load_state(STATE_OPEN)

    # Let's understand the structure around 0x09BF5AF0 better.
    # The region 0x09BF5240-0x09BF5BC0 seems to be a render/texture manager.
    # 0x09BF524C = HUD object pointer
    # 0x09BF5260 = self-pointer (linked list?)
    # 0x09BF5270 = texture descriptor with ptrs
    # Then arrays of (ptr, ptr, count, 0) at 0x09BF5280...
    # 0x09BF5AF0 sits at the boundary between this array and render state data.

    # Let's check: does the structure at 0x09BF5240 have a recognizable size?
    # The HUD pointer at 0x09BF524C is 0x0C into the structure.
    # Let's compute: 0x09BF5AF0 - 0x09BF5240 = 0x8B0
    # That's quite far. It could be part of the same large structure or a different one.

    # Let's check what's at 0x09BF5AF0 relative to the texture array.
    # The texture entries start at 0x09BF5270 and are 16-byte entries:
    # (ptr1, ptr2, count, 0). Last non-zero entry at 0x09BF5AB0.
    # 0x09BF5AB0 = entry at index (0xAB0-0x270)/16 = 0x840/16 = 132.0 -- 0x84
    # Next entries from 0x09BF5AC0 are all zero in both states.
    # Then 0x09BF5AF0 has the flag.

    # So 0x09BF5AF0 is at offset 0x280 past the last texture entry.
    # It's likely a SEPARATE field in the parent structure.

    # Let's look at the full structure from 0x09BF5240 to find its vtable or type info
    print("=== Structure identification at 0x09BF5240 ===")
    for i in range(0, 0x30, 4):
        addr = 0x09BF5240 + i
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        marker = " ***" if vc != vo else ""
        if vc != 0 or vo != 0:
            is_ptr = 0x08000000 <= vc <= 0x09FFFFFF
            tag = " PTR" if is_ptr else ""
            print(f"  0x{addr:08X}: C=0x{vc:08X}{tag}  O=0x{vo:08X}{marker}")

    # Let's also look at what comes before 0x09BF5240
    print("\n=== What's before 0x09BF5240? ===")
    for i in range(0x40):
        addr = 0x09BF5200 + i*4
        vc = read_u32(mem_c, addr)
        if vc != 0:
            is_ptr = 0x08000000 <= vc <= 0x09FFFFFF
            tag = " PTR" if is_ptr else ""
            print(f"  0x{addr:08X}: 0x{vc:08X}{tag}")

    # CANDIDATE SUMMARY:
    print("\n" + "="*70)
    print("CANDIDATE SUMMARY")
    print("="*70)

    candidates = [
        ("0x09BF5AF0", 0x09BF5AF0, "Near HUD manager, in heap, 0->1"),
        ("0x09DA9754", 0x09DA9754, "In overlay data near UI addresses, 0->1"),
        ("0x09BADAA8", 0x09BADAA8, "In object list, 0->1, isolated"),
        ("0x09BEE698", 0x09BEE698, "Near linked list with ptr 0x0896B960, 1->0"),
        ("0x09BAA814", 0x09BAA814, "Similar structure to 0x09BEE698, 1->0"),
    ]

    for name, addr, desc in candidates:
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        print(f"\n  {name}: CLOSED={vc}, OPEN={vo}  ({desc})")
        # Show 16 bytes before and after for context
        for j in range(-4, 5):
            a = addr + j*4
            c = read_u32(mem_c, a)
            o = read_u32(mem_o, a)
            m = " ***" if c != o else ""
            arrow = " <-- THIS" if j == 0 else ""
            print(f"    {'+' if j>=0 else ''}{j*4:+3d} 0x{a:08X}: C=0x{c:08X}  O=0x{o:08X}{m}{arrow}")

    # Let's also see if 0x09BF5AF0 is referenced by any code.
    # Since it's at a fixed address in heap, game code likely reads it
    # via a base pointer + offset. The base would be 0x09BF5240 or nearby.
    # Offset from 0x09BF524C: 0x09BF5AF0 - 0x09BF524C = 0x8A4
    # Offset from 0x09BF5240: 0x09BF5AF0 - 0x09BF5240 = 0x8B0
    print(f"\n0x09BF5AF0 - 0x09BF524C = 0x{0x09BF5AF0-0x09BF524C:X}")
    print(f"0x09BF5AF0 - 0x09BF5240 = 0x{0x09BF5AF0-0x09BF5240:X}")

    # CWCheat addresses:
    print("\n=== CWCheat addresses ===")
    for name, addr in [("0x09BF5AF0", 0x09BF5AF0), ("0x09DA9754", 0x09DA9754)]:
        cw_off = addr - 0x08800000
        print(f"  {name}: CW offset = 0x{cw_off:07X}")
        print(f"    32-bit write 1: _L 0x2{cw_off:07X} 0x00000001")
        print(f"    32-bit write 0: _L 0x2{cw_off:07X} 0x00000000")
        print(f"     8-bit write 1: _L 0x0{cw_off:07X} 0x00000001")
        print(f"     8-bit write 0: _L 0x0{cw_off:07X} 0x00000000")

    # Let's also check if these addresses are in the game_task overlay
    # or in separately allocated memory
    overlay_base = 0x09C57C80
    for name, addr in [("0x09BF5AF0", 0x09BF5AF0), ("0x09DA9754", 0x09DA9754)]:
        if addr >= overlay_base:
            print(f"\n  {name} is in overlay (offset +0x{addr-overlay_base:X})")
        else:
            print(f"\n  {name} is BELOW overlay base (in heap/dynamic alloc)")

if __name__ == "__main__":
    main()
