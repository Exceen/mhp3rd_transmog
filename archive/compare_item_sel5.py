#!/usr/bin/env python3
"""Focused investigation of item selector flag candidates."""

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

def dump_region(label, mem_c, mem_o, start, count=0x80):
    print(f"\n=== {label} (0x{start:08X}) ===")
    for i in range(0, count, 4):
        addr = start + i
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        marker = " ***" if vc != vo else ""
        if vc != 0 or vo != 0 or marker:
            fc = struct.unpack_from("<f", mem_c, psp_to_off(addr))[0]
            fo = struct.unpack_from("<f", mem_o, psp_to_off(addr))[0]
            print(f"  +0x{i:03X} 0x{addr:08X}: C=0x{vc:08X} O=0x{vo:08X}{marker}")

def main():
    print("Loading states...")
    mem_c = load_state(STATE_CLOSED)
    mem_o = load_state(STATE_OPEN)

    # Top candidates to investigate:

    # 1. 0x09DA9754 - in the overlay data area near known UI addresses
    #    (0x09DA93EC = map scale, 0x09DA93A0 = HP bar scale)
    dump_region("Near UI data (0x09DA9740)", mem_c, mem_o, 0x09DA9740, 0x40)

    # 2. 0x09AAB9CC - isolated 0->1
    dump_region("0x09AAB9C0 region", mem_c, mem_o, 0x09AAB9A0, 0x80)

    # 3. 0x09BA1D08 - isolated 0->1
    dump_region("0x09BA1D00 region", mem_c, mem_o, 0x09BA1CE0, 0x60)

    # 4. 0x09BADAA8 - isolated 0->1
    dump_region("0x09BADAA0 region", mem_c, mem_o, 0x09BADA80, 0x60)

    # 5. 0x09BAE29C - isolated 0->1
    dump_region("0x09BAE280 region", mem_c, mem_o, 0x09BAE260, 0x60)

    # 6. 0x09BEE698 - isolated 1->0
    dump_region("0x09BEE680 region", mem_c, mem_o, 0x09BEE670, 0x60)

    # 7. 0x09BAA814 - isolated 1->0
    dump_region("0x09BAA800 region", mem_c, mem_o, 0x09BAA7F0, 0x60)

    # 8. 0x09BA20D4 - isolated 1->0
    dump_region("0x09BA20C0 region", mem_c, mem_o, 0x09BA20B0, 0x60)

    # Let's also check: the HUD object in CLOSED state had vtable 0x09DCAE60.
    # What's at that vtable? It should have function pointers.
    # When the item selector opens, maybe a sub-object or state field changes.
    # Let's look at the CLOSED HUD object more carefully.
    print("\n=== CLOSED HUD object at 0x09DD0CF0 (first 0x100 bytes) ===")
    for i in range(0, 0x100, 4):
        addr = 0x09DD0CF0 + i
        vc = read_u32(mem_c, addr)
        if vc != 0:
            print(f"  +0x{i:03X}: 0x{vc:08X}")

    # In OPEN state the HUD object memory was overwritten. Let's look for the HUD
    # object in OPEN state by finding what changed the vtable slot.
    # Maybe the HUD object was moved? Let's search for a ptr to vtable 0x09DCAE60
    # in CLOSED state, then check what those pointers point to in OPEN state.

    # The pointer at 0x09BF524C -> 0x09DD0CF0. In CLOSED, that has vtable.
    # In OPEN, it has garbage. But the pointer is the same. So the object was
    # overwritten, not moved.

    # Let's check: did a NEW object get placed at 0x09DD0CF0 in OPEN?
    # The data there in OPEN looks like sprite/animation data (small ints + floats).
    # This could be the item selector widget data itself!

    # Let's look more broadly at the HUD object in CLOSED - is there a child pointer
    # or linked list?
    print("\n=== CLOSED HUD object full dump (0x09DD0CF0, 0x300 bytes) ===")
    for i in range(0, 0x300, 4):
        addr = 0x09DD0CF0 + i
        off = psp_to_off(addr)
        if off + 4 > len(mem_c):
            break
        vc = read_u32(mem_c, addr)
        if vc != 0:
            # If it looks like a pointer, mark it
            is_ptr = 0x08000000 <= vc <= 0x09FFFFFF
            tag = " PTR" if is_ptr else ""
            print(f"  +0x{i:03X}: 0x{vc:08X}{tag}")

    # The real question: where is the "is item selector open" flag?
    # It could be:
    # - A field inside a persistent UI manager (not the HUD object that got overwritten)
    # - A global variable
    # - Part of the player input state

    # Let's check the input/controller state area
    # On PSP, controller data is often at 0x09xxxxxx
    # Let's check near the global_ptr 0x089C7508 area
    dump_region("Near global_ptr 0x089C7500", mem_c, mem_o, 0x089C74F0, 0x40)

    # Check near 0x09BF5AF0 (0->1, last one found)
    dump_region("0x09BF5AE0 region", mem_c, mem_o, 0x09BF5AC0, 0x80)

    # Let's also check 0x09DA97xx more carefully - this is very close to known UI addresses
    dump_region("UI area 0x09DA9700-0x09DA9800", mem_c, mem_o, 0x09DA9700, 0x100)

if __name__ == "__main__":
    main()
