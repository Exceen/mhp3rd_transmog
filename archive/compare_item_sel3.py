#!/usr/bin/env python3
"""Compare MHP3rd save states - find item selector flag by searching broader memory."""

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

def psp_to_off(addr):
    return addr - PSP_BASE + MEM_OFFSET

def main():
    print("Loading states...")
    mem_c = load_state(STATE_CLOSED)
    mem_o = load_state(STATE_OPEN)

    # Search for vtable 0x09DCAE60 in OPEN state across ALL memory
    vtable_bytes = struct.pack("<I", 0x09DCAE60)
    print("\nSearching for vtable 0x09DCAE60 in OPEN state (full memory)...")
    pos = 0
    hits = []
    while pos < len(mem_o):
        idx = mem_o.find(vtable_bytes, pos)
        if idx == -1:
            break
        psp = idx - MEM_OFFSET + PSP_BASE
        hits.append((idx, psp))
        pos = idx + 1
    print(f"  Found {len(hits)} occurrences:")
    for foff, psp in hits[:30]:
        print(f"    file=0x{foff:X}  PSP=0x{psp:08X}")

    print("\nSearching for vtable 0x09DCAE60 in CLOSED state (full memory)...")
    pos = 0
    hits_c = []
    while pos < len(mem_c):
        idx = mem_c.find(vtable_bytes, pos)
        if idx == -1:
            break
        psp = idx - MEM_OFFSET + PSP_BASE
        hits_c.append((idx, psp))
        pos = idx + 1
    print(f"  Found {len(hits_c)} occurrences:")
    for foff, psp in hits_c[:30]:
        print(f"    file=0x{foff:X}  PSP=0x{psp:08X}")

    # The decompressed sizes differ. PPSSPP state might have variable sections.
    # Let's check if after the PSP RAM (32MB = 0x02000000), there are additional sections
    # that shifted between saves.
    # PSP RAM: 0x08000000 - 0x09FFFFFF (32MB), file offset 0x48 to 0x02000048
    psp_ram_end = 0x02000048

    print(f"\n--- Checking around PSP RAM boundary ---")
    print(f"PSP RAM in file: 0x48 to 0x{psp_ram_end:X}")

    # Check what's after PSP RAM in both states
    for label, mem in [("CLOSED", mem_c), ("OPEN", mem_o)]:
        print(f"\n{label} after PSP RAM (file offset 0x{psp_ram_end:X}):")
        for i in range(0, 0x40, 4):
            off = psp_ram_end + i
            if off + 4 <= len(mem):
                v = struct.unpack_from("<I", mem, off)[0]
                print(f"  +0x{i:02X}: 0x{v:08X}")

    # Now the key question: is 0x09DD0CF0 within PSP RAM range?
    # 0x09DD0CF0 - 0x08000000 = 0x01DD0CF0, which is within 32MB (0x02000000)
    # So it IS in PSP RAM. The object should be at file offset 0x01DD0CF0 + 0x48 = 0x01DD0D38
    # And we confirmed CLOSED has the vtable there but OPEN doesn't.

    # Theory: the object was destroyed/reallocated in OPEN state.
    # Let's check if the pointer at 0x09BF524C still makes sense for OPEN state.
    # Maybe a different pointer holds the active HUD object.

    # Let's look at a wider region around the pointer
    ptr_region = 0x09BF5200
    print(f"\n--- Memory around pointer region 0x{ptr_region:08X} ---")
    for i in range(0, 0x100, 4):
        addr = ptr_region + i
        vc = read_u32(mem_c, addr)
        vo = read_u32(mem_o, addr)
        marker = " ***" if vc != vo else ""
        if vc != 0 or vo != 0:
            print(f"  0x{addr:08X}: C=0x{vc:08X}  O=0x{vo:08X}{marker}")

    # Let's also look at the HUD object region in OPEN state more carefully
    # Maybe it was replaced by a different object type (item selector object)
    obj_addr = 0x09DD0CF0
    print(f"\n--- Object at 0x{obj_addr:08X} in OPEN state ---")
    # Show first 0x40 bytes as u32
    for i in range(0, 0x80, 4):
        addr = obj_addr + i
        vo = read_u32(mem_o, addr)
        # Interpret floats too
        fo = struct.unpack_from("<f", mem_o, psp_to_off(addr))[0]
        print(f"  +0x{i:02X} (0x{addr:08X}): 0x{vo:08X}  float={fo:.4f}")

    # Let's also check if there's a different HUD-like pointer
    # Search in dynamic region for pointers that point to objects with vtable 0x09DCAE60
    # in OPEN state
    if hits:  # vtable found in OPEN
        print(f"\n--- Checking objects with vtable 0x09DCAE60 in OPEN state ---")
        for foff, psp in hits[:10]:
            print(f"\n  Object at PSP 0x{psp:08X}:")
            for i in range(0, 0x60, 4):
                v = read_u32(mem_o, psp + i)
                print(f"    +0x{i:02X}: 0x{v:08X}")

    # Let's try yet another approach: the OPEN state may have the HUD object at a
    # DIFFERENT address. Let's look for what changed in the 0x09BF region.
    # Maybe there's a separate "item selector active" flag somewhere simple.

    # Search for simple flag patterns: a byte/word that's 0 in CLOSED and 1 in OPEN
    # in the game's static data region (0x089xxxxx)
    print(f"\n--- Scanning for 0->1 byte changes in 0x0895xxxx-0x099xxxxx (32-bit aligned) ---")
    scan_start = 0x0897_0000
    scan_end = 0x09C0_0000
    candidates = []
    min_len = min(len(mem_c), len(mem_o))

    for psp_addr in range(scan_start, scan_end, 4):
        off = psp_to_off(psp_addr)
        if off + 4 > min_len:
            break
        vc = struct.unpack_from("<I", mem_c, off)[0]
        vo = struct.unpack_from("<I", mem_o, off)[0]
        # Look for 0->1 or 0->2 or 0->small number changes
        if vc == 0 and 1 <= vo <= 10:
            candidates.append((psp_addr, vc, vo))
        elif 1 <= vc <= 10 and vo == 0:
            candidates.append((psp_addr, vc, vo))

    print(f"  Found {len(candidates)} candidates")
    if len(candidates) <= 200:
        for addr, vc, vo in candidates:
            print(f"    0x{addr:08X}: {vc} -> {vo}")
    else:
        print("  (too many, showing first 100)")
        for addr, vc, vo in candidates[:100]:
            print(f"    0x{addr:08X}: {vc} -> {vo}")

if __name__ == "__main__":
    main()
