#!/usr/bin/env python3
"""Compare MHP3rd save states - focused search for item selector active flag."""

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

def read_u16(mem, addr):
    return struct.unpack_from("<H", mem, psp_to_off(addr))[0]

def read_u8(mem, addr):
    return mem[psp_to_off(addr)]

def main():
    print("Loading states...")
    mem_c = load_state(STATE_CLOSED)
    mem_o = load_state(STATE_OPEN)
    min_len = min(len(mem_c), len(mem_o))

    # The game_task overlay is at 0x09C57C80. The item selector is likely managed
    # by the HUD task. Let's look at the game_task overlay region for differences.

    # First, let's look at the region around 0x09BF524C (the HUD object pointer)
    # for nearby state flags
    print("\n=== Region around HUD pointer (0x09BF5200 - 0x09BF5400) ===")
    for addr in range(0x09BF5200, 0x09BF5400, 4):
        off = psp_to_off(addr)
        if off + 4 > min_len:
            break
        vc = struct.unpack_from("<I", mem_c, off)[0]
        vo = struct.unpack_from("<I", mem_o, off)[0]
        if vc != vo:
            print(f"  0x{addr:08X}: C=0x{vc:08X}  O=0x{vo:08X}")

    # Let's look at known game_task overlay data regions
    # The overlay base is 0x09C57C80
    # UI-related state often lives near the overlay data section

    # Let's scan the dynamic overlay region 0x09C57C80 - 0x09E00000 for simple flag changes
    print("\n=== Scanning overlay region 0x09C57C80 - 0x09E00000 for 0<->1 changes (byte level) ===")
    start = 0x09C57C80
    end = 0x09E00000
    byte_candidates = []

    for addr in range(start, end):
        off_c = psp_to_off(addr)
        off_o = psp_to_off(addr)
        if off_c >= min_len or off_o >= min_len:
            break
        bc = mem_c[off_c]
        bo = mem_o[off_o]
        if bc == 0 and bo == 1:
            byte_candidates.append((addr, 0, 1))
        elif bc == 1 and bo == 0:
            byte_candidates.append((addr, 1, 0))

    print(f"  Found {len(byte_candidates)} byte candidates (0<->1)")
    for addr, vc, vo in byte_candidates[:50]:
        # Show context: surrounding bytes in both states
        ctx_c = " ".join(f"{mem_c[psp_to_off(addr-2+i)]:02X}" for i in range(8))
        ctx_o = " ".join(f"{mem_o[psp_to_off(addr-2+i)]:02X}" for i in range(8))
        print(f"  0x{addr:08X}: {vc}->{vo}  ctx_C=[{ctx_c}]  ctx_O=[{ctx_o}]")

    # Also scan for word-sized 0->1 changes in overlay
    print("\n=== Word-aligned 0<->1 changes in overlay region ===")
    for addr in range(start, end, 4):
        off = psp_to_off(addr)
        if off + 4 > min_len:
            break
        vc = struct.unpack_from("<I", mem_c, off)[0]
        vo = struct.unpack_from("<I", mem_o, off)[0]
        if (vc == 0 and vo == 1) or (vc == 1 and vo == 0):
            print(f"  0x{addr:08X}: {vc} -> {vo}")

    # Let's also check the player data / quest context area
    # Known: 0x099FF2DC = HP food bonus, 0x09BF524C = HUD ptr
    # The item selector state might be near the player input/UI state

    # Scan 0x09900000 - 0x09C00000 for isolated 0->1 word changes
    print("\n=== Word-aligned 0<->1 changes in 0x099F0000 - 0x09C00000 ===")
    for addr in range(0x099F0000, 0x09C00000, 4):
        off = psp_to_off(addr)
        if off + 4 > min_len:
            break
        vc = struct.unpack_from("<I", mem_c, off)[0]
        vo = struct.unpack_from("<I", mem_o, off)[0]
        if (vc == 0 and vo == 1) or (vc == 1 and vo == 0):
            # Check if neighbors are also changing (skip noisy regions)
            prev_off = psp_to_off(addr - 4)
            next_off = psp_to_off(addr + 4)
            vcp = struct.unpack_from("<I", mem_c, prev_off)[0]
            vop = struct.unpack_from("<I", mem_o, prev_off)[0]
            vcn = struct.unpack_from("<I", mem_c, next_off)[0]
            von = struct.unpack_from("<I", mem_o, next_off)[0]
            isolated = (vcp == vop and vcn == von)
            tag = " [ISOLATED]" if isolated else ""
            print(f"  0x{addr:08X}: {vc} -> {vo}{tag}")

    # Check static game data area for flag
    print("\n=== Word-aligned 0<->1 changes in 0x0884xxxx - 0x0890xxxx (game code/data) ===")
    for addr in range(0x08840000, 0x08900000, 4):
        off = psp_to_off(addr)
        if off + 4 > min_len:
            break
        vc = struct.unpack_from("<I", mem_c, off)[0]
        vo = struct.unpack_from("<I", mem_o, off)[0]
        if (vc == 0 and vo == 1) or (vc == 1 and vo == 0):
            prev_off = psp_to_off(addr - 4)
            next_off = psp_to_off(addr + 4)
            vcp = struct.unpack_from("<I", mem_c, prev_off)[0]
            vop = struct.unpack_from("<I", mem_o, prev_off)[0]
            vcn = struct.unpack_from("<I", mem_c, next_off)[0]
            von = struct.unpack_from("<I", mem_o, next_off)[0]
            isolated = (vcp == vop and vcn == von)
            tag = " [ISOLATED]" if isolated else ""
            print(f"  0x{addr:08X}: {vc} -> {vo}{tag}")

if __name__ == "__main__":
    main()
