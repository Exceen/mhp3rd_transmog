#!/usr/bin/env python3
"""Generate CWCheat codes for scaling the entire MHP3rd clock UI.

Layout table at 0x09D92CB0, 36-byte entries.
Entry format: halfwords at +0(v0_x), +2(v0_y), +4(v1_x), +6(v1_y), +24(X), +26(Y)
Texture coords at +8..+15 are NOT modified.

All values verified from save state dump.
"""

LAYOUT_BASE = 0x09D92CB0
ENTRY_SIZE = 36
CW_BASE = 0x08800000

# ALL clock entries: (v0_x, v0_y, v1_x, v1_y, X, Y)
# Values from dump_all_clock_entries.py output
ALL_ENTRIES = {
    # Background/frame (always rendered)
    # 2 is the clock background — NOT scaled (user wants it full size)
    3:  (0,  0,  14, 15, 37, 11),   # clock hands background 14x15
    # Mode indicators (day/night palette A)
    4:  (0, 14,  14,  0, 37, 26),
    5:  (15, 14,  0,  0, 22, 26),
    6:  (0,  0,  15, 15, 22, 11),
    7:  (15, 14,  0,  0, 37, 26),
    # Mode indicators (day/night palette B, semi-transparent)
    8:  (0,  0,  14, 15, 37, 11),
    9:  (0, 14,  14,  0, 37, 26),
    10: (15, 14,  0,  0, 22, 26),
    11: (0,  0,  15, 15, 22, 11),
    12: (15, 14,  0,  0, 37, 26),
    # Flash/transition indicators
    13: (0,  0,   5, 21, 34, 25),
    14: (0,  0,  19, 12, 35, 25),
    15: (19, 12,  0,  0, 18, 14),
    # Clock hand (11 rotational positions)
    16: (0,  0,   7, 24, 33,  5),
    17: (0,  0,  14, 22, 33,  7),
    18: (0,  0,  23, 14, 33, 15),
    19: (0,  0,  24,  7, 33, 22),
    20: (0, 14,  23,  0, 33, 22),
    21: (0, 22,  14,  0, 33, 22),
    22: (0, 24,   7,  0, 33, 22),
    23: (14, 22,  0,  0, 26, 22),
    24: (23, 14,  0,  0, 17, 22),
    25: (24,  0,   0,  7, 16, 22),
    26: (23,  0,   0, 14, 16, 15),
    # 28 is the CLOCK2 colon/digit separator — NOT scaled (shared with other UI)
}

# Pivot point: geometric center of background sprite
# Entry 2: v0=(0,0) v1=(67,46) at X=2, Y=4
# Center = (2 + 67/2, 4 + 46/2) = (35.5, 27)
PIVOT_X = 36
PIVOT_Y = 27


def scale_entry(v0x, v0y, v1x, v1y, ox, oy, scale):
    nv0x = round(v0x * scale)
    nv0y = round(v0y * scale)
    nv1x = round(v1x * scale)
    nv1y = round(v1y * scale)
    nx = round(PIVOT_X + (ox - PIVOT_X) * scale)
    ny = round(PIVOT_Y + (oy - PIVOT_Y) * scale)
    return nv0x, nv0y, nv1x, nv1y, nx, ny


def generate_cheat(scale, label, entry_filter=None):
    lines = []
    lines.append(f"_C0  Clock Scale {label}")
    guard = "_L 0xD1457C90 0x00005FA0"

    for idx in sorted(ALL_ENTRIES.keys()):
        if entry_filter and idx not in entry_filter:
            continue
        v0x, v0y, v1x, v1y, ox, oy = ALL_ENTRIES[idx]
        nv0x, nv0y, nv1x, nv1y, nx, ny = scale_entry(
            v0x, v0y, v1x, v1y, ox, oy, scale)

        entry_addr = LAYOUT_BASE + idx * ENTRY_SIZE
        vert0 = (nv0x & 0xFFFF) | ((nv0y & 0xFFFF) << 16)
        vert1 = (nv1x & 0xFFFF) | ((nv1y & 0xFFFF) << 16)
        xy = (nx & 0xFFFF) | ((ny & 0xFFFF) << 16)

        cw0 = (entry_addr + 0) - CW_BASE
        cw4 = (entry_addr + 4) - CW_BASE
        cw24 = (entry_addr + 24) - CW_BASE

        lines.append(f"{guard}")
        lines.append(f"_L 0x2{cw0:07X} 0x{vert0:08X}")
        lines.append(f"{guard}")
        lines.append(f"_L 0x2{cw4:07X} 0x{vert1:08X}")
        lines.append(f"{guard}")
        lines.append(f"_L 0x2{cw24:07X} 0x{xy:08X}")

    return lines


# Print scaled values for verification
for label, scale in [("50%", 0.5), ("75%", 0.75), ("100% (Restore)", 1.0)]:
    print(f"\n--- {label} (pivot {PIVOT_X},{PIVOT_Y}) ---")
    for idx in sorted(ALL_ENTRIES.keys()):
        v0x, v0y, v1x, v1y, ox, oy = ALL_ENTRIES[idx]
        nv0x, nv0y, nv1x, nv1y, nx, ny = scale_entry(
            v0x, v0y, v1x, v1y, ox, oy, scale)
        print(f"  [{idx:2d}] ({v0x},{v0y})-({v1x},{v1y}) @({ox},{oy})"
              f" -> ({nv0x},{nv0y})-({nv1x},{nv1y}) @({nx},{ny})")

MAX_LINES = 32  # CWCheat max lines per code

print("\n\n=== CWCHEAT CODES ===\n")

for label, scale in [("50%", 0.5), ("75%", 0.75), ("100% (Restore)", 1.0)]:
    # Generate all _L lines (no header)
    all_lines = []
    guard = "_L 0xD1457C90 0x00005FA0"
    for idx in sorted(ALL_ENTRIES.keys()):
        v0x, v0y, v1x, v1y, ox, oy = ALL_ENTRIES[idx]
        nv0x, nv0y, nv1x, nv1y, nx, ny = scale_entry(
            v0x, v0y, v1x, v1y, ox, oy, scale)
        entry_addr = LAYOUT_BASE + idx * ENTRY_SIZE
        vert0 = (nv0x & 0xFFFF) | ((nv0y & 0xFFFF) << 16)
        vert1 = (nv1x & 0xFFFF) | ((nv1y & 0xFFFF) << 16)
        xy = (nx & 0xFFFF) | ((ny & 0xFFFF) << 16)
        cw0 = (entry_addr + 0) - CW_BASE
        cw4 = (entry_addr + 4) - CW_BASE
        cw24 = (entry_addr + 24) - CW_BASE
        all_lines.append(f"{guard}")
        all_lines.append(f"_L 0x2{cw0:07X} 0x{vert0:08X}")
        all_lines.append(f"{guard}")
        all_lines.append(f"_L 0x2{cw4:07X} 0x{vert1:08X}")
        all_lines.append(f"{guard}")
        all_lines.append(f"_L 0x2{cw24:07X} 0x{xy:08X}")

    # Split into chunks of MAX_LINES - 1 (reserve 1 for header)
    chunk_max = MAX_LINES - 1
    chunks = [all_lines[i:i+chunk_max] for i in range(0, len(all_lines), chunk_max)]
    for ci, chunk in enumerate(chunks):
        part = f" ({ci+1}/{len(chunks)})" if len(chunks) > 1 else ""
        print(f"_C0  Clock Scale {label}{part}")
        print("\n".join(chunk))
        print()
