#!/usr/bin/env python3
"""Focused search for MHP3rd UI addresses."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
PSP_BASE = 0x08000000
STATE_HEADER = 0xB0
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(STATE_HEADER)
        compressed = f.read()
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(psp_addr):
    return psp_addr - PSP_BASE + MEM_OFFSET

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_float(data, off):
    return struct.unpack_from('<f', data, off)[0]

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

# ============================================================
# 1. Wider dump around bar scale - this area has UI layout floats
# ============================================================
print("\n=== UI FLOAT TABLE (0x09DA9300 - 0x09DA9500) ===")
for addr in range(0x09DA9300, 0x09DA9500, 4):
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        val = read_u32(data, off)
        fval = read_float(data, off)
        cw = addr - 0x08800000
        # Highlight interesting values
        marker = ""
        if addr == 0x09DA93A0: marker = " <-- HP bar ref (150/scale)"
        elif addr == 0x09DA93A4: marker = " <-- Stam bar ref (900/scale)"
        elif addr == 0x09DA93EC: marker = " <-- Map scale"
        elif addr == 0x09DA93E4: marker = " <-- Map inv scale"
        elif 1.0 <= abs(fval) <= 500.0 and val != 0x3F800000 and val != 0:
            marker = " ***"
        print(f"  0x{addr:08X} (CW 0x2{cw:07X}): 0x{val:08X}  f={fval:12.4f}{marker}")

# ============================================================
# 2. Search near map position address for more UI params
# ============================================================
print("\n=== UI DATA NEAR MAP POS (0x09D90200 - 0x09D90500) ===")
for addr in range(0x09D90200, 0x09D90500, 4):
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        val = read_u32(data, off)
        fval = read_float(data, off)
        hi = (val >> 16) & 0xFFFF
        lo = val & 0xFFFF
        cw = addr - 0x08800000
        marker = ""
        if addr == 0x09D902B0: marker = " <-- Map position"
        elif addr == 0x09D90430: marker = " <-- Map icon size"
        # Check if looks like packed X/Y (two small u16s)
        elif lo <= 500 and hi <= 500 and val != 0:
            marker = f" *** packed? lo={lo} hi={hi}"
        print(f"  0x{addr:08X} (CW 0x2{cw:07X}): 0x{val:08X}  f={fval:12.4f}{marker}")

# ============================================================
# 3. Search for ADDIU clusters with screen-coordinate values (5-480)
# ============================================================
print("\n=== ADDIU CLUSTERS WITH SCREEN COORDS (overlay) ===")
overlay_start = psp_to_offset(0x09C57C80)
overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)

clusters_found = []
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if (instr >> 21) == 0x120:  # addiu $rt, $zero, imm
        imm = instr & 0xFFFF
        if imm > 0x8000: imm -= 0x10000
        # Focus on screen-coordinate-like values
        if 5 <= imm <= 480:
            # Count nearby addiu with screen coords in tight window
            count = 0
            nearby = []
            for j in range(off - 48, off + 48, 4):
                if overlay_start <= j < overlay_end:
                    i2 = read_u32(data, j)
                    if (i2 >> 21) == 0x120:
                        im2 = i2 & 0xFFFF
                        if im2 > 0x8000: im2 -= 0x10000
                        if 5 <= im2 <= 480:
                            count += 1
                            rt2 = (i2 >> 16) & 0x1F
                            psp2 = j - MEM_OFFSET + PSP_BASE
                            nearby.append((psp2, rt2, im2))
            if count >= 3:
                group_key = off // 96
                clusters_found.append((group_key, off, count, nearby))

# Deduplicate
seen = set()
reg_names = {4:'a0', 5:'a1', 6:'a2', 7:'a3', 8:'t0', 9:'t1', 10:'t2', 11:'t3'}
for gk, off, count, nearby in clusters_found:
    if gk in seen: continue
    seen.add(gk)
    psp = off - MEM_OFFSET + PSP_BASE
    print(f"\n  0x{psp:08X} ({count} screen-coord addiu):")
    for addr, r, v in nearby:
        rn = reg_names.get(r, f'${r}')
        cw = addr - 0x08800000
        print(f"    0x{addr:08X} (CW 0x2{cw:07X}): addiu {rn}, $zero, {v}")

# ============================================================
# 4. Same search in eboot
# ============================================================
print("\n=== ADDIU CLUSTERS WITH SCREEN COORDS (eboot 0x0884-0x0890) ===")
eboot_start = psp_to_offset(0x08840000)
eboot_end = min(psp_to_offset(0x08900000), len(data) - 4)

clusters_found2 = []
for off in range(eboot_start, eboot_end, 4):
    instr = read_u32(data, off)
    if (instr >> 21) == 0x120:
        imm = instr & 0xFFFF
        if imm > 0x8000: imm -= 0x10000
        if 5 <= imm <= 480:
            count = 0
            nearby = []
            for j in range(off - 48, off + 48, 4):
                if eboot_start <= j < eboot_end:
                    i2 = read_u32(data, j)
                    if (i2 >> 21) == 0x120:
                        im2 = i2 & 0xFFFF
                        if im2 > 0x8000: im2 -= 0x10000
                        if 5 <= im2 <= 480:
                            count += 1
                            rt2 = (i2 >> 16) & 0x1F
                            psp2 = j - MEM_OFFSET + PSP_BASE
                            nearby.append((psp2, rt2, im2))
            if count >= 3:
                group_key = off // 96
                clusters_found2.append((group_key, off, count, nearby))

seen2 = set()
for gk, off, count, nearby in clusters_found2:
    if gk in seen2: continue
    seen2.add(gk)
    psp = off - MEM_OFFSET + PSP_BASE
    print(f"\n  0x{psp:08X} ({count} screen-coord addiu):")
    for addr, r, v in nearby:
        rn = reg_names.get(r, f'${r}')
        cw = addr - 0x08800000
        print(f"    0x{addr:08X} (CW 0x2{cw:07X}): addiu {rn}, $zero, {v}")

# ============================================================
# 5. Look for code that references bar scale floats
# ============================================================
print("\n=== CODE LOADING BAR SCALE FLOATS ===")
# lwc1 instruction loads float: opcode 0x31 (110001)
# lwc1 $ft, offset($rs): 0xC4000000 | (rs << 21) | (ft << 16) | offset
# We need to find lwc1 with offset matching low bits of 0x93A0
# After a lui with 0x09DB (since 0x09DA93A0 = 0x09DB0000 + (-0x6C60) = 0x09DA93A0)
# Actually, lui 0x09DB, then addiu -0x6C60 or lwc1 offset -0x6C60
# Or lui 0x09DA, then lwc1 offset 0x93A0... but 0x93A0 > 0x7FFF so sign extended = -0x6C60

target_lo = 0x93A0  # which as signed = -0x6C60 = 0x9360... hmm
# 0x09DA93A0: lui would be 0x09DB (since 0x93A0 is negative when sign-extended: 0x09DA + 1 = 0x09DB, offset = 0x93A0 - 0x10000 = -0x6C60)
# So: lui $reg, 0x09DB; lwc1 $ft, -0x6C60($reg)

for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if (instr >> 26) == 0x0F:  # LUI
        imm = instr & 0xFFFF
        if imm == 0x09DB:
            rt = (instr >> 16) & 0x1F
            psp = off - MEM_OFFSET + PSP_BASE
            # Check surrounding instructions
            context = []
            for k in range(-4, 12):
                coff = off + k * 4
                if overlay_start <= coff < overlay_end:
                    ci = read_u32(data, coff)
                    cpsp = coff - MEM_OFFSET + PSP_BASE
                    context.append(f"    0x{cpsp:08X}: 0x{ci:08X}")
            if any("9360" in c or "93a0" in c.lower() for c in context):
                print(f"\n  LUI ${rt}, 0x09DB at 0x{psp:08X}:")
                for c in context:
                    print(c)

print("\nDone!")
