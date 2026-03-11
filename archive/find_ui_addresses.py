#!/usr/bin/env python3
"""Search MHP3rd save state for UI rendering addresses."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
PSP_BASE = 0x08000000
STATE_HEADER = 0xB0
MEM_OFFSET = 0x48  # offset in decompressed state where PSP RAM starts

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(STATE_HEADER)
        compressed = f.read()
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(psp_addr):
    return psp_addr - PSP_BASE + MEM_OFFSET

def offset_to_psp(off):
    return off - MEM_OFFSET + PSP_BASE

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_float(data, off):
    return struct.unpack_from('<f', data, off)[0]

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)
print(f"Decompressed size: {len(data)} bytes")

# ============================================================
# 1. Verify known addresses
# ============================================================
print("\n=== VERIFYING KNOWN ADDRESSES ===")
known = {
    "Bar scale HP (150/scale)": 0x09DA93A0,
    "Bar scale Stam (900/scale)": 0x09DA93A4,
    "Map scale float": 0x09DA93EC,
    "Map inv scale": 0x09DA93E4,
    "Map icon size": 0x09D90430,
    "Map position": 0x09D902B0,
    "Monster ptr table": 0x09DA9860,
    "Task sentinel": 0x09C57CA0,
    "Print settings": 0x09ADB910,
}
for name, addr in known.items():
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        val_u32 = read_u32(data, off)
        val_f = read_float(data, off)
        print(f"  {name}: 0x{addr:08X} = 0x{val_u32:08X} (float: {val_f:.4f})")

# ============================================================
# 2. Search overlay for ADDIU clusters (UI coordinate setters)
# ============================================================
print("\n=== SEARCHING FOR ADDIU CLUSTERS IN OVERLAY (UI COORDS) ===")
# The game_task overlay is at 0x09C57C80, ~1.5MB
# UI rendering functions use clusters of: addiu $reg, $zero, <small_value>
# Encoding: 0x2400XXXX where bits 25:21 = 0 (src=$zero), bits 20:16 = dst
# addiu $a1, $zero, val = 0x24050000 | val  (a1 = $5)
# addiu $a0, $zero, val = 0x24040000 | val  (a0 = $4)
# addiu $a2, $zero, val = 0x24060000 | val  (a2 = $6)
# etc.

overlay_start = 0x09C57C80
overlay_end = overlay_start + 0x200000  # ~2MB search range

# Look for functions with multiple addiu $reg, $zero, <small_val> in a small window
def find_addiu_clusters(data, start_psp, end_psp, window=64, min_count=3):
    """Find clusters of addiu $reg, $zero, val instructions."""
    results = []
    start_off = psp_to_offset(start_psp)
    end_off = min(psp_to_offset(end_psp), len(data) - 4)

    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        # addiu $rt, $zero, imm: opcode=001001, rs=00000
        # bits 31:26 = 001001, bits 25:21 = 00000
        if (instr >> 21) == 0x120:  # 0x24000000 >> 21
            # Found addiu $rt, $zero, imm
            rt = (instr >> 16) & 0x1F
            imm = instr & 0xFFFF
            if imm > 0x8000:
                imm = imm - 0x10000  # sign extend
            # Check for small position values (0-500 range)
            if 0 <= imm <= 500:
                # Count nearby addiu $reg, $zero in window
                count = 0
                nearby = []
                for j in range(off - window, off + window, 4):
                    if start_off <= j < end_off:
                        instr2 = read_u32(data, j)
                        if (instr2 >> 21) == 0x120:
                            rt2 = (instr2 >> 16) & 0x1F
                            imm2 = instr2 & 0xFFFF
                            if imm2 > 0x8000:
                                imm2 = imm2 - 0x10000
                            if 0 <= imm2 <= 500:
                                count += 1
                                nearby.append((offset_to_psp(j), rt2, imm2))
                if count >= min_count:
                    results.append((offset_to_psp(off), rt, imm, count, nearby))
    return results

# Search the overlay
clusters = find_addiu_clusters(data, overlay_start, overlay_end, window=80, min_count=4)

# Deduplicate by grouping nearby clusters
seen = set()
for psp_addr, rt, imm, count, nearby in clusters:
    group_key = psp_addr // 128
    if group_key in seen:
        continue
    seen.add(group_key)
    reg_names = {4: 'a0', 5: 'a1', 6: 'a2', 7: 'a3', 8: 't0', 9: 't1'}
    print(f"\n  Cluster at 0x{psp_addr:08X} ({count} addiu in window):")
    for addr, r, v in nearby:
        rn = reg_names.get(r, f'${r}')
        cw_off = addr - 0x08800000
        print(f"    0x{addr:08X} (CW 0x{cw_off:07X}): addiu {rn}, $zero, {v} (0x{v&0xFFFF:04X})")

# ============================================================
# 3. Search eboot for similar patterns (static UI code)
# ============================================================
print("\n\n=== SEARCHING EBOOT FOR ADDIU CLUSTERS (0x0883-088F) ===")
eboot_clusters = find_addiu_clusters(data, 0x08830000, 0x08900000, window=80, min_count=4)

seen2 = set()
for psp_addr, rt, imm, count, nearby in eboot_clusters:
    group_key = psp_addr // 128
    if group_key in seen2:
        continue
    seen2.add(group_key)
    reg_names = {4: 'a0', 5: 'a1', 6: 'a2', 7: 'a3', 8: 't0', 9: 't1'}
    print(f"\n  Cluster at 0x{psp_addr:08X} ({count} addiu in window):")
    for addr, r, v in nearby:
        rn = reg_names.get(r, f'${r}')
        cw_off = addr - 0x08800000
        print(f"    0x{addr:08X} (CW 0x{cw_off:07X}): addiu {rn}, $zero, {v} (0x{v&0xFFFF:04X})")

# ============================================================
# 4. Search for UI sprite data tables (like MHFU's 0x08938Axx)
# ============================================================
print("\n\n=== SEARCHING FOR SPRITE DATA TABLES ===")
# In MHFU, the UI sprite table had consecutive small 16-bit values
# representing X, Y, width, height coordinates
# Pattern: sequences of 16-bit values in range 0-500

def find_sprite_tables(data, start_psp, end_psp, min_entries=8):
    """Find regions with many consecutive small 16-bit values."""
    results = []
    start_off = psp_to_offset(start_psp)
    end_off = min(psp_to_offset(end_psp), len(data) - 2)

    i = start_off
    while i < end_off:
        # Count consecutive small 16-bit values
        count = 0
        j = i
        while j < end_off:
            val = read_u16(data, j)
            if val <= 500:
                count += 1
                j += 2
            else:
                break
        if count >= min_entries:
            psp_addr = offset_to_psp(i)
            results.append((psp_addr, count))
            # Print some values
            vals = []
            for k in range(min(count, 16)):
                vals.append(read_u16(data, i + k*2))
            print(f"  0x{psp_addr:08X}: {count} small u16s: {vals}")
            i = j
        else:
            i += 2
    return results

# Search overlay data regions
print("In overlay (0x09D8-0x09DB):")
find_sprite_tables(data, 0x09D80000, 0x09DB0000, min_entries=10)

# Search eboot data regions
print("\nIn eboot data (0x0890-0x0898):")
find_sprite_tables(data, 0x08900000, 0x08980000, min_entries=10)

# ============================================================
# 5. Dump area around known bar scale address for context
# ============================================================
print("\n\n=== MEMORY AROUND BAR SCALE (0x09DA9380-0x09DA9400) ===")
for addr in range(0x09DA9380, 0x09DA9400, 4):
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        val = read_u32(data, off)
        fval = read_float(data, off)
        cw = addr - 0x08800000
        print(f"  0x{addr:08X} (CW 0x2{cw:07X}): 0x{val:08X}  float={fval:.6f}")

# ============================================================
# 6. Look for the HP/Stamina bar rendering code
# ============================================================
print("\n\n=== SEARCHING FOR HP BAR RENDERING (JAL patterns near known addrs) ===")
# kurogami's bar scale is at 0x09DA93A0. Search for code that loads from this address.
# LUI + ORI pattern to load 0x09DA93A0:
#   lui $reg, 0x09DB (or 0x09DA)
#   ori/addiu $reg, $reg, 0x93A0

# Search for lui 0x09DA or 0x09DB in overlay
target_hi = [0x09DA, 0x09DB]
overlay_off_start = psp_to_offset(overlay_start)
overlay_off_end = min(psp_to_offset(overlay_end), len(data) - 4)

print("Code referencing 0x09DAxxxx or 0x09DBxxxx:")
for off in range(overlay_off_start, overlay_off_end, 4):
    instr = read_u32(data, off)
    # LUI: 0x3C000000 | (rt << 16) | imm
    if (instr >> 26) == 0x0F:  # LUI opcode
        imm = instr & 0xFFFF
        if imm in target_hi:
            psp_addr = offset_to_psp(off)
            rt = (instr >> 16) & 0x1F
            # Check next few instructions for addiu/ori with low part
            for k in range(1, 5):
                next_off = off + k * 4
                if next_off + 4 <= len(data):
                    next_instr = read_u32(data, next_off)
                    next_op = next_instr >> 26
                    if next_op in (0x09, 0x0D):  # addiu or ori
                        lo = next_instr & 0xFFFF
                        full_addr = (imm << 16) + (lo if lo < 0x8000 else lo - 0x10000)
                        if 0x09DA9380 <= full_addr <= 0x09DA9400:
                            print(f"  0x{psp_addr:08X}: lui ${rt}, 0x{imm:04X} -> 0x{full_addr:08X}")

print("\nDone!")
