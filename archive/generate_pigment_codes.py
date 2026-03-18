#!/usr/bin/env python3
"""
Generate CWCheat codes to universally enable armor pigment coloring in MHP3rd.

Two approaches:
1. Data approach: Write 0x01 to byte+19 of ALL armor data table entries
2. Code approach: Patch the lbu instructions that read the flag

The data approach is more reliable since it propagates through all code paths.
"""
import struct

CW_BASE = 0x08800000

# Armor data tables: base address, entry count, entry size=40
TABLES = {
    'HEAD':  (0x089825AC, 256),
    'CHEST': (0x08980144, 233),
    'ARMS':  (0x0897DFFC, 213),
    'WAIST': (0x08984DAC, 214),
    'LEGS':  (0x08986F1C, 220),
}

PIGMENT_OFFSET = 19  # byte offset within 40-byte entry
ENTRY_SIZE = 40

def cw_addr(psp_addr):
    return psp_addr - CW_BASE

def generate_data_codes():
    """Generate per-entry byte writes to set pigment flag for all armor."""
    lines = []
    total = 0
    for name, (base, count) in TABLES.items():
        lines.append(f"; {name}: {count} entries at 0x{base:08X}")
        for i in range(count):
            addr = base + i * ENTRY_SIZE + PIGMENT_OFFSET
            offset = cw_addr(addr)
            lines.append(f"_L 0x0{offset:07X} 0x00000001")
            total += 1
    return lines, total

def generate_code_patches():
    """Generate code patches for all known pigment flag read sites."""
    patches = []

    # EBOOT patches (always in memory)
    patches.append("; EBOOT: entity pigment population (5-slot loop)")
    patches.append("; 0x088A43FC: lbu $v1, 0x13($v0) -> addiu $v1, $zero, 1")
    patches.append(f"_L 0x200A43FC 0x24030001")

    patches.append("; EBOOT: pigment query functions via 0x0885C3DC")
    patches.append("; 0x088690EC: lbu $v0, 0x13($v0) -> addiu $v0, $zero, 1")
    patches.append(f"_L 0x200690EC 0x24020001")
    patches.append("; 0x088691D8: lbu $v1, 0x13($v0) -> addiu $v1, $zero, 1")
    patches.append(f"_L 0x200691D8 0x24030001")
    patches.append("; 0x088A8E38: lbu $v0, 0x13($v0) -> addiu $v0, $zero, 1")
    patches.append(f"_L 0x200A8E38 0x24020001")

    patches.append("; EBOOT: get_pigment_flag fallthrough return 0 -> return 1")
    patches.append("; 0x0885C82C: addu $v0,$zero,$zero -> addiu $v0, $zero, 1")
    patches.append(f"_L 0x2005C82C 0x24020001")

    patches.append("; EBOOT: direct pigment read at 0x0883CF2C")
    patches.append("; 0x0883CF2C: lbu $v1, 0x13($v0) -> addiu $v1, $zero, 1")
    patches.append(f"_L 0x2003CF2C 0x24030001")

    # Overlay patches (need guard)
    # Guard: check overlay prologue at 0x09CB73A0 == 0x27BDFF40
    # Lower 16 bits in LE = 0xFF40
    guard = "0xD04B73A0 0x0000FF40"

    patches.append("")
    patches.append("; Overlay: equipment box UI pigment gate")
    patches.append("; Force $s4=1 at 0x09CB740C (pigment disabled path -> enabled)")
    patches.append(f"_L {guard}")
    patches.append(f"_L 0x204B740C 0x24140001")

    patches.append("; Overlay: first individual item pigment check")
    patches.append(f"_L {guard}")
    patches.append(f"_L 0x204B73EC 0x24030001")

    patches.append("; Overlay: second pigment check at 0x09CB74E8")
    patches.append(f"_L {guard}")
    patches.append(f"_L 0x204B74E8 0x24020001")

    return patches

print("=" * 60)
print("APPROACH 1: CODE PATCHES (recommended - fewer lines)")
print("=" * 60)
code_patches = generate_code_patches()
for line in code_patches:
    print(line)

print(f"\nTotal code patch lines: {sum(1 for l in code_patches if l.startswith('_L'))}")

print()
print("=" * 60)
print("APPROACH 2: DATA WRITES (brute force - write to all entries)")
print("=" * 60)
data_lines, total = generate_data_codes()
print(f"; Total entries: {total}")
print(f"; This writes 0x01 to byte+19 of every armor data table entry")
print(f"; WARNING: {total} CWCheat lines, runs every frame")
# Only print first few as sample
for line in data_lines[:20]:
    print(line)
print(f"... ({total - 20} more lines)")

# Write full data codes to a file
with open('/Users/Exceen/Downloads/mhp3rd_modding/pigment_all_data.txt', 'w') as f:
    f.write("_C1 Pigment Enable: ALL Armor (data writes)\n")
    for line in data_lines:
        f.write(line + '\n')
print(f"\nFull data codes written to pigment_all_data.txt")

# Also generate the complete INI section for code patches
print()
print("=" * 60)
print("READY-TO-USE CWCheat SECTION")
print("=" * 60)
print()
print("_C1 Pigment Enable: ALL Armor (code patches)")
for line in code_patches:
    if line.startswith('_L'):
        print(line)
