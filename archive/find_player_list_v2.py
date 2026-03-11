#!/usr/bin/env python3
"""Find player list rendering by tracing name data references."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

REG_NAMES = {0:'$zero',1:'$at',2:'$v0',3:'$v1',4:'$a0',5:'$a1',6:'$a2',7:'$a3',
             8:'$t0',9:'$t1',10:'$t2',11:'$t3',12:'$t4',13:'$t5',14:'$t6',15:'$t7',
             16:'$s0',17:'$s1',18:'$s2',19:'$s3',20:'$s4',21:'$s5',22:'$s6',23:'$s7',
             24:'$t8',25:'$t9',28:'$gp',29:'$sp',30:'$fp',31:'$ra'}

def disasm_simple(instr):
    """Simple MIPS disassembler for common instructions."""
    op = instr >> 26
    if op == 0x09:  # addiu
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"addiu {REG_NAMES.get(rt, f'${rt}')}, {REG_NAMES.get(rs, f'${rs}')}, {imm} (0x{imm & 0xFFFF:04X})"
    elif op == 0x0F:  # lui
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        return f"lui {REG_NAMES.get(rt, f'${rt}')}, 0x{imm:04X}"
    elif op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        return f"jal 0x{target:08X}"
    elif op == 0x23:  # lw
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"lw {REG_NAMES.get(rt, f'${rt}')}, {imm}({REG_NAMES.get(rs, f'${rs}')})"
    elif op == 0x25:  # lhu
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"lhu {REG_NAMES.get(rt, f'${rt}')}, {imm}({REG_NAMES.get(rs, f'${rs}')})"
    elif op == 0x2B:  # sw
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"sw {REG_NAMES.get(rt, f'${rt}')}, {imm}({REG_NAMES.get(rs, f'${rs}')})"
    elif op == 0x29:  # sh
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"sh {REG_NAMES.get(rt, f'${rt}')}, {imm}({REG_NAMES.get(rs, f'${rs}')})"
    elif op == 0x28:  # sb
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"sb {REG_NAMES.get(rt, f'${rt}')}, {imm}({REG_NAMES.get(rs, f'${rs}')})"
    elif op == 0x0D:  # ori
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        return f"ori {REG_NAMES.get(rt, f'${rt}')}, {REG_NAMES.get(rs, f'${rs}')}, 0x{imm:04X}"
    elif instr == 0:
        return "nop"
    elif op == 0 and (instr & 0x3F) == 0x08:  # jr
        rs = (instr >> 21) & 0x1F
        return f"jr {REG_NAMES.get(rs, f'${rs}')}"
    return f"? (op={op})"

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

# ============================================================
# The player name is at 0x09B491FC (from existing cheats)
# Name "Exceen" = FF25 FF58 FF25 FF58 FF45 FF4E
# Search for code that loads from near this address
# LUI 0x09B5 (since 0x09B491FC: lui = 0x09B5, offset = 0x91FC - 0x10000 = -0x6E04)
# Or LUI 0x09B4, offset = 0x91FC
# 0x91FC as signed = -0x6E04, so lui 0x09B5, addiu -0x6E04
# ============================================================

print("\n=== SEARCHING FOR CODE REFERENCING PLAYER NAME AREA ===")
# Player name at 0x09B491FC
# Also at 0x09BA17D0 (second copy)
# Search for LUI 0x09B5 (for 0x09B491FC) and LUI 0x09BA/0x09BB (for 0x09BA17D0)

target_his = [0x09B5, 0x09B4, 0x09BA, 0x09BB]
ranges = [
    ("overlay", 0x09C57C80, 0x09DC0000),
    ("eboot", 0x08800000, 0x08960000),
]

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)

    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        if (instr >> 26) == 0x0F:  # LUI
            imm = instr & 0xFFFF
            if imm in target_his:
                rt = (instr >> 16) & 0x1F
                psp = off - MEM_OFFSET + PSP_BASE
                # Check next few instructions for relevant offsets
                for k in range(1, 6):
                    noff = off + k * 4
                    if noff + 4 <= len(data):
                        ni = read_u32(data, noff)
                        nop = ni >> 26
                        if nop in (0x09, 0x0D):  # addiu or ori
                            nrs = (ni >> 21) & 0x1F
                            if nrs == rt:  # Same register as LUI target
                                nlo = ni & 0xFFFF
                                if nlo >= 0x8000 and nop == 0x09:
                                    full = (imm << 16) + nlo - 0x10000
                                else:
                                    full = (imm << 16) + nlo
                                # Check if this references player data area
                                if 0x09B40000 <= full <= 0x09BC0000:
                                    print(f"\n  [{region_name}] 0x{psp:08X}: lui ${rt}, 0x{imm:04X} -> 0x{full:08X}")
                                    # Dump context
                                    for j in range(-4, 16):
                                        coff = off + j * 4
                                        if start_off <= coff < end_off:
                                            ci = read_u32(data, coff)
                                            cpsp = coff - MEM_OFFSET + PSP_BASE
                                            cw = cpsp - 0x08800000
                                            d = disasm_simple(ci)
                                            marker = " <<<" if j == 0 else ""
                                            print(f"    0x{cpsp:08X} (CW 0x{cw:07X}): 0x{ci:08X}  {d}{marker}")

# ============================================================
# Also search for the print settings pointer 0x09ADB910
# Code that loads this pointer is involved in text rendering
# ============================================================
print("\n\n=== CODE LOADING PRINT SETTINGS PTR (0x09ADB910) ===")
# 0x09ADB910: lui 0x09AE, offset = 0xB910 - 0x10000 = -0x46F0
# So: lui $reg, 0x09AE; addiu/lw $reg, -0x46F0 (0xB910)

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)

    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        if (instr >> 26) == 0x0F:  # LUI
            imm = instr & 0xFFFF
            if imm == 0x09AE:
                rt = (instr >> 16) & 0x1F
                psp = off - MEM_OFFSET + PSP_BASE
                # Check next instructions for B910 offset
                for k in range(1, 4):
                    noff = off + k * 4
                    if noff + 4 <= len(data):
                        ni = read_u32(data, noff)
                        nlo = ni & 0xFFFF
                        if nlo == 0xB910:
                            print(f"\n  [{region_name}] 0x{psp:08X}: lui ${rt}, 0x09AE -> ref to 0x09ADB910")
                            for j in range(-4, 12):
                                coff = off + j * 4
                                if start_off <= coff < end_off:
                                    ci = read_u32(data, coff)
                                    cpsp = coff - MEM_OFFSET + PSP_BASE
                                    cw = cpsp - 0x08800000
                                    d = disasm_simple(ci)
                                    print(f"    0x{cpsp:08X} (CW 0x{cw:07X}): 0x{ci:08X}  {d}")

# ============================================================
# Search for store halfword (sh) instructions that write to
# offsets 0x120 and 0x122 (print cursor X/Y)
# These are the instructions that SET the text position before drawing
# ============================================================
print("\n\n=== SH instructions writing to offset +0x120/+0x122 (text cursor) ===")
for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)

    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        op = instr >> 26
        if op == 0x29:  # SH
            imm = instr & 0xFFFF
            if imm in (0x0120, 0x0122):
                psp = off - MEM_OFFSET + PSP_BASE
                rs = (instr >> 21) & 0x1F
                rt = (instr >> 16) & 0x1F
                print(f"\n  [{region_name}] 0x{psp:08X}: sh {REG_NAMES.get(rt, f'${rt}')}, 0x{imm:X}({REG_NAMES.get(rs, f'${rs}')})")
                # Context
                for j in range(-6, 6):
                    coff = off + j * 4
                    if start_off <= coff < end_off:
                        ci = read_u32(data, coff)
                        cpsp = coff - MEM_OFFSET + PSP_BASE
                        cw = cpsp - 0x08800000
                        d = disasm_simple(ci)
                        marker = " <<<" if j == 0 else ""
                        print(f"    0x{cpsp:08X} (CW 0x{cw:07X}): 0x{ci:08X}  {d}{marker}")

print("\nDone!")
