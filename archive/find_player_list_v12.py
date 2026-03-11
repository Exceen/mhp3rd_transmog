#!/usr/bin/env python3
"""Identify all layout table entries used for player list background rendering.
Dump the layout table entries near the player list area, and trace which entries
are referenced by 0x09D60280 and 0x09D6172C."""

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

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    sa = (instr >> 6) & 0x1F
    func = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x18: return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x01:
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

LAYOUT_TABLE = 0x09D92CB0
ENTRY_SIZE = 36
INDEX_TABLE = 0x09D95DEC

# Dump layout table entries 0 through ~100 to see which ones have coordinates
# near the player list area (X=0-40, Y=0-130)
print("=== LAYOUT TABLE ENTRIES (entries with Y 0-150 or near player list) ===")
print(f"Table base: 0x{LAYOUT_TABLE:08X}, entry size: {ENTRY_SIZE}")
for i in range(120):
    entry_addr = LAYOUT_TABLE + i * ENTRY_SIZE
    off = psp_to_offset(entry_addr)
    if off + ENTRY_SIZE > len(data): break

    # Read key fields
    x = read_s16(data, off + 24)
    y = read_s16(data, off + 26)

    # Read other fields for context
    f0 = read_u32(data, off + 0)
    f4 = read_u32(data, off + 4)
    f8 = read_u32(data, off + 8)
    f12 = read_u32(data, off + 12)
    f16 = read_u32(data, off + 16)
    f20 = read_u32(data, off + 20)
    f24 = read_u32(data, off + 24)  # X(lo16) Y(hi16) packed
    f28 = read_u32(data, off + 28)
    f32 = read_u32(data, off + 32)

    # Highlight entries that look like player list
    marker = ""
    if 0 <= x <= 50 and 0 <= y <= 130:
        marker = " <<< PLAYER LIST AREA?"
    if i in [47, 57, 70, 82]:
        marker = " <<< PLAYER NAME ENTRY"

    cw_addr = entry_addr - 0x08800000
    print(f"  [{i:3d}] 0x{entry_addr:08X} (CW 0x{cw_addr:07X}): "
          f"X={x:4d} Y={y:4d}  "
          f"[{f0:08X} {f4:08X} {f8:08X} {f12:08X} {f16:08X} {f20:08X} {f24:08X} {f28:08X} {f32:08X}]"
          f"{marker}")

# Also dump the index table to see what indices map to what
print(f"\n=== INDEX TABLE at 0x{INDEX_TABLE:08X} ===")
idx_off = psp_to_offset(INDEX_TABLE)
for i in range(20):
    if idx_off + i >= len(data): break
    idx = read_u8(data, idx_off + i)
    entry_addr = LAYOUT_TABLE + idx * ENTRY_SIZE
    eoff = psp_to_offset(entry_addr)
    x = read_s16(data, eoff + 24) if eoff + 26 <= len(data) else 0
    y = read_s16(data, eoff + 26) if eoff + 28 <= len(data) else 0
    print(f"  index_table[{i}] = {idx} -> entry at 0x{entry_addr:08X} (X={x}, Y={y})")

# Now carefully trace 0x09D60280 to see which entries it uses
print("\n\n=== DETAILED TRACE OF 0x09D60280 (background renderer) ===")
for addr in range(0x09D60280, 0x09D60600, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    # Flag any references to layout table
    if "addiu" in d:
        simm = instr & 0xFFFF
        if simm < 0x8000:
            simm_val = simm
        else:
            simm_val = simm - 0x10000
        # Check if this is an offset into the layout table
        if simm_val > 0 and simm_val % ENTRY_SIZE == 0:
            entry_idx = simm_val // ENTRY_SIZE
            marker = f" [entry_offset={simm_val}, idx={entry_idx}]"
        # Check for known offsets
        if simm_val == 72:  # entry 2 * 36
            marker = " [ENTRY 2 OFFSET]"
        if simm_val == 108:  # entry 3 * 36
            marker = " [ENTRY 3 OFFSET]"
        if simm_val == 36:
            marker = " [ENTRY 1 OFFSET]"
        if simm_val == 144:
            marker = " [ENTRY 4 OFFSET]"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target == 0x08901168:
            marker = " [SPRITE RENDER]"
        elif 0x088E0000 <= target <= 0x08910000:
            marker += f" [RENDER:{target:08X}]"
        elif 0x09D50000 <= target <= 0x09D70000:
            marker += f" [OVL:{target:08X}]"
    if "jr $ra" in d:
        marker = " [RETURN]"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
        break
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also trace 0x09D6172C
print("\n\n=== DETAILED TRACE OF 0x09D6172C (second background renderer) ===")
for addr in range(0x09D6172C, 0x09D61C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "addiu" in d:
        simm = instr & 0xFFFF
        simm_val = simm if simm < 0x8000 else simm - 0x10000
        if simm_val > 0 and simm_val % ENTRY_SIZE == 0:
            entry_idx = simm_val // ENTRY_SIZE
            marker = f" [entry_offset={simm_val}, idx={entry_idx}]"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target == 0x08901168:
            marker = " [SPRITE RENDER]"
        elif 0x088E0000 <= target <= 0x08910000:
            marker += f" [RENDER:{target:08X}]"
        elif 0x09D50000 <= target <= 0x09D70000:
            marker += f" [OVL:{target:08X}]"
    if "jr $ra" in d:
        marker = " [RETURN]"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
        break
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also trace 0x09D648AC more carefully - it renders HP bar sprites
print("\n\n=== DETAILED TRACE OF 0x09D648AC (HP bar renderer) ===")
for addr in range(0x09D648AC, 0x09D64D00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target == 0x08901168:
            marker = " [SPRITE RENDER]"
        elif 0x088E0000 <= target <= 0x08910000:
            marker += f" [RENDER:{target:08X}]"
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jr $ra" in d:
        marker = " [RETURN]"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
        break
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Dump parent function 0x09D6C498 around the rendering section (0x09D6C700 - 0x09D6CA00)
# to see the complete call sequence
print("\n\n=== PARENT 0x09D6C498 RENDERING SECTION (0x09D6C700-0x09D6CA00) ===")
for addr in range(0x09D6C700, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if target == 0x09D6380C: marker = " [PLAYER NAMES/ICONS]"
        elif target == 0x09D6309C: marker = " [SECOND RENDERER]"
        elif target == 0x09D60280: marker = " [BG SPRITES A]"
        elif target == 0x09D6172C: marker = " [BG SPRITES B]"
        elif target == 0x09D648AC: marker = " [HP BARS]"
        elif target == 0x09D62384: marker = " [FUNC 0x09D62384]"
        elif target == 0x09D5E8D0: marker = " [FUNC 0x09D5E8D0]"
        elif target == 0x09D5E9C0: marker = " [FUNC 0x09D5E9C0]"
        elif 0x09D50000 <= target <= 0x09D70000:
            marker = f" [OVL:{target:08X}]"
        elif 0x088E0000 <= target <= 0x08910000:
            marker = f" [EBOOT:{target:08X}]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

print("\nDone!")
