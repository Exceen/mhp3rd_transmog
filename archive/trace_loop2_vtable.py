#!/usr/bin/env python3
"""Dump 0x09D62B30 fully and trace what JALR vtable calls resolve to at runtime."""

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

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F; sa = (instr >> 6) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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

# First, dump 0x09D62B30 fully
print("=== 0x09D62B30 (PER_PLAYER_LOOP2) FULL DUMP ===")
for addr in range(0x09D62B30, 0x09D62E00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "jalr" in d: marker = " *** INDIRECT CALL ***"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x09C50000 <= target <= 0x09DA0000:
            marker = f" [OVL:0x{target:08X}]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")
    if "jr $ra" in d:
        break

# Now look at what the orchestrator passes to LOOP2
print("\n\n=== LOOP2 CALLER CONTEXT (0x09D6C934-0x09D6C974) ===")
for addr in range(0x09D6C934, 0x09D6C978, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: {d}")

# Try to find the player list data structure at runtime
# The orchestrator uses $s2 as the main HUD structure
# Player entries are at offset 28($s0) where $s0 iterates from $s2
# Each player entry has a vtable; offset 84 = render func, 308 = render2 func
# Let's find $s2's value - it's set from the parent function
# Actually, let's look at the player entry objects directly
# From 0x09D62B30: it receives $a1 = player object, $a2 = index
# Then uses the object to find vtable entries

# Let's find what functions have addresses that look like overlay code
# by checking common vtable patterns
print("\n\n=== SCANNING FOR VTABLE ENTRIES POINTING TO KNOWN FUNCTIONS ===")
# Known render-related functions
known_funcs = {
    0x09D62384: "SWITCH_DISPATCHER",
    0x09D624D4: "SPRITE_F8F0_x8",
    0x09D61838: "HP_BAR_SUB",
    0x09D61558: "HP_BAR_SUB2",
    0x09D614EC: "BG_SUB",
    0x09D61248: "SPRITE_1000_DIRECT",
    0x09D6228C: "SPRITE_1000_SUB",
    0x09D5F410: "SPRITE_1168_x3",
    0x09D5EAAC: "DEFAULT_RENDER",
    0x09D5EF74: "OVL_EF74",
    0x09D612D4: "OVL_12D4",
}

# Scan overlay data area for function pointers
# These would typically be in data sections after the code
print("Looking for vtable entries in overlay data area...")
for addr in range(0x09D90000, 0x09DA0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    if val in known_funcs:
        print(f"  0x{addr:08X}: 0x{val:08X} = {known_funcs[val]}")

# Also check the jump table area mentioned in the switch dispatcher
# 0x09D9E12C (lui 0x09DA, addiu -7892)
print("\n\n=== SWITCH TABLE AT 0x09D9E12C ===")
for i in range(9):
    addr = 0x09D9E12C + i * 4
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    name = ""
    if val in known_funcs:
        name = f" = {known_funcs[val]}"
    elif 0x09D60000 <= val <= 0x09D70000:
        name = " [OVL code]"
    print(f"  [{i}] 0x{addr:08X}: 0x{val:08X}{name}")

# Also scan the HUD data structure area for vtable pointers
# The HUD structure is likely at a known global pointer
# Let's check what's at 0x09BAxxxx (lui $s0, 0x09BB was used in the code)
print("\n\n=== LOOKING FOR HUD STRUCTURE (lui 0x09BB area) ===")
# From 0x09D6C660: lw $a0, -6544($s0) where $s0 is set from lui 0x09BB
# $s0 = 0x09BB0000, so reads 0x09BB0000 - 6544 = 0x09BAE670
hud_ptr_addr = 0x09BAE670
off = psp_to_offset(hud_ptr_addr)
hud_ptr = read_u32(data, off)
print(f"HUD ptr at 0x{hud_ptr_addr:08X}: 0x{hud_ptr:08X}")

# Player count is at offset 8 of the HUD structure
if 0x08000000 <= hud_ptr <= 0x0A000000:
    count_off = psp_to_offset(hud_ptr + 8)
    if count_off + 4 <= len(data):
        count = read_u32(data, count_off)
        print(f"Player count at 0x{hud_ptr+8:08X}: {count}")

    # Player entries start at offset 12 (first player) and offset 28 (sorted list)
    # From LOOP1: lw $a1, 12($s0) where $s0 = $s2 = hud_struct
    # From LOOP2: lw $a1, 28($s1) where $s1 starts at $s2
    for slot in range(4):
        # LOOP1 uses offset 12 + slot*4
        entry_off = psp_to_offset(hud_ptr + 12 + slot * 4)
        if entry_off + 4 > len(data): break
        entry_ptr = read_u32(data, entry_off)
        print(f"\n  Player {slot} entry ptr (off {12+slot*4}): 0x{entry_ptr:08X}")

        if 0x08000000 <= entry_ptr <= 0x0A000000:
            # Check vtable-like entries at various offsets
            for vt_off in [0, 4, 8, 80, 84, 88, 100, 304, 308, 312]:
                vt_addr = entry_ptr + vt_off
                vt_file_off = psp_to_offset(vt_addr)
                if vt_file_off + 4 > len(data): continue
                val = read_u32(data, vt_file_off)
                name = ""
                if val in known_funcs:
                    name = f" = {known_funcs[val]}"
                elif 0x09C50000 <= val <= 0x09DA0000:
                    name = " [OVL code]"
                elif 0x08800000 <= val <= 0x089A0000:
                    name = " [EBOOT code]"
                if name:
                    print(f"    +{vt_off}: 0x{val:08X}{name}")

        # LOOP2 uses offset 28 + slot*4
        entry_off2 = psp_to_offset(hud_ptr + 28 + slot * 4)
        if entry_off2 + 4 > len(data): break
        entry_ptr2 = read_u32(data, entry_off2)
        if entry_ptr2 != entry_ptr and 0x08000000 <= entry_ptr2 <= 0x0A000000:
            print(f"  Player {slot} LOOP2 entry ptr (off {28+slot*4}): 0x{entry_ptr2:08X}")
            for vt_off in [0, 4, 8, 80, 84, 88, 100, 304, 308, 312]:
                vt_addr = entry_ptr2 + vt_off
                vt_file_off = psp_to_offset(vt_addr)
                if vt_file_off + 4 > len(data): continue
                val = read_u32(data, vt_file_off)
                name = ""
                if val in known_funcs:
                    name = f" = {known_funcs[val]}"
                elif 0x09C50000 <= val <= 0x09DA0000:
                    name = " [OVL code]"
                elif 0x08800000 <= val <= 0x089A0000:
                    name = " [EBOOT code]"
                if name:
                    print(f"    +{vt_off}: 0x{val:08X}{name}")

print("\nDone!")
