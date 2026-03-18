#!/usr/bin/env python3
"""Find the item selector state flag — look for state machine values
(small integers at aligned addresses) that differ between open/closed states."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    return data[off]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data_off = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")
data_on = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

# Search ALL game RAM for 4-byte aligned values that are:
# - 0 when item selector is closed
# - small nonzero (1-10) when open
# These are likely state flags or state machine values
print("=== 4-byte aligned, OFF=0 → ON=small(1-10), full RAM scan ===")
candidates = []
for addr in range(0x09800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_off) or off + 4 > len(data_on):
        break
    v_off = read_u32(data_off, off)
    v_on = read_u32(data_on, off)
    if v_off == 0 and 1 <= v_on <= 10:
        candidates.append((addr, v_on))

print(f"Found {len(candidates)} candidates")
for addr, v_on in candidates:
    region = ""
    if 0x09BB0000 <= addr < 0x09BC0000: region = " [UI/ITEM area]"
    elif 0x09BE0000 <= addr < 0x09BF0000: region = " [game state]"
    elif 0x09BF0000 <= addr < 0x09C00000: region = " [HUD ptrs]"
    elif 0x09C50000 <= addr < 0x09E00000: region = " [overlay]"
    elif 0x09D80000 <= addr < 0x09E00000: region = " [overlay data]"
    print(f"  0x{addr:08X}: 0 → {v_on}{region}")

# Also search for aligned byte flags (check as single bytes at aligned-4 addresses)
# where the 32-bit word goes from all-zero to having just the low byte set
print(f"\n=== 32-bit words: 0x00000000 → 0x000000XX (byte flag), full RAM ===")
for addr in range(0x09800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_off) or off + 4 > len(data_on):
        break
    v_off = read_u32(data_off, off)
    v_on = read_u32(data_on, off)
    if v_off == 0 and v_on != 0 and (v_on & 0xFFFFFF00) == 0:
        if v_on <= 10:  # already covered above
            continue
        print(f"  0x{addr:08X}: 0 → 0x{v_on:02X} ({v_on})")

# Now look at the existing item selector area more carefully
# Check what the $fp base is and look for state fields in the object
# $fp is used in the renderer; let's check what $fp points to
# From overlay render code: lw $a0, 0x9F18($fp) — so $fp+0x9F18 = render context
# Let's see what $fp itself is. It's set up in the function prologue.
# The parent function 0x09D6C498 likely sets $fp = $sp or similar
# Let's check $fp-relative addresses for state flags

# Check for code that loads a byte/word near the item selector check
# The item selector rendering area is around 0x09D63xxx
# Let's search for conditional branches that could be "if item_selector_active"
print(f"\n=== Branch-on-zero/nonzero patterns near item selector render (0x09D63800-0x09D64000) ===")
REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm_brief(instr, addr):
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00 and rd == 0: return "nop"
        return f"special"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"op=0x{op:02X}"

# Look for patterns: load → beq/bne $zero (checking a flag)
for addr in range(0x09D63800, 0x09D64000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_on): break
    instr = read_u32(data_on, off)
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    if op in [0x04, 0x05] and (rs == 0 or rt == 0):  # beq/bne with $zero
        # Show the load instruction before this branch
        prev_off = psp_to_offset(addr - 4)
        prev_instr = read_u32(data_on, prev_off)
        prev2_off = psp_to_offset(addr - 8)
        prev2_instr = read_u32(data_on, prev2_off)
        d_prev2 = disasm_brief(prev2_instr, addr - 8)
        d_prev = disasm_brief(prev_instr, addr - 4)
        d = disasm_brief(instr, addr)
        print(f"  0x{addr-8:08X}: {d_prev2}")
        print(f"  0x{addr-4:08X}: {d_prev}")
        print(f"  0x{addr:08X}: {d}")
        print()

print("\nDone!")
