#!/usr/bin/env python3
"""Verify the pigment flag check instruction and search for global pigment unlock."""
import struct, zstandard, sys

PPST = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
STATE_OFFSET_BASE = 0x48  # state_offset = PSP_addr - 0x08000000 + 0x48

def psp_to_state(addr):
    return addr - PSP_BASE + STATE_OFFSET_BASE

def read_u32(data, state_off):
    return struct.unpack_from('<I', data, state_off)[0]

def read_u16(data, state_off):
    return struct.unpack_from('<H', data, state_off)[0]

def read_u8(data, state_off):
    return data[state_off]

def disasm_simple(word, addr):
    """Basic MIPS disassembly for common instructions."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    rd = (word >> 11) & 0x1F
    funct = word & 0x3F

    rn = lambda r: f"${['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra'][r]}"

    if op == 0:  # R-type
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"R-type func=0x{funct:02X} {rn(rd)},{rn(rs)},{rn(rt)}"
    elif op == 0x09: return f"addiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x24: return f"lbu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x20: return f"lb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x04: return f"beq {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x05: return f"bne {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x0A: return f"slti {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0B: return f"sltiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0D: return f"ori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x03: return f"jal 0x{(word & 0x03FFFFFF) << 2:08X}"
    elif op == 0x02: return f"j 0x{(word & 0x03FFFFFF) << 2:08X}"
    else: return f"op=0x{op:02X} rt={rn(rt)} rs={rn(rs)} imm=0x{imm:04X}"

# Load save state
with open(PPST, 'rb') as f:
    raw = f.read()
compressed = raw[HEADER_SIZE:]
dctx = zstandard.ZstdDecompressor()
data = dctx.decompress(compressed, max_output_size=64*1024*1024)
print(f"Decompressed save state: {len(data)} bytes")

# 1. Verify instruction at 0x0885C844
print("\n=== Verify instruction at 0x0885C844 ===")
target_addr = 0x0885C844
soff = psp_to_state(target_addr)
word = read_u32(data, soff)
print(f"0x{target_addr:08X}: 0x{word:08X}  {disasm_simple(word, target_addr)}")

# Dump context: function 0x0885C7BC to 0x0885C880
print("\n=== Function 0x0885C7BC context (get_pigment_flag) ===")
for addr in range(0x0885C7BC, 0x0885C8A0, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    marker = " <-- PATCH TARGET" if addr == 0x0885C844 else ""
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm_simple(word, addr)}{marker}")

# 2. Check one of the known working pigment addresses to verify they're in the right spot
print("\n=== Verify known pigment flag addresses ===")
# Yukumo head entry 1 at offset +19: 0x089825E7 (from existing cheat 0x001825E7)
head_base = 0x089825AC
for eid in [1, 12]:
    entry_addr = head_base + eid * 40
    flag_addr = entry_addr + 19
    soff = psp_to_state(flag_addr)
    val = read_u8(data, soff)
    print(f"  HEAD entry {eid}: pigment_flag@0x{flag_addr:08X} = {val}")

# 3. Check callers - do they actually call 0x0885C7BC?
print("\n=== Verify callers of 0x0885C7BC ===")
callers = [0x0883D380, 0x0883EB48, 0x08841FE8, 0x08843118, 0x0884D304,
           0x0884D36C, 0x0884D548, 0x088A54B8, 0x088B3E10]
target_jal = 0x03 << 26 | (0x0885C7BC >> 2)  # jal 0x0885C7BC
for caller in callers:
    soff = psp_to_state(caller)
    word = read_u32(data, soff)
    match = "MATCH" if word == target_jal else "NO MATCH"
    print(f"  0x{caller:08X}: 0x{word:08X}  {disasm_simple(word, caller)}  [{match}]")

# 4. Search for global pigment/color unlock flag
# Look for "Clear All Quests" style flag areas near save data
# The HD version cheat 0x817544C8 suggests quest flags at 0x097544C8 area
# For ULJM05800, quest/unlock flags might be elsewhere
# Let's look at the save data region and search for patterns

# 5. Check what the callers do with the result
print("\n=== Context around caller 0x0883D380 (color table lookup) ===")
for addr in range(0x0883D360, 0x0883D3C0, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm_simple(word, addr)}")

print("\n=== Context around caller 0x0883EB48 (entity pigment write) ===")
for addr in range(0x0883EB28, 0x0883EB88, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm_simple(word, addr)}")

print("\n=== Context around caller 0x088A54B8 (equip pigment write) ===")
for addr in range(0x088A5490, 0x088A5500, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm_simple(word, addr)}")
