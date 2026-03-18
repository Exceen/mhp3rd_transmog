#!/usr/bin/env python3
"""
Find the equipment box submenu code that decides whether to show "Pigment" option.
Focus on the parent function of the pigment display caller at 0x09CB7D48.
"""
import struct, zstandard

PPST = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
STATE_OFFSET_BASE = 0x48

def psp_to_state(addr):
    return addr - PSP_BASE + STATE_OFFSET_BASE

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

rnames = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
          's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']
def rn(r): return f"${rnames[r]}"

def disasm(word, addr):
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    sa = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target = (word & 0x03FFFFFF) << 2
    if op == 0:
        if word == 0: return "nop"
        if funct == 0x00: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"[special 0x{funct:02X}] {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
    elif op == 0x02: return f"j 0x{target:08X}"
    elif op == 0x03: return f"jal 0x{target:08X}"
    elif op == 0x04: return f"beq {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x05: return f"bne {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x06: return f"blez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x07: return f"bgtz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x09: return f"addiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0A: return f"slti {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0B: return f"sltiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0C: return f"andi {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0D: return f"ori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x20: return f"lb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x21: return f"lh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x24: return f"lbu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    else: return f"[op=0x{op:02X}] {rn(rt)}, 0x{imm:04X}({rn(rs)})"

with open(PPST, 'rb') as f:
    raw = f.read()
data = zstandard.ZstdDecompressor().decompress(raw[HEADER_SIZE:], max_output_size=64*1024*1024)

# Find the parent function of 0x09CB7D48 (caller of pigment display)
print("=== Parent function of pigment display caller ===")
for addr in range(0x09CB7D48, 0x09CB7A00, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        print(f"Function starts at 0x{func_start:08X}")
        # Dump the function
        for a in range(func_start, min(func_start + 0x200, 0x09CB7E00), 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            d = disasm(w, a)
            markers = ""
            if a == 0x09CB7D48: markers = "  <-- jal pigment_display"
            if 'jal 0x088' in d: markers = f"  <-- EBOOT call"
            print(f"  0x{a:08X}: 0x{w:08X}  {d}{markers}")
            if 'jr $ra' in d and a > func_start + 4:
                a2 = a + 4
                s2 = psp_to_state(a2)
                w2 = read_u32(data, s2)
                print(f"  0x{a2:08X}: 0x{w2:08X}  {disasm(w2, a2)}")
                break
        break

# Now let's look at where the equipment box SUBMENU is built.
# Search for the EBOOT function 0x088E7048 which is called right before
# the pigment display function
print("\n=== EBOOT function 0x088E7048 (called before pigment display) ===")
for addr in range(0x088E7048, 0x088E7200, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    d = disasm(word, addr)
    print(f"  0x{addr:08X}: 0x{word:08X}  {d}")
    if 'jr $ra' in d and addr > 0x088E704C:
        addr2 = addr + 4
        soff2 = psp_to_state(addr2)
        word2 = read_u32(data, soff2)
        print(f"  0x{addr2:08X}: 0x{word2:08X}  {disasm(word2, addr2)}")
        break

# Search for functions in the overlay that handle equipment box submenu
# The submenu construction likely happens in a different function
# Let's look at functions that call menu-building EBOOT functions
# Known: 0x0880E654 is called 5 times near 0x09CB6220 - this looks like
# adding 5 menu options!
print("\n=== Overlay code around 0x09CB6200 (5x calls to 0x0880E654) ===")
for addr in range(0x09CB6180, 0x09CB6380, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    d = disasm(word, addr)
    markers = ""
    if 'jal 0x0880E654' in d: markers = "  <-- add_menu_option?"
    print(f"  0x{addr:08X}: 0x{word:08X}  {d}{markers}")

# Let's also check for the function 0x0886AE7C which is called once
print("\n=== EBOOT function 0x0886AE7C ===")
for addr in range(0x0886AE7C, 0x0886AF80, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    d = disasm(word, addr)
    print(f"  0x{addr:08X}: 0x{word:08X}  {d}")
    if 'jr $ra' in d and addr > 0x0886AE80:
        addr2 = addr + 4
        soff2 = psp_to_state(addr2)
        word2 = read_u32(data, soff2)
        print(f"  0x{addr2:08X}: 0x{word2:08X}  {disasm(word2, addr2)}")
        break
