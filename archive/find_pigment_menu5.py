#!/usr/bin/env python3
"""
Trace back from the pigment display to find what menu option triggers it.
Also look at the 6 consecutive strcpy calls at 0x09CAC878 and surroundings.
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
        if funct == 0x03: return f"sra {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x04: return f"sllv {rn(rd)}, {rn(rt)}, {rn(rs)}"
        if funct == 0x06: return f"srlv {rn(rd)}, {rn(rt)}, {rn(rs)}"
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x0A: return f"movz {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x0B: return f"movn {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x18: return f"mult {rn(rs)}, {rn(rt)}"
        if funct == 0x19: return f"multu {rn(rs)}, {rn(rt)}"
        if funct == 0x10: return f"mfhi {rn(rd)}"
        if funct == 0x12: return f"mflo {rn(rd)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x26: return f"xor {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x27: return f"nor {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"[special 0x{funct:02X}] {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
    elif op == 0x01:
        if rt == 0: return f"bltz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        if rt == 1: return f"bgez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        return f"regimm rt={rt}"
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
    elif op == 0x0E: return f"xori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
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

def dump_range(start, end, label=""):
    if label:
        print(f"\n{'='*70}")
        print(f"=== {label}")
        print(f"{'='*70}")
    for addr in range(start, end, 4):
        soff = psp_to_state(addr)
        if soff + 4 > len(data): break
        word = read_u32(data, soff)
        print(f"  0x{addr:08X}: 0x{word:08X}  {disasm(word, addr)}")

# 1. Find the function containing 0x09CB7DD4 (caller of pigment parent)
print("=== Finding function containing 0x09CB7DD4 ===")
for addr in range(0x09CB7DD4, 0x09CB7A00, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        print(f"Function starts at 0x{func_start:08X} (stack = {-simm})")
        dump_range(func_start, func_start + 0x100, f"Function at 0x{func_start:08X}")
        break

# 2. Find callers of 0x09CB7DD4 (if it's a function) or the function containing it
# Search for jal to 0x09CB7DD4
print("\n\n=== Callers of 0x09CB7DD4 ===")
target_jal = (0x03 << 26) | (0x09CB7DD4 >> 2)
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  0x{addr:08X}: jal 0x09CB7DD4")
        dump_range(addr - 40, addr + 20, f"Caller at 0x{addr:08X}")

# Also search for function pointer
ptr_bytes = struct.pack('<I', 0x09CB7DD4)
for offset in range(psp_to_state(0x09C57C80), min(psp_to_state(0x09F00000), len(data) - 4), 4):
    if data[offset:offset+4] == ptr_bytes:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  Function pointer at 0x{psp_addr:08X}")
        # Show nearby pointers for context
        for i in range(-5, 6):
            off2 = offset + i * 4
            val = read_u32(data, off2)
            psp2 = psp_addr + i * 4
            marker = " <-- THIS" if i == 0 else ""
            print(f"    0x{psp2:08X}: 0x{val:08X}{marker}")

# 3. Look at 0x09CAC800 area (6 consecutive strcpy calls)
dump_range(0x09CAC800, 0x09CAC900, "Area around 0x09CAC878 (6 strcpy calls)")

# 4. Dump the area around 0x09CACB00-0x09CACD80 (4 calls to menu finalize)
# This might be the per-item action menu
print("\n\n=== Finding function around 0x09CACB00 ===")
for addr in range(0x09CACB00, 0x09CAC700, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        print(f"Function starts at 0x{func_start:08X} (stack = {-simm})")
        dump_range(func_start, min(func_start + 0x400, 0x09CACE00),
                   f"Function at 0x{func_start:08X}")
        break

# 5. The key question: how does the game decide which overlay function to call?
# The pigment display parent 0x09CB7CF4 might be in a function pointer table.
# Let's search for ALL overlay function pointers in the 0x09CB7xxx range
print("\n\n=== Search for function pointers in 0x09CB7xxx data area ===")
for offset in range(psp_to_state(0x09D80000), min(psp_to_state(0x09F00000), len(data) - 4), 4):
    val = read_u32(data, offset)
    if 0x09CB7000 <= val < 0x09CB8000:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  0x{psp_addr:08X}: 0x{val:08X}")

# 6. Also check for a dispatch/handler table using jump registers
# The menu selection handler would load a function pointer from a table
# and call it via jalr
print("\n\n=== jalr calls in overlay near equipment box ===")
for addr in range(0x09CB5000, 0x09CB8000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    funct = word & 0x3F
    rs = (word >> 21) & 0x1F
    if op == 0 and funct == 0x09:  # jalr
        d = disasm(word, addr)
        print(f"  0x{addr:08X}: {d}")
        # Show context
        for a in range(addr - 12, addr + 8, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == addr else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")
