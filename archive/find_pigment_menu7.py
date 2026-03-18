#!/usr/bin/env python3
"""
Focus on the 72-byte entry population code:
1. What writes byte +19 (0x13) = pigment flag?
2. What writes byte +7 = pigment color count?
3. What writes byte +6?
4. The full function containing 0x09CB5198 (sb $v1, 0x0013($s0))
5. The caller of 0x09CB7D88 at 0x09CB8F0C to understand state machine
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

# 1. Find the function containing 0x09CB5198 (sb $v1, 0x0013($s0))
print("=== Finding function containing 0x09CB5198 (pigment flag population) ===")
for addr in range(0x09CB5198, 0x09CB4F00, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        print(f"Function starts at 0x{func_start:08X} (stack = {-simm})")
        dump_range(func_start, func_start + 0x200,
                   f"Entry population function at 0x{func_start:08X}")
        break

# 2. Find the function containing 0x09CB5248 (sb $zero, 0x0013($s1))
print("\n\n=== Finding function containing 0x09CB5248 ===")
for addr in range(0x09CB5248, 0x09CB5198, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start2 = addr
        print(f"Function starts at 0x{func_start2:08X}")
        dump_range(func_start2, func_start2 + 0x100,
                   f"Function at 0x{func_start2:08X}")
        break

# 3. Context around sb +7 writes that set byte+7 to non-zero
# 0x09CB6088: sb $v0, 0x0007($s0) — what sets $v0?
dump_range(0x09CB6040, 0x09CB60A0, "Context of sb $v0, +7 at 0x09CB6088")

# 4. Dump the caller function around 0x09CB8F0C
print("\n\n=== Finding function containing 0x09CB8F0C (caller of pigment handler) ===")
for addr in range(0x09CB8F0C, 0x09CB8C00, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start3 = addr
        print(f"Function starts at 0x{func_start3:08X} (stack = {-simm})")
        dump_range(func_start3, min(func_start3 + 0x200, 0x09CB9200),
                   f"State machine at 0x{func_start3:08X}")
        break

# 5. Check what the 6 options text strings say
# The submenu at 0x09CB610C loads strings via 0x09CB5440(context, index)
# The context comes from 0x09CB53FC which returns a data pointer
# Let's trace what data the string table points to
print("\n\n=== String table analysis ===")
# 0x09CB53FC returns a base data pointer based on language version
# Then 0x09CB5440 indexes into it
# The base data has a field at +0x18 that points to another structure
# which has a field at +0x20 that points to string data

# Let's look at what the overlay state structure looks like
# The submenu builder calls 0x09CB53FC with $a0 = some context
# Let's check what's at the overlay data areas
for test_addr in [0x09D846D4, 0x09D84710, 0x09D8471A]:
    soff = psp_to_state(test_addr)
    if soff + 16 <= len(data):
        hexdata = data[soff:soff+16]
        hexstr = ' '.join(f'{b:02X}' for b in hexdata)
        print(f"  [0x{test_addr:08X}]: {hexstr}")

# 6. What does 0x0880EA5C do? (the menu finalize function)
dump_range(0x0880EA5C, 0x0880EB00, "EBOOT 0x0880EA5C (menu finalize)")

# 7. Let's also look at what happens at 0x09CB797C (the skip-pigment target)
# from the handler at 0x09CB77FC
dump_range(0x09CB7960, 0x09CB7A00, "Handler skip-pigment path at 0x09CB797C")
