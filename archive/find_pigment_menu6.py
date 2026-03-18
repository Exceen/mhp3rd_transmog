#!/usr/bin/env python3
"""
Investigate the menu option builder 0x09CAC4F0 and 0x09CAA794
which determine what options appear in the equipment box action menu.
Also check the function pointer table at 0x09DC65FC and the handler functions.
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

# 1. Dump the function pointer table at 0x09DC65FC and surroundings
print("=== Function pointer table at 0x09DC65FC ===")
for i in range(-4, 12):
    addr = 0x09DC65FC + i * 4
    soff = psp_to_state(addr)
    val = read_u32(data, soff)
    marker = ""
    if 0x09CB0000 <= val < 0x09D00000:
        marker = f"  <-- overlay func"
    print(f"  [{i:2d}] 0x{addr:08X}: 0x{val:08X}{marker}")

# 2. Dump function 0x09CAC4F0 (called from submenu builder with a1=0)
print("\n")
dump_range(0x09CAC4F0, 0x09CAC600, "Function 0x09CAC4F0 (menu option builder)")

# 3. Dump function 0x09CAA794 (called from alternate path)
dump_range(0x09CAA794, 0x09CAA900, "Function 0x09CAA794 (alternate menu builder)")

# 4. Dump function 0x09CB5298 (called from 0x09CB7D88 to get state)
dump_range(0x09CB5298, 0x09CB53FC, "Function 0x09CB5298 (state getter)")

# 5. Dump the handler functions from the table
for func_addr in [0x09CB7CB8, 0x09CB7CA4, 0x09CB77EC, 0x09CB7C90, 0x09CB7C7C]:
    dump_range(func_addr, func_addr + 0x40, f"Handler at 0x{func_addr:08X}")

# 6. Check if 0x09CB7390 (from 0x09DCC3A4) is related to pigment
dump_range(0x09CB7390, 0x09CB73B0, "Function 0x09CB7390 (from pointer table)")

# 7. Find callers of 0x09CB7D88 in overlay
print("\n\n=== Callers of 0x09CB7D88 ===")
target_jal = (0x03 << 26) | (0x09CB7D88 >> 2)
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  0x{addr:08X}: jal 0x09CB7D88")

# Also as function pointer
ptr_bytes = struct.pack('<I', 0x09CB7D88)
for offset in range(psp_to_state(0x09C57C80), min(psp_to_state(0x09F00000), len(data) - 4), 4):
    if data[offset:offset+4] == ptr_bytes:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  Function pointer at 0x{psp_addr:08X}")
        for i in range(-3, 4):
            off2 = offset + i * 4
            val = read_u32(data, off2)
            psp2 = psp_addr + i * 4
            marker = " <-- THIS" if i == 0 else ""
            print(f"    0x{psp2:08X}: 0x{val:08X}{marker}")
