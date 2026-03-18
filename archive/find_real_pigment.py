#!/usr/bin/env python3
"""
Find the ACTUAL code that reads the pigment flag byte (+19 / 0x13) from armor data tables.
The function at 0x0885C7BC skips armor types 0-4 entirely.
The per-armor CWCheat byte writes to +19 DO work, so something else reads them.
Search both EBOOT and overlay regions.
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
        if funct == 0x00 and word != 0: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x00 and word == 0: return "nop"
        if funct == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x19: return f"multu {rn(rs)}, {rn(rt)}"
        if funct == 0x18: return f"mult {rn(rs)}, {rn(rt)}"
        if funct == 0x10: return f"mfhi {rn(rd)}"
        if funct == 0x12: return f"mflo {rn(rd)}"
        return f"special func=0x{funct:02X} {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
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
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x20: return f"lb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x21: return f"lh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x24: return f"lbu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    else: return f"[op=0x{op:02X}] {rn(rt)}, {simm}({rn(rs)})"

with open(PPST, 'rb') as f:
    raw = f.read()
data = zstandard.ZstdDecompressor().decompress(raw[HEADER_SIZE:], max_output_size=64*1024*1024)
print(f"Decompressed: {len(data)} bytes\n")

# Search for ALL lbu/lb instructions with offset 0x13 in EBOOT region
print("=== All lbu/lb with offset 0x0013 in EBOOT (0x08804000 - 0x08920000) ===")
results = []
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    imm = word & 0xFFFF
    if imm == 0x0013 and op in (0x20, 0x24):  # lb or lbu
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        instr = "lbu" if op == 0x24 else "lb"
        results.append((addr, word, f"{instr} {rn(rt)}, 0x0013({rn(rs)})"))

print(f"Found {len(results)} instructions")
for addr, word, asm in results:
    # Check nearby context for armor table references
    context_info = ""
    for off in range(-40, 44, 4):
        nearby = addr + off
        s = psp_to_state(nearby)
        if s + 4 > len(data): continue
        w = read_u32(data, s)
        nop = (w >> 26) & 0x3F
        nimm = w & 0xFFFF
        # Check for lui with armor table region
        if nop == 0x0F and nimm in (0x0897, 0x0898):
            context_info += f" [near lui 0x{nimm:04X} at 0x{nearby:08X}]"
        # Check for references to entry size 40 (0x28)
        if nop == 0x09 and (nimm == 0x0028 or nimm == 40):
            context_info += f" [near addiu +40 at 0x{nearby:08X}]"
        # Check for multiply by 40 pattern (sll by 3 = *8, then add *32)
        if nop == 0 and ((w >> 6) & 0x1F) == 3 and (w & 0x3F) == 0:
            context_info += f" [near sll *8 at 0x{nearby:08X}]"
    print(f"  0x{addr:08X}: 0x{word:08X}  {asm}{context_info}")

# Now search the dynamic overlay region
print("\n=== All lbu/lb with offset 0x0013 in overlay (0x09C00000 - 0x09E00000) ===")
overlay_results = []
for addr in range(0x09C00000, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    imm = word & 0xFFFF
    if imm == 0x0013 and op in (0x20, 0x24):
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        instr = "lbu" if op == 0x24 else "lb"
        overlay_results.append((addr, word, f"{instr} {rn(rt)}, 0x0013({rn(rs)})"))

print(f"Found {len(overlay_results)} instructions")
for addr, word, asm in overlay_results:
    context_info = ""
    for off in range(-40, 44, 4):
        nearby = addr + off
        s = psp_to_state(nearby)
        if s + 4 > len(data): continue
        w = read_u32(data, s)
        nop = (w >> 26) & 0x3F
        nimm = w & 0xFFFF
        if nop == 0x0F and nimm in (0x0897, 0x0898):
            context_info += f" [near lui 0x{nimm:04X} at 0x{nearby:08X}]"
    print(f"  0x{addr:08X}: 0x{word:08X}  {asm}{context_info}")

# Also search for code that computes entry_addr + 19 differently
# Maybe using addiu offset, 19 after a table lookup
print("\n=== Search for addiu with immediate 19 (0x13) near armor table refs ===")
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    imm = word & 0xFFFF
    if op == 0x09 and imm == 0x0013:  # addiu with +19
        # Check nearby for armor table references
        has_armor_ref = False
        for off in range(-60, 64, 4):
            nearby = addr + off
            s = psp_to_state(nearby)
            if s + 4 > len(data): continue
            w = read_u32(data, s)
            nop = (w >> 26) & 0x3F
            nimm = w & 0xFFFF
            if nop == 0x0F and nimm in (0x0897, 0x0898):
                has_armor_ref = True
                break
        if has_armor_ref:
            rs = (word >> 21) & 0x1F
            rt = (word >> 16) & 0x1F
            print(f"  0x{addr:08X}: addiu {rn(rt)}, {rn(rs)}, 19 [near armor table ref]")

# Deep dive: look at the secondary pigment function 0x0885CF58
print("\n=== Secondary pigment function at 0x0885CF58 ===")
for addr in range(0x0885CF58, 0x0885D040, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm(word, addr)}")

# Check function at 0x0885BE6C (equipment lookup used by get_pigment_flag)
# See if there are other callers that might be the real pigment path for armor
print("\n=== Callers of equipment lookup 0x0885BE6C ===")
target_jal = (0x03 << 26) | (0x0885BE6C >> 2)
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        # Check what instruction follows (likely reads from result)
        next_soff = psp_to_state(addr + 8)  # skip delay slot
        next_word = read_u32(data, next_soff)
        next_asm = disasm(next_word, addr + 8)
        print(f"  0x{addr:08X}: jal 0x0885BE6C  →  next: 0x{addr+8:08X}: {next_asm}")
