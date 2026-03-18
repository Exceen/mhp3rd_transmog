#!/usr/bin/env python3
"""Dump the equipment lookup function at 0x0885C3DC used by the real pigment readers."""
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
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x18: return f"mult {rn(rs)}, {rn(rt)}"
        if funct == 0x19: return f"multu {rn(rs)}, {rn(rt)}"
        if funct == 0x10: return f"mfhi {rn(rd)}"
        if funct == 0x12: return f"mflo {rn(rd)}"
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

print("=== Equipment lookup 0x0885C3DC ===")
for addr in range(0x0885C3DC, 0x0885C500, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    d = disasm(word, addr)
    print(f"  0x{addr:08X}: 0x{word:08X}  {d}")
    if 'jr $ra' in d and addr > 0x0885C3E0:
        # Print one more (delay slot) and stop
        addr2 = addr + 4
        soff2 = psp_to_state(addr2)
        word2 = read_u32(data, soff2)
        print(f"  0x{addr2:08X}: 0x{word2:08X}  {disasm(word2, addr2)}")
        break

# Also check the callers of 0x0885C3DC
print("\n=== All callers of 0x0885C3DC in EBOOT ===")
target_jal = (0x03 << 26) | (0x0885C3DC >> 2)
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        # Get the instruction after delay slot (result usage)
        next_soff = psp_to_state(addr + 8)
        next_word = read_u32(data, next_soff)
        print(f"  0x{addr:08X}: jal 0x0885C3DC  →  0x{addr+8:08X}: {disasm(next_word, addr+8)}")

# Now check what the overlay's 72-byte structure is.
# The base pointer is loaded from 0x09E78E38
print("\n=== Overlay equipment box data pointer ===")
ptr_addr = 0x09E78E38
soff = psp_to_state(ptr_addr)
ptr_val = read_u32(data, soff)
print(f"  [0x{ptr_addr:08X}] = 0x{ptr_val:08X}")

if ptr_val != 0 and ptr_val > 0x08000000 and ptr_val < 0x0A000000:
    # Dump the structure for the first few entries
    base = ptr_val + 40  # addiu $a2, $a2, 40
    print(f"  Equipment box data base (after +40): 0x{base:08X}")
    for i in range(5):
        entry = base + i * 72
        soff = psp_to_state(entry)
        pigment = data[soff + 19] if soff + 19 < len(data) else -1
        # Also read first few bytes for context
        model_m = struct.unpack_from('<h', data, soff + 0)[0] if soff + 4 <= len(data) else -1
        model_f = struct.unpack_from('<h', data, soff + 2)[0] if soff + 4 <= len(data) else -1
        print(f"  Entry {i}: addr=0x{entry:08X}, model_m={model_m}, model_f={model_f}, pigment_flag(+19)={pigment}")
        # Hex dump first 24 bytes
        hexdata = data[soff:soff+24]
        hexstr = ' '.join(f'{b:02X}' for b in hexdata)
        print(f"    Hex[0:24]: {hexstr}")
