#!/usr/bin/env python3
"""
Find the per-item action menu that conditionally adds "Change Pigment".
Search the ENTIRE overlay for:
1. All calls to strcpy/0x0880E654 that are preceded by conditional branches
2. All calls to 0x0880EA5C (the tail call in the submenu builder)
3. Any menu construction with variable option counts
4. The function that handles item selection (triggers when you press confirm on armor)
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

# 1. Find ALL calls to 0x0880EA5C in the overlay (the menu finalize function)
print("=== All calls to 0x0880EA5C in overlay ===")
target_jal_ea5c = (0x03 << 26) | (0x0880EA5C >> 2)
target_j_ea5c = (0x02 << 26) | (0x0880EA5C >> 2)
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal_ea5c or word == target_j_ea5c:
        d = disasm(word, addr)
        print(f"  0x{addr:08X}: {d}")

# 2. Find ALL calls to 0x0880E654 (strcpy) in the overlay
print("\n=== All calls to 0x0880E654 in overlay ===")
target_jal_e654 = (0x03 << 26) | (0x0880E654 >> 2)
calls_e654 = []
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal_e654:
        calls_e654.append(addr)
        print(f"  0x{addr:08X}: jal 0x0880E654")
print(f"  Total: {len(calls_e654)} calls")

# 3. Look at what calls the pigment display parent (0x09CB7CF4)
# We need to find the function that decides to ENTER pigment mode
print("\n=== Callers of 0x09CB7CF4 (pigment display parent) ===")
target_jal = (0x03 << 26) | (0x09CB7CF4 >> 2)
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  0x{addr:08X}: jal 0x09CB7CF4")
        # Dump context
        for a in range(addr - 32, addr + 16, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == addr else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")

# Also search for references as function pointer
func_ptr_bytes = struct.pack('<I', 0x09CB7CF4)
for offset in range(psp_to_state(0x09C57C80), psp_to_state(0x09F00000), 4):
    if offset + 4 > len(data): break
    if data[offset:offset+4] == func_ptr_bytes:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  Function pointer at 0x{psp_addr:08X}")

# 4. Search for the function that handles item selection in the equipment box
# This is likely a state machine / switch based on menu choice
# Look for callers of 0x09CB73A0 (the pigment display function itself)
print("\n=== Callers of 0x09CB73A0 (pigment display function) ===")
target_jal = (0x03 << 26) | (0x09CB73A0 >> 2)
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  0x{addr:08X}: jal 0x09CB73A0")
        for a in range(addr - 32, addr + 16, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == addr else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")

# Also as function pointer
func_ptr_bytes = struct.pack('<I', 0x09CB73A0)
for offset in range(psp_to_state(0x09C57C80), psp_to_state(0x09F00000), 4):
    if offset + 4 > len(data): break
    if data[offset:offset+4] == func_ptr_bytes:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  Function pointer at 0x{psp_addr:08X}")

# 5. Search for function pointers to ALL the key overlay functions we know
# These might be in a handler table
print("\n=== Search for function pointer tables ===")
key_funcs = [0x09CB610C, 0x09CB7CF4, 0x09CB73A0, 0x09CB5440, 0x09CB53FC]
for func in key_funcs:
    func_bytes = struct.pack('<I', func)
    for offset in range(psp_to_state(0x09C57C80), psp_to_state(0x09F00000), 4):
        if offset + 4 > len(data): break
        if data[offset:offset+4] == func_bytes:
            psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
            print(f"  0x{func:08X} found at 0x{psp_addr:08X}")

# 6. Look at what 0x0886AE7C does — it's called from the submenu area
# and has a huge stack (672 bytes). This might be the main equipment box handler.
print("\n=== Function 0x0886AE7C (large EBOOT function) ===")
# Check if it uses function pointers or a switch table
dump_range(0x0886AE7C, 0x0886AF50, "Start of 0x0886AE7C")

# 7. Let's look at what the data structure byte +7 means
# It's set in many places. Let's trace one of the clear paths
# 0x09CB6088: sb $v0, 0x0007($s0) — what's $v0 here?
print("\n=== Context around sb +7 writes ===")
for addr in [0x09CB6060, 0x09CB60A0, 0x09CB60C0, 0x09CB65D0, 0x09CB6730]:
    dump_range(addr - 24, addr + 16, f"Around sb +7 at 0x{addr:08X}")

# 8. The pigment option might use a completely different mechanism.
# In MH games, the equipment box action menu is often built dynamically
# based on the item type and state. Let's search for the string table
# that contains option names.
# The submenu builder loads strings from a pointer table at $s1.
# $s1 = lw 0x0018($v0) where $v0 is from 0x09CB53FC
# Let's check what 0x09CB53FC returns
dump_range(0x09CB53FC, 0x09CB5440, "Function 0x09CB53FC")
