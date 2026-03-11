#!/usr/bin/env python3
"""Extended trace of item selector flag."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
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
    if off + 4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

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
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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

# 1. Full dump of 0x088A3984 (need to see 0x088A39B0 path for $a1=1)
print("=== FUNCTION 0x088A3984 (full, including $a1=1 path at 0x088A39B0) ===")
for addr in range(0x088A3984, 0x088A3984 + 300, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: {d}")
    # Stop after second jr $ra
    if "jr $ra" in d and addr > 0x088A39D0:
        break

# 2. Check the object at 0x09541310 + 98
obj_addr = 0x09541310
flag_addr = obj_addr + 98  # 0x09541372
flag_off = psp_to_offset(flag_addr)
flag_val = read_u8(data, flag_off)
print(f"\n=== OBJECT 0x09541310 ===")
print(f"  byte at +98 (0x{flag_addr:08X}) = {flag_val}")
# Dump bytes 96-104 for context
for b in range(90, 110):
    off = psp_to_offset(obj_addr + b)
    val = read_u8(data, off)
    print(f"  byte at +{b} (0x{obj_addr+b:08X}) = {val}")

# 3. Check if pointer chain is stable across different save states
print("\n\n=== CHECKING POINTER CHAIN ACROSS SAVE STATES ===")
states = [
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst",
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst",
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst",
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_1.ppst",
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst",
]

for path in states:
    try:
        d = decompress_ppst(path)
        # Check *(0x09BB7A80)
        p1 = read_u32(d, psp_to_offset(0x09BB7A80))
        # Check *(p1 + 8) if p1 is valid
        if p1 and 0x08000000 <= p1 <= 0x0A000000:
            p2 = read_u32(d, psp_to_offset(p1 + 8))
            flag = None
            if p2 and 0x08000000 <= p2 <= 0x0A000000:
                flag = read_u8(d, psp_to_offset(p2 + 98))
            print(f"  {path.split('/')[-1]}: *(0x09BB7A80)=0x{p1:08X}, *(+8)=0x{p2:08X if p2 else 0:08X}, byte@+98={flag}")
        else:
            print(f"  {path.split('/')[-1]}: *(0x09BB7A80)=0x{p1:08X if p1 else 0:08X} (invalid)")
    except Exception as e:
        print(f"  {path.split('/')[-1]}: ERROR: {e}")

# 4. Also try the simpler approach: look for the flag at a static address
# The function 0x09D64F20 writes: sb $v0, 1814($fp)
# $fp is the UI context. Let's find what $fp points to in the save state.
# The render function 0x09D60D88 is called with $a0 = UI context
# Let's look for the caller of 0x09D60D88 to find where $a0 comes from
print("\n\n=== LOOKING FOR UI CONTEXT POINTER ===")
# Check overlay data area for the UI context
# Typically game_task overlay stores contexts in its data section
# The overlay data is around 0x09D8xxxx-0x09DAxxxx

# Search for pointers in known areas that when +1814 have byte 0 or 1
print("Searching 0x09BB7A80 area (24 entries):")
for i in range(24):
    addr = 0x09BB7A80 + i * 4
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    if val and 0x08000000 <= val <= 0x0A000000:
        try:
            flag = read_u8(data, psp_to_offset(val + 1814))
            print(f"  [{i}] 0x{addr:08X} -> 0x{val:08X}, byte@+1814 = {flag}")
        except:
            pass

# 5. Check the $a1=0 case too: the function checks byte at $a0+98
# For $a1=0: returns 1 if byte@+98 is 4, 5, or 6
# For $a1=1: need to see the code at 0x088A39B0
print(f"\n\nObject at 0x09541310, bytes 96-100:")
for b in [96, 97, 98, 99, 100]:
    off = psp_to_offset(obj_addr + b)
    val = read_u8(data, off)
    print(f"  +{b} = {val} (0x{val:02X})")

print("\nDone!")
