#!/usr/bin/env python3
"""Analyze the square button rendering in the item selector.
Find all callers of 0x0890000C and 0x088FFF0C in the item selector region,
and disassemble both functions to understand what they render."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    return zstd.ZstdDecompressor().decompress(data[0xB0:], max_output_size=256*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

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
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

print("Loading save state...")
data = load_state(STATE)

# Step 1: Disassemble function at 0x0890000C
print("=" * 70)
print("=== Function at 0x0890000C ===")
print("=" * 70)
# Check if this is a function entry — look for prologue
for addr in range(0x0890000C, 0x0890000C - 0x20, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    if "addiu $sp" in d and ",-" in d.replace(" ", ""):
        print(f"  Possible function start at 0x{addr:08X}: {d}")
        break

# Scan backward to find function start
func_start = None
for addr in range(0x0890000C, 0x088FF000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    simm = instr & 0xFFFF
    if simm >= 0x8000: simm -= 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        break
    # Also check for jr $ra which marks end of previous function
    if op == 0 and (instr & 0x3F) == 0x08 and ((instr >> 21) & 0x1F) == 31:
        func_start = addr + 8  # function starts 2 instructions after jr $ra (delay slot + next)
        break

if func_start:
    print(f"\nFunction likely starts at 0x{func_start:08X}")
else:
    func_start = 0x0890000C
    print(f"\nCouldn't find prologue, starting from 0x{func_start:08X}")

print(f"\nDisassembly:")
for addr in range(func_start, func_start + 0x200, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if addr == 0x0890000C: m = "  <<<< KILLED BY CODE #1"
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f"  [0x{target:08X}]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]{m}")
        # print delay slot too
        addr2 = addr + 4
        instr2 = read_u32(data, psp_to_offset(addr2))
        print(f"  0x{addr2:08X}: 0x{instr2:08X}  {disasm(instr2, addr2)}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Step 2: Disassemble first part of 0x088FFF0C
print(f"\n{'='*70}")
print("=== Function at 0x088FFF0C (HP_BAR_RENDER) - first 40 instructions ===")
print(f"{'='*70}")
for addr in range(0x088FFF0C, 0x088FFF0C + 160, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f"  [0x{target:08X}]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        addr2 = addr + 4
        instr2 = read_u32(data, psp_to_offset(addr2))
        print(f"  0x{addr2:08X}: 0x{instr2:08X}  {disasm(instr2, addr2)}")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Step 3: Find ALL callers of 0x0890000C in overlay region
print(f"\n{'='*70}")
print("=== All callers of 0x0890000C (square button func) ===")
print(f"{'='*70}")
target_26 = 0x0890000C >> 2
jal_enc = (3 << 26) | (target_26 & 0x03FFFFFF)
j_enc = (2 << 26) | (target_26 & 0x03FFFFFF)

for region, start, end in [("EBOOT", 0x08800000, 0x08A00000),
                            ("OVERLAY", 0x09C50000, 0x09E00000)]:
    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_enc or instr == j_enc:
            kind = "jal" if instr == jal_enc else "j"
            print(f"\n  {region} 0x{addr:08X}: {kind} 0x0890000C")
            # Show context
            for ctx in range(addr - 20, addr + 12, 4):
                ci = read_u32(data, psp_to_offset(ctx))
                cd = disasm(ci, ctx)
                mark = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{ci:08X}  {cd}{mark}")

# Step 4: Find ALL callers of 0x088FFF0C in the item selector function region (0x09D609A4-0x09D60F30)
print(f"\n{'='*70}")
print("=== Callers of 0x088FFF0C in item selector region (0x09D609A4-0x09D60F30) ===")
print(f"{'='*70}")
target_26b = 0x088FFF0C >> 2
jal_enc_b = (3 << 26) | (target_26b & 0x03FFFFFF)

for addr in range(0x09D609A4, 0x09D60F30, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == jal_enc_b:
        print(f"\n  0x{addr:08X}: jal 0x088FFF0C")
        for ctx in range(addr - 24, addr + 8, 4):
            ci = read_u32(data, psp_to_offset(ctx))
            cd = disasm(ci, ctx)
            mark = " <<<" if ctx == addr else ""
            print(f"    0x{ctx:08X}: 0x{ci:08X}  {cd}{mark}")

# Step 5: Also check the parent function region for calls
print(f"\n{'='*70}")
print("=== Callers of 0x0890000C in parent function region (0x09D6C498-0x09D6CA00) ===")
print(f"{'='*70}")
for addr in range(0x09D6C498, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == jal_enc:
        print(f"\n  0x{addr:08X}: jal 0x0890000C")
        for ctx in range(addr - 24, addr + 8, 4):
            ci = read_u32(data, psp_to_offset(ctx))
            cd = disasm(ci, ctx)
            mark = " <<<" if ctx == addr else ""
            print(f"    0x{ctx:08X}: 0x{ci:08X}  {cd}{mark}")

# Also search wider overlay area
print(f"\n{'='*70}")
print("=== All callers of 0x0890000C in full overlay ===")
print(f"{'='*70}")
count = 0
for addr in range(0x09C50000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_enc or instr == j_enc:
        kind = "jal" if instr == jal_enc else "j"
        print(f"  0x{addr:08X}: {kind} 0x0890000C")
        count += 1
print(f"Total overlay callers: {count}")

print("\nDone!")
