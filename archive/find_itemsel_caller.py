#!/usr/bin/env python3
"""Find the item selector render function and its caller chain.
The item selector position patches are at 0x09D60DBC-0x09D60EF4.
Goal: find who calls this function and what condition gates it."""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        return zstd.ZstdDecompressor().decompress(f.read(), max_output_size=64*1024*1024)

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
    target = (instr & 0x03FFFFFF) << 2
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X}"
    if op == 0x01:
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        return f"regimm rt=0x{rt:02X}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

# Use the save state with item selector OPEN (index 5)
data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Step 1: Find function start by scanning backward from 0x09D60DBC
# Look for addiu $sp, $sp, -XX (function prologue)
print("=== Scanning backward from 0x09D60DBC for function prologue ===")
for addr in range(0x09D60DBC, 0x09D60800, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    rt = (instr >> 16) & 0x1F
    rs = (instr >> 21) & 0x1F
    simm = (instr & 0xFFFF)
    if simm >= 0x8000: simm -= 0x10000
    # addiu $sp, $sp, -XX
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        print(f"  Found prologue at 0x{addr:08X}: {disasm(instr, addr)}")
        func_start = addr
        break
else:
    print("  No prologue found!")
    func_start = None

if func_start:
    # Step 2: Dump the function from start to first jr $ra
    print(f"\n=== Item selector render function at 0x{func_start:08X} ===")
    for addr in range(func_start, func_start + 0x400, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""
        if addr == 0x09D60DBC: marker = "  <-- first item sel X patch"
        if addr == 0x09D60EF4: marker = "  <-- last item sel X patch"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")
        # Stop after jr $ra + delay slot
        if "jr $ra" in d:
            # Print delay slot
            addr2 = addr + 4
            off2 = psp_to_offset(addr2)
            instr2 = read_u32(data, off2)
            print(f"  0x{addr2:08X}: 0x{instr2:08X}  {disasm(instr2, addr2)}")
            func_end = addr2 + 4
            break

    # Step 3: Find all jal/j calls TO this function in overlay and eboot
    print(f"\n=== Callers of 0x{func_start:08X} ===")
    target_26 = func_start >> 2
    jal_encoding = (3 << 26) | (target_26 & 0x03FFFFFF)
    j_encoding = (2 << 26) | (target_26 & 0x03FFFFFF)

    for region_name, start, end in [("EBOOT", 0x08800000, 0x08A00000),
                                      ("OVERLAY", 0x09C50000, 0x09E00000)]:
        for addr in range(start, end, 4):
            off = psp_to_offset(addr)
            if off + 4 > len(data): break
            instr = read_u32(data, off)
            if instr == jal_encoding or instr == j_encoding:
                kind = "jal" if instr == jal_encoding else "j"
                # Show context: 10 instructions before
                print(f"\n  {region_name} 0x{addr:08X}: {kind} 0x{func_start:08X}")
                print(f"  Context (10 instructions before):")
                for ctx_addr in range(addr - 40, addr + 8, 4):
                    ctx_off = psp_to_offset(ctx_addr)
                    ctx_instr = read_u32(data, ctx_off)
                    marker = " <<<" if ctx_addr == addr else ""
                    print(f"    0x{ctx_addr:08X}: 0x{ctx_instr:08X}  {disasm(ctx_instr, ctx_addr)}{marker}")

print("\nDone!")
