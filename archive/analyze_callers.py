#!/usr/bin/env python3
"""Analyze callers of 0x088A3984 (selector state check) to find:
1. What each caller does with $v0 (the result)
2. Which callers might run per-frame
3. Whether any caller stores the result to a static address
"""

import struct
import zstandard as zstd

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
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

def disasm_simple(word, addr):
    """Basic MIPS disassembly for common instructions."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    shamt = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target = (word & 0x03FFFFFF) << 2 | (addr & 0xF0000000)

    rn = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
          '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
          '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
          '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

    if word == 0:
        return "nop"

    if op == 0:  # R-type
        if funct == 0x08: return f"jr {rn[rs]}"
        if funct == 0x09: return f"jalr {rn[rd]}, {rn[rs]}"
        if funct == 0x21: return f"addu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x23: return f"subu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x25: return f"or {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x24: return f"and {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x2A: return f"slt {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x2B: return f"sltu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x00: return f"sll {rn[rd]}, {rn[rt]}, {shamt}"
        if funct == 0x02: return f"srl {rn[rd]}, {rn[rt]}, {shamt}"
        return f"R-type op=0 funct=0x{funct:02X} rs={rn[rs]} rt={rn[rt]} rd={rn[rd]}"

    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {rn[rs]}, {rn[rt]}, 0x{addr+4+simm*4:08X}"
    if op == 0x05: return f"bne {rn[rs]}, {rn[rt]}, 0x{addr+4+simm*4:08X}"
    if op == 0x06: return f"blez {rn[rs]}, 0x{addr+4+simm*4:08X}"
    if op == 0x07: return f"bgtz {rn[rs]}, 0x{addr+4+simm*4:08X}"
    if op == 0x01:
        if rt == 0: return f"bltz {rn[rs]}, 0x{addr+4+simm*4:08X}"
        if rt == 1: return f"bgez {rn[rs]}, 0x{addr+4+simm*4:08X}"
        return f"REGIMM rt={rt}"
    if op == 0x08: return f"addi {rn[rt]}, {rn[rs]}, {simm}"
    if op == 0x09: return f"addiu {rn[rt]}, {rn[rs]}, {simm}"
    if op == 0x0A: return f"slti {rn[rt]}, {rn[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {rn[rt]}, {rn[rs]}, {simm}"
    if op == 0x0C: return f"andi {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {rn[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x21: return f"lh {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x23: return f"lw {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x24: return f"lbu {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x25: return f"lhu {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x28: return f"sb {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x29: return f"sh {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x2B: return f"sw {rn[rt]}, {simm}({rn[rs]})"

    return f"op=0x{op:02X} rs={rn[rs]} rt={rn[rt]} imm=0x{imm:04X}"

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_1.ppst")

# Callers of 0x088A3984
callers = [0x08842CB0, 0x088A47F8, 0x088A5CCC, 0x088AD7B8, 0x08910CA0, 0x08959F5C]

for caller_addr in callers:
    print(f"\n{'='*60}")
    print(f"=== CALLER AT 0x{caller_addr:08X} ===")
    print(f"{'='*60}")

    # Dump 20 instructions before and 20 after the call
    start = caller_addr - 20*4
    end = caller_addr + 20*4

    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        word = read_u32(data, off)
        dis = disasm_simple(word, addr)
        marker = " <<<< JAL 0x088A3984" if addr == caller_addr else ""
        print(f"  0x{addr:08X}: {word:08X}  {dis}{marker}")

# Also check: does 0x088A3984 itself store result anywhere static?
print(f"\n{'='*60}")
print(f"=== FUNCTION 0x088A3984 DISASSEMBLY ===")
print(f"{'='*60}")
for addr in range(0x088A3984, 0x088A3A40, 4):
    off = psp_to_offset(addr)
    word = read_u32(data, off)
    dis = disasm_simple(word, addr)
    print(f"  0x{addr:08X}: {word:08X}  {dis}")

# Check what function contains each caller by scanning backwards for
# the function prologue (addiu $sp, $sp, -N)
print(f"\n{'='*60}")
print(f"=== FUNCTION BOUNDARIES ===")
print(f"{'='*60}")
for caller_addr in callers:
    # Scan backwards for stack frame setup
    for addr in range(caller_addr, caller_addr - 0x200, -4):
        off = psp_to_offset(addr)
        word = read_u32(data, off)
        op = (word >> 26) & 0x3F
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        simm = imm if imm < 0x8000 else imm - 0x10000
        # addiu $sp, $sp, -N
        if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
            print(f"  Caller 0x{caller_addr:08X} is in function starting at ~0x{addr:08X} (frame size {-simm})")
            break
    else:
        print(f"  Caller 0x{caller_addr:08X}: could not find function start")

print("\nDone!")
