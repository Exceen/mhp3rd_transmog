#!/usr/bin/env python3
"""Disassemble eboot functions around player list Y=50 references."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
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

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    sa = (instr >> 6) & 0x1F
    func = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    if instr == 0:
        return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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
    if op == 0x04:
        target = addr + 4 + (simm << 2)
        return f"beq {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x05:
        target = addr + 4 + (simm << 2)
        return f"bne {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x06:
        target = addr + 4 + (simm << 2)
        return f"blez {REGS[rs]}, 0x{target:08X}"
    if op == 0x07:
        target = addr + 4 + (simm << 2)
        return f"bgtz {REGS[rs]}, 0x{target:08X}"
    if op == 0x01:
        if rt == 0x01:
            target = addr + 4 + (simm << 2)
            return f"bgez {REGS[rs]}, 0x{target:08X}"
        if rt == 0x00:
            target = addr + 4 + (simm << 2)
            return f"bltz {REGS[rs]}, 0x{target:08X}"
        if rt == 0x11:
            target = addr + 4 + (simm << 2)
            return f"bgezal {REGS[rs]}, 0x{target:08X}"
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        return f"jal 0x{target:08X}"
    if op == 0x02:
        target = (instr & 0x03FFFFFF) << 2
        return f"j 0x{target:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Focus on the eboot cluster: 0x0888CC00-0x0888F400
# These addresses had Y=50 near rendering JALs
# Let's dump from 0x0888C000 to 0x0889000 to find function boundaries

# First, find function boundaries by looking for "jr $ra" + nop patterns
print("=== FUNCTION MAP 0x0888C000 - 0x08890000 ===")
functions = []
for addr in range(0x0888C000, 0x08890000, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    # Check for addiu $sp, $sp, -N (function prologue)
    if (instr >> 16) == 0x27BD:
        simm = (instr & 0xFFFF)
        if simm >= 0x8000:  # negative = stack alloc
            functions.append(addr)

print(f"Found {len(functions)} functions")
for f in functions:
    print(f"  0x{f:08X}")

# Now dump the functions that contain Y=50 references
target_funcs = []
for i, faddr in enumerate(functions):
    end = functions[i+1] if i+1 < len(functions) else faddr + 0x400
    for addr in range(faddr, min(end, faddr + 0x1000), 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        if (instr >> 21) == 0x120:  # addiu rt, $zero, imm
            imm = instr & 0xFFFF
            if imm in (50, 66, 87, 108, 2):
                target_funcs.append((faddr, end, addr, imm))
                break

print(f"\n=== FUNCTIONS CONTAINING PLAYER LIST Y VALUES ===")
for faddr, fend, match_addr, match_val in target_funcs:
    print(f"\nFunction at 0x{faddr:08X}, match at 0x{match_addr:08X} (value={match_val}):")
    # Dump ~60 instructions around the match
    dump_start = max(faddr, match_addr - 40*4)
    dump_end = min(fend, match_addr + 40*4)
    for addr in range(dump_start, dump_end, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""
        if addr == match_addr:
            marker = " <<<<<<"
        # Highlight JALs to rendering functions
        if (instr >> 26) == 0x03:
            target = (instr & 0x03FFFFFF) << 2
            if 0x088E0000 <= target <= 0x08910000:
                marker += " [RENDER]"
        print(f"  0x{addr:08X}: {d}{marker}")

# Also check the overlay functions with Y=50
print("\n\n=== OVERLAY FUNCTION AT 0x09D4C158 (addiu $s5, $zero, 50) ===")
# Find function start
for addr in range(0x09D4C158, 0x09D4B000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if (instr >> 16) == 0x27BD and (instr & 0xFFFF) >= 0x8000:
        func_start = addr
        break

for addr in range(func_start, func_start + 200*4, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if addr == 0x09D4C158:
        marker = " <<<<< Y=50"
    if (instr >> 26) == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    # Check for addiu with player Y values
    if (instr >> 21) == 0x120:
        imm = instr & 0xFFFF
        if imm in (50, 66, 87, 108):
            marker += f" Y={imm}"
    print(f"  0x{addr:08X}: {d}{marker}")

# Also check 0x09D63004 and 0x09D63070 (overlay, Y=50 near rendering)
print("\n\n=== OVERLAY FUNCTION NEAR 0x09D63004 ===")
for addr in range(0x09D63004, 0x09D62000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if (instr >> 16) == 0x27BD and (instr & 0xFFFF) >= 0x8000:
        func_start = addr
        break

for addr in range(func_start, func_start + 200*4, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if addr in (0x09D63004, 0x09D63070):
        marker = " <<<<< Y=50"
    if (instr >> 26) == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    if (instr >> 21) == 0x120:
        imm = instr & 0xFFFF
        if imm in (2, 50, 66, 87, 108):
            marker += f" val={imm}"
    print(f"  0x{addr:08X}: {d}{marker}")

print("\nDone!")
