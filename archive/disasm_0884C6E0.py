#!/usr/bin/env python3
"""Disassemble function at 0x0884C6E0 and verify pointer chain."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u8(data, off):
    return struct.unpack_from('B', data, off)[0]

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
        if func == 0x0A: return f"movz {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0B: return f"movn {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x18: return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x19: return f"multu {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
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
        rt_v = (instr >> 16) & 0x1F
        if rt_v == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x10: return f"bltzal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11: return f"cop1 raw=0x{instr:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)
print(f"Decompressed {len(data)} bytes\n")

# --- Disassemble context before the function (10 instructions) ---
print("=== Context before function (0x0884C6B8 - 0x0884C6DC) ===")
for addr in range(0x0884C6B8, 0x0884C6E0, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f"  [-> 0x{target:08X}]"
    if "jalr" in d: m = "  [INDIRECT CALL]"
    if "jr $ra" in d: m = "  [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# --- Disassemble function at 0x0884C6E0 for ~100 instructions ---
print("\n=== Function at 0x0884C6E0 (~100 instructions) ===")
count = 0
for addr in range(0x0884C6E0, 0x0884C6E0 + 100 * 4, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f"  [-> 0x{target:08X}]"
    if "jalr" in d: m = "  [INDIRECT CALL]"
    if "jr $ra" in d: m = "  [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
    count += 1
    # Stop if we hit jr $ra (but print the delay slot too)
    if "jr $ra" in d:
        # print delay slot
        next_addr = addr + 4
        next_off = psp_to_offset(next_addr)
        next_instr = read_u32(data, next_off)
        next_d = disasm(next_instr, next_addr)
        print(f"  0x{next_addr:08X}: 0x{next_instr:08X}  {next_d}  [delay slot]")
        break

print(f"\n  ({count} instructions disassembled)")

# --- Pointer chain verification ---
print("\n=== Pointer Chain Verification ===")

ptr_addr = 0x09BF524C
ptr_off = psp_to_offset(ptr_addr)
hud_ptr = read_u32(data, ptr_off)
print(f"  [0x{ptr_addr:08X}] = 0x{hud_ptr:08X}")

if hud_ptr != 0:
    flag_addr = hud_ptr + 0x54
    flag_off = psp_to_offset(flag_addr)
    flag_val = read_u8(data, flag_off)
    print(f"  [0x{flag_addr:08X}] (hud_ptr + 0x54) = 0x{flag_val:02X} ({flag_val})")
else:
    print("  hud_ptr is NULL, cannot read +0x54")

print("\nDone!")
