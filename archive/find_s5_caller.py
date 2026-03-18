#!/usr/bin/env python3
"""Find $s5 in the caller of 0x09D6C498 to locate the HUD object.
Caller is at 0x09C5ED88. Need to find $s5's value."""

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
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X}"

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Find the caller function prologue by scanning backward from 0x09C5ED88
print("=== Scanning backward from 0x09C5ED88 for function prologue ===")
func_start = None
for addr in range(0x09C5ED88, 0x09C5E800, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    simm = (instr & 0xFFFF)
    if simm >= 0x8000: simm -= 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        print(f"  Found prologue at 0x{addr:08X}: {disasm(instr, addr)}")
        func_start = addr
        break

if func_start:
    # Dump from prologue to the call site
    print(f"\n=== Caller function 0x{func_start:08X} (up to call at 0x09C5ED88) ===")
    for addr in range(func_start, 0x09C5ED90, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""
        if addr == 0x09C5ED84: marker = "  <-- $a0 = $s5 + 0xC0 (HUD object)"
        if addr == 0x09C5ED88: marker = "  <-- jal 0x09D6C498"
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Now try to find $s5 from the context
# Look for a lw instruction that loads into $s5 ($s5 = reg 21)
print("\n=== Looking for $s5 assignments ===")
if func_start:
    for addr in range(func_start, 0x09C5ED88, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        op = instr >> 26
        rt = (instr >> 16) & 0x1F
        rd = (instr >> 11) & 0x1F
        if rt == 21 and op in [0x23, 0x0F, 0x09, 0x0D]:  # lw, lui, addiu, ori targeting $s5
            print(f"  0x{addr:08X}: {disasm(instr, addr)}")
        if op == 0 and rd == 21:  # special instruction targeting $s5
            func2 = instr & 0x3F
            if func2 == 0x21:  # addu
                print(f"  0x{addr:08X}: {disasm(instr, addr)}")

print("\nDone!")
