#!/usr/bin/env python3
"""Check the original instruction at 0x08901310 and verify cave addresses are free."""

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
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"raw=0x{instr:08X}"

data = load_state(STATE)

# Check original instruction at 0x08901310 and surrounding
print("=== Instructions around 0x08901310 ===")
for addr in range(0x08901300, 0x08901330, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    mark = " <<<< HOOK" if addr == 0x08901310 else ""
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{mark}")

# Check if 0x08800280-0x088002A0 is free (all zeros?)
print("\n=== Memory at 0x08800280-0x088002C0 ===")
for addr in range(0x08800280, 0x088002C0, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{instr:08X}")

# Check what's at 0x09D6C65C (the branch target when bit0=0)
print("\n=== Code at 0x09D6C65C (OPEN path) ===")
for addr in range(0x09D6C65C, 0x09D6C700, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d: m = f" [0x{(instr & 0x03FFFFFF) << 2:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Also verify: overlay at 0x09D6C528 instruction
print("\n=== Instruction at 0x09D6C528 ===")
addr = 0x09D6C528
instr = read_u32(data, psp_to_offset(addr))
print(f"  0x{addr:08X}: 0x{instr:08X}  {disasm(instr, addr)}")

print("\nDone!")
