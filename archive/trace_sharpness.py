#!/usr/bin/env python3
"""Find all sharpness render calls (0x088C926C callers) and their $a3/$t0 setup."""

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
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Find all callers of 0x088C926C in the sharpness overlay area
jal_926c = 0x0C000000 | (0x088C926C >> 2)
callers = []
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_926c:
        callers.append(addr)

# Also find all j instructions that lead to a 0x088C926C call
# (indirect calls via jump to a setup section)

print(f"=== All {len(callers)} callers of 0x088C926C in sharpness area ===")
for call_addr in callers:
    print(f"\n  --- Call at 0x{call_addr:08X} ---")
    # Scan backwards to find $a3 and $t0 setup
    a3_addr = None
    t0_addr = None
    a3_val = None
    t0_val = None
    for addr in range(call_addr - 4, call_addr - 60, -4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        op = instr >> 26
        rt = (instr >> 16) & 0x1F
        rs = (instr >> 21) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000

        # Check for $a3 (reg 7) setup
        if a3_addr is None:
            if op == 0x09 and rt == 7 and rs == 0:  # addiu $a3, $zero, imm
                a3_addr = addr
                a3_val = simm
            elif op == 0 and (instr & 0x3F) == 0x21 and ((instr >> 11) & 0x1F) == 7:
                # addu $a3, ?, ?
                src1 = (instr >> 21) & 0x1F
                src2 = (instr >> 16) & 0x1F
                if src1 == 0 and src2 == 0:
                    a3_addr = addr
                    a3_val = 0
                elif src1 == 0 or src2 == 0:
                    a3_addr = addr
                    a3_val = f"reg"

        # Check for $t0 (reg 8) setup
        if t0_addr is None:
            if op == 0x09 and rt == 8 and rs == 0:  # addiu $t0, $zero, imm
                t0_addr = addr
                t0_val = simm
            elif op == 0 and (instr & 0x3F) == 0x21 and ((instr >> 11) & 0x1F) == 8:
                src1 = (instr >> 21) & 0x1F
                src2 = (instr >> 16) & 0x1F
                if src1 == 0 and src2 == 0:
                    t0_addr = addr
                    t0_val = 0

    # Show results
    if a3_addr:
        cw_off = a3_addr - 0x08800000
        print(f"  $a3 set at 0x{a3_addr:08X}: value={a3_val}  (CW: 0x2{cw_off:07X})")
    else:
        print(f"  $a3 setup NOT FOUND")
    if t0_addr:
        cw_off = t0_addr - 0x08800000
        t0_cw = t0_addr - 0x08800000
        print(f"  $t0 set at 0x{t0_addr:08X}: value={t0_val}  (CW: 0x2{t0_cw:07X})" if isinstance(t0_val, int) else f"  $t0 set at 0x{t0_addr:08X}: value={t0_val}")
    else:
        print(f"  $t0 setup NOT FOUND")

    # Show 10 instructions before call for context
    print(f"  Context:")
    for addr in range(call_addr - 40, call_addr + 8, 4):
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        m = ""
        if addr == call_addr: m = " <<<< CALL"
        elif addr == a3_addr: m = " <<<< $a3 SETUP"
        elif addr == t0_addr: m = " <<<< $t0 SETUP"
        if "$a3" in d: m += " [a3]"
        if "$t0" in d: m += " [t0]"
        print(f"    0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
