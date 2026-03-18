#!/usr/bin/env python3
"""Find the HUD object ($s2) and its item selector state.
$s3 = jal 0x088B51B8(*(0x09BB7A80), ...)
Then $s3+0xBA0 has the flags.
$s2 = first arg to parent function 0x09D6C498."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return data[off]

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
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X}"

data_closed = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")
data_open = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")

# Find callers of 0x09D6C498 to determine what $a0 ($s2) is
print("=== Callers of 0x09D6C498 ===")
target_26 = 0x09D6C498 >> 2
jal_encoding = (3 << 26) | (target_26 & 0x03FFFFFF)
for region_name, start, end in [("EBOOT", 0x08800000, 0x08A00000),
                                  ("OVERLAY", 0x09C50000, 0x09E00000)]:
    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data_open): break
        instr = read_u32(data_open, off)
        if instr == jal_encoding:
            print(f"  {region_name} 0x{addr:08X}: jal 0x09D6C498")
            # Show 10 instructions before
            for ctx in range(addr - 40, addr + 4, 4):
                ctx_off = psp_to_offset(ctx)
                ctx_instr = read_u32(data_open, ctx_off)
                marker = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{ctx_instr:08X}  {disasm(ctx_instr, ctx)}{marker}")
            print()

# Also check: what is at *(0x09BB7A80)? This is the first arg to 0x088B51B8.
ptr_9BB7A80_c = read_u32(data_closed, psp_to_offset(0x09BB7A80))
ptr_9BB7A80_o = read_u32(data_open, psp_to_offset(0x09BB7A80))
print(f"*(0x09BB7A80): closed=0x{ptr_9BB7A80_c:08X} open=0x{ptr_9BB7A80_o:08X}")

# Check the pointer at 0x08AACE80 (used for lbu arg)
ptr_AACE80_c = read_u32(data_closed, psp_to_offset(0x08AACE80))
ptr_AACE80_o = read_u32(data_open, psp_to_offset(0x08AACE80))
print(f"*(0x08AACE80): closed=0x{ptr_AACE80_c:08X} open=0x{ptr_AACE80_o:08X}")

# Dump the update function 0x09D69938 to find what state it manages
print("\n=== Function 0x09D69938 (item selector update) ===")
for addr in range(0x09D69938, 0x09D69938 + 0x200, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data_open, off)
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}")
    if "jr $ra" in d:
        addr2 = addr + 4
        off2 = psp_to_offset(addr2)
        instr2 = read_u32(data_open, off2)
        print(f"  0x{addr2:08X}: 0x{instr2:08X}  {disasm(instr2, addr2)}")
        # Check for function end
        next_off = psp_to_offset(addr2 + 4)
        next_instr = read_u32(data_open, next_off)
        next_op = next_instr >> 26
        next_rs = (next_instr >> 21) & 0x1F
        next_rt = (next_instr >> 16) & 0x1F
        next_simm = next_instr & 0xFFFF
        if next_simm >= 0x8000: next_simm -= 0x10000
        if next_op == 0x09 and next_rs == 29 and next_rt == 29 and next_simm < 0:
            break

print("\nDone!")
