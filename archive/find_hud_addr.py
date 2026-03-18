#!/usr/bin/env python3
"""Find the HUD object by tracing callers of 0x09C5EC18.
$s2 (in parent 0x09D6C498) = first_arg_to_0x09C5EC18 + 0xC0"""

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
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X}"

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst")
data_c = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

# Find callers of 0x09C5EC18
print("=== Callers of 0x09C5EC18 ===")
target_26 = 0x09C5EC18 >> 2
jal_enc = (3 << 26) | (target_26 & 0x03FFFFFF)
for region_name, start, end in [("EBOOT", 0x08800000, 0x08A00000),
                                  ("OVERLAY", 0x09C50000, 0x09E00000)]:
    for addr in range(start, end, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
        if instr == jal_enc:
            print(f"  {region_name} 0x{addr:08X}: jal 0x09C5EC18")
            # Show 5 instructions before
            for ctx in range(addr - 20, addr + 4, 4):
                ctx_off = psp_to_offset(ctx)
                ctx_instr = read_u32(data, ctx_off)
                marker = " <<<" if ctx == addr else ""
                print(f"    0x{ctx:08X}: 0x{ctx_instr:08X}  {disasm(ctx_instr, ctx)}{marker}")
            print()

# Also check: the function 0x09D6C498 uses $s3 = return of jal 0x088B51B8
# with $a0 = *(0x09BB7A80) = 0x09BB7A84
# Let's check what's at 0x09BB7A84 and nearby — this might be a button/input struct
# and 0x088B51B8 might return a pointer relative to it
print("=== *(0x09BB7A80) and context ===")
for addr in range(0x09BB7A70, 0x09BB7AB0, 4):
    off = psp_to_offset(addr)
    vc = read_u32(data_c, off)
    vo = read_u32(data, off)
    diff = " ***" if vc != vo else ""
    print(f"  0x{addr:08X}: closed=0x{vc:08X} open=0x{vo:08X}{diff}")

# Let's try to find $s3 by looking at 0x088B51B8's behavior
# It takes $a0=0x09BB7A84, $a1=byte, $a2=1
# Maybe it returns $a0 + some_offset?
# Or maybe $s3 is a global pointer loaded elsewhere.
# Let's check: in the parent, $s3+0xBA0 flags with bit0 set during gameplay.
# Search for a word with bit0 set and bits 1,9 clear in likely areas.
print("\n=== Searching for $s3+0xBA0 flags pattern (bit0=1, bit1=0, bit9=0) ===")
# The flags word should have bit0=1, and be consistent across both states
for addr in range(0x09B80000, 0x09C00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data_c): break
    vc = read_u32(data_c, off)
    vo = read_u32(data, off)
    # Both should have bit0=1, bit1=0, bit9=0
    if (vc & 0x0001) and not (vc & 0x0002) and not (vc & 0x0200):
        if (vo & 0x0001) and not (vo & 0x0002) and not (vo & 0x0200):
            # This could be the flags word
            # Check: the containing object at addr-0xBA0 should be $s3
            s3_candidate = addr - 0xBA0
            # $s3 + 0x18C should have a halfword != 0xA600 (from visibility check)
            off_18c = psp_to_offset(s3_candidate + 0x18C)
            if off_18c + 2 <= len(data):
                h = struct.unpack_from('<H', data, off_18c)[0]
                if h != 0xA600 and h != 0:
                    # Also check that the word is small-ish (not a random pointer)
                    if vc < 0x10000 and vo < 0x10000:
                        print(f"  flags at 0x{addr:08X}: closed=0x{vc:08X} open=0x{vo:08X}")
                        print(f"    → $s3=0x{s3_candidate:08X}, +0x18C=0x{h:04X}")

print("\nDone!")
