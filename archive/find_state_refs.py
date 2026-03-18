#!/usr/bin/env python3
"""Find code references to 0x09BE9F5C and 0x09BE9F80.
These are accessed as base+offset. Common bases: 0x09BF (lui) or $fp/$s-reg.
0x09BE9F5C = 0x09BF0000 - 0x60A4 → offset 0x9F5C (signed)
0x09BE9F80 = 0x09BF0000 - 0x6080 → offset 0x9F80 (signed)
Both have simm encoding: 0x9F5C and 0x9F80 (signed = -24740 and -24704)"""

import struct
import zstandard as zstd

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

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")

targets = {0x9F5C: "0x09BE9F5C (flag 0→1)", 0x9F80: "0x09BE9F80 (state 0→3)"}

for imm_val, desc in targets.items():
    print(f"\n=== References to {desc} (offset 0x{imm_val:04X}) ===")

    # Search eboot and overlay for load/store with this immediate
    for region_name, start, end in [("EBOOT", 0x08800000, 0x08A00000),
                                      ("OVERLAY", 0x09C50000, 0x09E00000)]:
        for addr in range(start, end, 4):
            off = psp_to_offset(addr)
            if off + 4 > len(data): break
            instr = read_u32(data, off)
            imm = instr & 0xFFFF
            if imm != imm_val:
                continue

            op = instr >> 26
            rs = (instr >> 21) & 0x1F
            rt = (instr >> 16) & 0x1F

            # Only interested in load/store/addiu instructions
            desc_str = None
            if op == 0x23: desc_str = f"lw {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x20: desc_str = f"lb {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x24: desc_str = f"lbu {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x21: desc_str = f"lh {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x25: desc_str = f"lhu {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x2B: desc_str = f"sw {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x28: desc_str = f"sb {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x29: desc_str = f"sh {REGS[rt]}, 0x{imm_val:04X}({REGS[rs]})"
            elif op == 0x09: desc_str = f"addiu {REGS[rt]}, {REGS[rs]}, 0x{imm_val:04X}"

            if desc_str:
                # Check if base register likely holds 0x09BF0000 or similar
                # by looking for a preceding lui
                note = ""
                if rs == 30:  # $fp
                    note = " [$fp-relative]"
                print(f"  {region_name} 0x{addr:08X}: {desc_str}{note}")

print("\nDone!")
