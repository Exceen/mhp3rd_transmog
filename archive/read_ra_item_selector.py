#!/usr/bin/env python3
"""Read $ra buffer from save state with item selector open."""

import struct
import zstandard as zstd
from collections import Counter

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
    rd = (instr >> 11) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

# Read both save states for comparison
for label, idx in [("WITH item selector", 6), ("WITHOUT (previous)", 5)]:
    path = f"/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_{idx}.ppst"
    print(f"\n{'='*60}")
    print(f"=== {label} (index {idx}) ===")
    data = decompress_ppst(path)

    hook_val = read_u32(data, psp_to_offset(0x088FFF0C))
    print(f"  Hook: 0x{hook_val:08X} {'(ACTIVE)' if hook_val == 0x0A200140 else '(NOT hooked)'}")

    counter = read_u32(data, psp_to_offset(0x088001FC))
    print(f"  Counter: {counter}")

    ra_values = []
    for i in range(64):
        val = read_u32(data, psp_to_offset(0x08800200 + i * 4))
        ra_values.append(val)

    # Filter to valid-looking addresses
    valid = [v for v in ra_values if 0x08800000 <= v < 0x0A000000]
    counts = Counter(valid)
    if counts:
        print(f"  Unique $ra values ({len(valid)} valid entries):")
        for val, cnt in counts.most_common():
            region = "EBOOT" if val < 0x09000000 else "OVERLAY"
            print(f"    0x{val:08X} ({region}) x{cnt}")
    else:
        print(f"  No valid $ra values")

# Now show context around NEW callers in the item selector state
print(f"\n{'='*60}")
print("=== Context around callers (from item selector state) ===")
data = decompress_ppst(f"/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst")
ra_values = []
for i in range(64):
    val = read_u32(data, psp_to_offset(0x08800200 + i * 4))
    if 0x08800000 <= val < 0x0A000000:
        ra_values.append(val)

for ra_val in sorted(set(ra_values)):
    region = "EBOOT" if ra_val < 0x09000000 else "OVERLAY"
    cnt = ra_values.count(ra_val)
    call_addr = ra_val - 8  # jal is 2 instructions before $ra
    print(f"\n  --- $ra=0x{ra_val:08X} ({region}) x{cnt}, call at 0x{call_addr:08X} ---")
    for addr in range(call_addr - 16, call_addr + 12, 4):
        off = psp_to_offset(addr)
        if off + 4 > len(data) or off < 0: continue
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        m = " <<<<" if addr == call_addr else ""
        print(f"    0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
