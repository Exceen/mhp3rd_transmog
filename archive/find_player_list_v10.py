#!/usr/bin/env python3
"""Find the player list background rendering code.
The function at 0x09D6380C renders names/icons. The background is rendered elsewhere.
Look at sibling calls from the parent function 0x09D6C498."""

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
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
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
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        return f"jal 0x{target:08X}"
    if op == 0x02:
        target = (instr & 0x03FFFFFF) << 2
        return f"j 0x{target:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# The parent function at 0x09D6C498 calls many sub-functions.
# The rendering loop at 0x09D6C8F8-0x09D6C928 calls 0x09D6380C for names/icons.
# There's another loop at 0x09D6C940-0x09D6C978 that calls 0x09D6309C.
# And before rendering, functions like 0x09D5E8D0, 0x09D5E9C0, 0x09D648AC are called.
# The background is likely rendered by one of these.

# Let's dump functions called from the parent that might render the background:
# 0x09D62384 - called at 0x09D6C720 (right before the rendering section)
# 0x09D5E8D0 - called at 0x09D6C738
# 0x09D5E9C0 - called at 0x09D6C744
# 0x09D648AC - called at 0x09D6C750
# 0x09D60280 - called at 0x09D6C7EC
# 0x09D6172C - called at 0x09D6C7F8

# Also look at the second rendering loop at 0x09D6C940-0x09D6C978
# which calls 0x09D6309C with different args

# Let's first check 0x09D6309C - this was identified earlier as rendering player data
# It's called in a second loop AFTER the name rendering loop

print("=== FUNCTION AT 0x09D6309C (second loop renderer) ===")
for addr in range(0x09D6309C, 0x09D63400, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also dump 0x09D62384 - called right before background rendering section
print("\n\n=== FUNCTION AT 0x09D62384 ===")
for addr in range(0x09D62384, 0x09D62800, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    # Look for layout table reference
    if "0x09D9" in d or "addiu" in d:
        simm_val = instr & 0xFFFF
        if simm_val == 0x2CB0 or simm_val == 0x5DEC or simm_val == 0x5DE0:
            marker += " [TABLE]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Dump 0x09D648AC
print("\n\n=== FUNCTION AT 0x09D648AC ===")
for addr in range(0x09D648AC, 0x09D64C00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Dump 0x09D5E8D0 and 0x09D5E9C0 (called before rendering)
print("\n\n=== FUNCTION AT 0x09D5E8D0 ===")
for addr in range(0x09D5E8D0, 0x09D5EA00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    print(f"  0x{addr:08X}: {d}{marker}")

print("\n\n=== FUNCTION AT 0x09D5E9C0 ===")
for addr in range(0x09D5E9C0, 0x09D5EB00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    marker = ""
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
    print(f"  0x{addr:08X}: {d}{marker}")

# Also look at 0x09D60280 - another function called in the rendering path
print("\n\n=== FUNCTION AT 0x09D60280 ===")
for addr in range(0x09D60280, 0x09D60600, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
        # Also flag calls to layout table functions
        if 0x09D60000 <= target <= 0x09D70000:
            marker += f" [OVL:{target:08X}]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

# Also check 0x09D6172C
print("\n\n=== FUNCTION AT 0x09D6172C ===")
for addr in range(0x09D6172C, 0x09D61A00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    cw = addr - 0x08800000
    marker = ""
    if "lh" in d and ("24(" in d or "26(" in d):
        marker = " <<< X/Y?"
    if "jal" in d:
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x08910000:
            marker += " [RENDER]"
        if 0x09D60000 <= target <= 0x09D70000:
            marker += f" [OVL:{target:08X}]"
    print(f"  0x{addr:08X} (CW 0x{cw:07X}): {d}{marker}")

print("\nDone!")
