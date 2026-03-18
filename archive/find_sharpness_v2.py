#!/usr/bin/env python3
"""Find sharpness indicator render path - search for 0x08901168 callers
and look for the actual vtable function targets."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

data = decompress_ppst(PPST_FILE)

# Find ALL callers of 0x08901168 in the entire memory
jal_1168 = 0x0C000000 | (0x08901168 >> 2)
print("=== ALL callers of 0x08901168 (sprite render with X/Y offset) ===")
for addr in range(0x08800000, 0x09E00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_1168:
        loc = "EBOOT" if addr < 0x09000000 else "OVERLAY"
        print(f"  0x{addr:08X} ({loc})")

# Now try to resolve vtable targets from the sharpness area
# From the jalr analysis, the common pattern is:
#   lw $v1, 0($s1)       ; vtable = obj->vtable
#   lw $v0, 0xD8($v1)    ; func = vtable[0xD8/4]
#   jalr $v0
# We need to find what $s1 points to. Let's look at the function entry.

# Let me search for the specific vtable offset +0xD8 pattern in the eboot
# to find what functions might be registered at vtable+0xD8
print("\n=== Looking for vtable method registration for offset 0xD8 ===")
# Pattern: sw $reg, 0xD8($reg2) in the eboot (storing a function pointer in vtable)
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    simm = instr & 0xFFFF
    if op == 0x2B and simm == 0x00D8:  # sw $rt, 0xD8($rs)
        rt = (instr >> 16) & 0x1F
        rs = (instr >> 21) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        print(f"  0x{addr:08X}: sw {REGS[rt]}, 0xD8({REGS[rs]})")
        # Check what's being stored - look backwards for lui/addiu/li pattern
        for a in range(addr - 4, addr - 20, -4):
            o = psp_to_offset(a)
            i = read_u32(data, o)
            iop = i >> 26
            irt = (i >> 16) & 0x1F
            if iop == 0x0F and irt == rt:  # lui into same reg
                imm = i & 0xFFFF
                print(f"    <- lui at 0x{a:08X}: 0x{imm:04X}xxxx")
            if iop == 0x09 and irt == rt:  # addiu into same reg
                irs = (i >> 21) & 0x1F
                isimm = i & 0xFFFF
                if isimm >= 0x8000: isimm -= 0x10000
                print(f"    <- addiu at 0x{a:08X}: {REGS[irt]}, {REGS[irs]}, {isimm}")

# Also look for vtable offset 0xDC (220) - used in the init code
for addr in range(0x08800000, 0x08A00000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    simm = instr & 0xFFFF
    if op == 0x2B and simm == 0x00DC:  # sw $rt, 0xDC($rs)
        rt = (instr >> 16) & 0x1F
        rs = (instr >> 21) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        # Only print if storing a code pointer (not stack/data)
        print(f"  0x{addr:08X}: sw {REGS[rt]}, 0xDC({REGS[rs]})")

# Brute force: scan known vtable areas for function pointers
# Vtables are usually arrays of function pointers. Let me look for arrays
# of valid code addresses in data sections.
# The vtable pointer would be at offset 0 of the object.
# Common vtable functions should include addresses in 0x0884-0x0890 range.

# Let me try to find actual vtable data by searching for sequences of
# code pointers to the eboot render area
print("\n=== Potential vtables (3+ consecutive eboot code pointers) ===")
for addr in range(0x08900000, 0x089A0000, 4):
    off = psp_to_offset(addr)
    if off + 4 * 3 > len(data): break
    # Check if this looks like a vtable: 3+ consecutive valid eboot function pointers
    count = 0
    for i in range(20):  # check up to 20 consecutive entries
        val = read_u32(data, off + i * 4)
        if 0x08800000 <= val < 0x08A00000 and (val & 3) == 0:
            count += 1
        else:
            break
    if count >= 5:
        # This could be a vtable! Dump it
        vals = []
        for i in range(min(count, 10)):
            vals.append(f"0x{read_u32(data, off + i * 4):08X}")
        # Check if entry at vtable+0xD8 (offset 54 words) exists
        d8_off = 0xD8 // 4
        if d8_off < count:
            d8_val = read_u32(data, off + d8_off * 4)
            print(f"  0x{addr:08X}: {count} ptrs, [0xD8]=0x{d8_val:08X}  first: {' '.join(vals[:5])}")
        else:
            print(f"  0x{addr:08X}: {count} ptrs (short)  first: {' '.join(vals[:5])}")

print("\nDone!")
