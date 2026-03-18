#!/usr/bin/env python3
"""Find the actual vtable[0xD8] target for the sharpness indicator object.
The sharpness code does: lw $v1, 0($s1); lw $v0, 0xD8($v1); jalr $v0
We need to find what $s1 points to and read its vtable."""

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
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        return f"special func=0x{func:02X}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Strategy: Find the function entry point for the sharpness code
# and trace where $s1 comes from.

# First, find function prologues in the sharpness area
print("=== Function prologues in 0x09D5D000-0x09D5F000 ===")
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  0x{addr:08X}: addiu $sp, $sp, {simm}")
            # Dump first 20 instructions to see where $s1 comes from
            print(f"    First 20 instructions:")
            for a in range(addr, addr + 80, 4):
                o = psp_to_offset(a)
                i = read_u32(data, o)
                d = disasm(i, a)
                m = ""
                if "$s1" in d: m = " <<<< S1"
                if "$a0" in d and "addu" in d: m += " [A0]"
                print(f"    0x{a:08X}: 0x{i:08X}  {d}{m}")

# Now let's try to find the vtable by looking at the 0x08823188 setup:
# sw $a1, 0xD8($a0) at 0x08823188
# This sets vtable[0xD8] = $a1
# Let's look at the full function containing 0x08823188
print(f"\n=== Function around 0x08823188 (vtable setup sw $a1, 0xD8($a0)) ===")
# Search backwards for function prologue
for addr in range(0x08823188, 0x08823000, -4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x09:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = instr & 0xFFFF
        if simm >= 0x8000: simm -= 0x10000
        if rs == 29 and rt == 29 and simm < 0:
            print(f"  Function starts at 0x{addr:08X}")
            for a in range(addr, 0x088231A0, 4):
                o = psp_to_offset(a)
                i = read_u32(data, o)
                d = disasm(i, a)
                m = ""
                if a == 0x08823188: m = " <<<< VTABLE[0xD8] SETUP"
                print(f"  0x{a:08X}: 0x{i:08X}  {d}{m}")
            break

# Alternative approach: scan overlay data for vtable pointers
# The sharpness objects should be in the overlay data area
# Look at heap-like areas (0x09D8-0x09DC) for objects with vtable pointers
print(f"\n=== Scanning for vtable pointers in overlay data (0x09D80000-0x09DC0000) ===")
print(f"Looking for objects where *(obj) is an eboot vtable address and vtable[0xD8/4] is valid...")
found_vtables = set()
for addr in range(0x09D80000, 0x09DC0000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    val = read_u32(data, off)
    # Check if this looks like a vtable pointer (points to eboot data section)
    if 0x08960000 <= val < 0x089A0000:
        vtable_addr = val
        if vtable_addr in found_vtables:
            continue
        # Read vtable[0xD8/4] = vtable[54]
        vt_off = psp_to_offset(vtable_addr + 0xD8)
        if vt_off + 4 > len(data): continue
        d8_val = read_u32(data, vt_off)
        # Check if it's a valid code pointer
        if (0x08800000 <= d8_val < 0x08A00000 or 0x09C00000 <= d8_val < 0x09E00000) and (d8_val & 3) == 0:
            found_vtables.add(vtable_addr)
            # Also read nearby vtable entries for context
            entries = []
            for i in range(0, 0x100, 4):
                ve_off = psp_to_offset(vtable_addr + i)
                if ve_off + 4 > len(data): break
                ve = read_u32(data, ve_off)
                entries.append(ve)
            print(f"\n  Object at 0x{addr:08X} -> vtable at 0x{vtable_addr:08X}")
            print(f"    vtable[0xD8] = 0x{d8_val:08X}")
            # Show some key vtable entries
            for idx in [0, 0x44//4, 0xAC//4, 0xD8//4, 0xDC//4, 0xE0//4, 0xE4//4, 0xF0//4, 0xFC//4, 0x15C//4, 0x1D4//4, 0x1D8//4]:
                if idx < len(entries):
                    val = entries[idx]
                    loc = "EBOOT" if val < 0x09000000 else "OVL" if val >= 0x09C00000 else "?"
                    print(f"    vtable[0x{idx*4:03X}] = 0x{val:08X} ({loc})")

print("\nDone!")
