#!/usr/bin/env python3
"""Disassemble the parent function 0x09D6C498 around the gate call at 0x09D6C7D0.

Find the exact branch that decides item selector rendering, and also
verify the $s3 pointer at runtime by checking multiple approaches.
"""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE_CLOSED = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"
STATE_OPEN   = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    return zstd.ZstdDecompressor().decompress(data[0xB0:], max_output_size=256*1024*1024)

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

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
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x01:
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Disassemble parent function around the gate call
print("=" * 70)
print("=== Parent 0x09D6C498 around gate call (0x09D6C7A0-0x09D6C9A0) ===")
print("=" * 70)
for addr in range(0x09D6C7A0, 0x09D6C9A0, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        m = f" [{loc} 0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d: m = " [RETURN]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Now let's also trace $s3 more carefully.
# At 0x09D6C498 entry, $s3 is set from the return of jal 0x088B51B8.
# Let's find where that call happens.
print(f"\n{'='*70}")
print(f"=== Parent 0x09D6C498 early section (finding $s3 setup) ===")
print(f"{'='*70}")
for addr in range(0x09D6C498, 0x09D6C550, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

# Check if 0x09BB7A8C pointer is valid by checking what's at *(0x09BB7A80)
# and nearby. Also check the pointer table structure.
print(f"\n{'='*70}")
print(f"=== Pointer table at 0x09BB7A80 ===")
print(f"{'='*70}")
for off in range(0, 0x30, 4):
    addr = 0x09BB7A80 + off
    vc = read_u32(mem_c, psp_to_offset(addr))
    vo = read_u32(mem_o, psp_to_offset(addr))
    d = " ***" if vc != vo else ""
    is_ptr = 0x08000000 <= vc <= 0x0A000000
    print(f"  0x{addr:08X}: C=0x{vc:08X}  O=0x{vo:08X}{d}{'  PTR' if is_ptr else ''}")

# Now let's look at the $s2 object. The gate function's first arg is $s2.
# $s2 = $a0 of 0x09D6C498. Let's trace from the function entry.
# Looking for where $s2 is saved and what it points to.

# Also: let me check the ACTUAL item selector state by looking at the render
# function 0x09D69938 and what it reads.
print(f"\n{'='*70}")
print(f"=== Render function 0x09D69938 (first 80 instructions) ===")
print(f"{'='*70}")
for addr in range(0x09D69938, 0x09D69938 + 320, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        m = f" [{loc} 0x{target:08X}]"
    if "jalr" in d: m = " [INDIRECT]"
    if "jr $ra" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d} [RETURN]")
        break
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("\nDone!")
