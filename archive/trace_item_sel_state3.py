#!/usr/bin/env python3
"""Trace the item selector state flag origin.

Key finding: At 0x09D6C660-0x09D6C670:
  lw $a0, -6544($s0)   # $s0=0x09BF, so $a0 = *(0x09BEE670)
  jal 0x08922370        # Call eboot function with this arg
  sb $v0, 384($s2)      # Store result to $s2+0x180

Also at 0x09D6C674:
  jal 0x08922380        # Another eboot function, result → $s2+0x3DA0

So 0x08922370 returns the item selector active state!
Let's disassemble it to find what address it reads.

Also: $s2+0x180 is the flag in the parent object.
We need to find $s2's address.
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
        rt_v = rt
        if rt_v == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11: return f"cop1 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

def dump_func(data, start, max_instrs=100, label=""):
    print(f"\n{'='*70}")
    print(f"=== {label} ===")
    print(f"{'='*70}")
    for i in range(max_instrs):
        addr = start + i * 4
        off = psp_to_offset(addr)
        if off + 4 > len(data): break
        instr = read_u32(data, off)
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

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Disassemble eboot function 0x08922370 — returns item selector active state
dump_func(mem_c, 0x08922370, 50, "EBOOT 0x08922370 - item selector state query")

# Also 0x08922380 — similar function
dump_func(mem_c, 0x08922380, 50, "EBOOT 0x08922380 - related state query")

# Now let's find the parent object address ($s2)
# Caller at 0x09C5ED84: addiu $a0, $s5, 192 (= $s5 + 0xC0)
# Let's get more context around the caller
print("\n" + "=" * 70)
print("=== Caller context at 0x09C5ED88 (more context) ===")
print("=" * 70)
for addr in range(0x09C5ED00, 0x09C5ED90, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    m = ""
    if "jal " in d and "jalr" not in d:
        target = (instr & 0x03FFFFFF) << 2
        m = f" [0x{target:08X}]"
    if "jr $ra" in d: m = " [RETURN]"
    mark = " <<<<" if addr == 0x09C5ED88 else ""
    print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}{mark}")

# Let's go further back to find where $s5 is set
for addr in range(0x09C5EC00, 0x09C5ED10, 4):
    off = psp_to_offset(addr)
    instr = read_u32(mem_c, off)
    d = disasm(instr, addr)
    if "$s5" in d or "addiu $sp" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}")

# Also check: what's at 0x09BEE670? (the pointer loaded as $a0 for 0x08922370)
ptr_off = psp_to_offset(0x09BEE670)
ptr_c = read_u32(mem_c, ptr_off)
ptr_o = read_u32(mem_o, ptr_off)
print(f"\n*(0x09BEE670) = CLOSED:0x{ptr_c:08X}  OPEN:0x{ptr_o:08X}")

# Follow the pointer to see what 0x08922370 actually reads
if ptr_c != 0:
    print(f"\nObject at 0x{ptr_c:08X} (closed state):")
    for off in range(0, 0x40, 4):
        addr = ptr_c + off
        val = read_u32(mem_c, psp_to_offset(addr))
        val_o = read_u32(mem_o, psp_to_offset(addr))
        diff = " ***" if val != val_o else ""
        print(f"  +0x{off:02X}: C=0x{val:08X}  O=0x{val_o:08X}{diff}")

print("\nDone!")
