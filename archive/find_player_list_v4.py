#!/usr/bin/env python3
"""Dump the text rendering function around 0x09D63A10 to find X/Y base positions."""

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

REG_NAMES = {0:'$zero',1:'$at',2:'$v0',3:'$v1',4:'$a0',5:'$a1',6:'$a2',7:'$a3',
             8:'$t0',9:'$t1',10:'$t2',11:'$t3',12:'$t4',13:'$t5',14:'$t6',15:'$t7',
             16:'$s0',17:'$s1',18:'$s2',19:'$s3',20:'$s4',21:'$s5',22:'$s6',23:'$s7',
             24:'$t8',25:'$t9',28:'$gp',29:'$sp',30:'$fp',31:'$ra'}

def disasm(instr):
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    imm = instr & 0xFFFF
    simm = imm - 0x10000 if imm >= 0x8000 else imm
    rn = lambda r: REG_NAMES.get(r, f'${r}')

    if instr == 0: return "nop"
    elif op == 0:
        func = instr & 0x3F
        sa = (instr >> 6) & 0x1F
        if func == 0x08: return f"jr {rn(rs)}"
        elif func == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        elif func == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x00: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x03: return f"sra {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x0A: return f"movz {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x0B: return f"movn {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"special.{func:02X} {rn(rd)},{rn(rs)},{rn(rt)}"
    elif op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    elif op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    elif op == 0x04: return f"beq {rn(rs)}, {rn(rt)}, {simm}"
    elif op == 0x05: return f"bne {rn(rs)}, {rn(rt)}, {simm}"
    elif op == 0x06: return f"blez {rn(rs)}, {simm}"
    elif op == 0x07: return f"bgtz {rn(rs)}, {simm}"
    elif op == 0x01:
        if rt == 0: return f"bltz {rn(rs)}, {simm}"
        elif rt == 1: return f"bgez {rn(rs)}, {simm}"
        elif rt == 0x11: return f"bgezal {rn(rs)}, {simm}"
        return f"regimm.{rt} {rn(rs)}, {simm}"
    elif op == 0x09: return f"addiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0A: return f"slti {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0B: return f"sltiu {rn(rt)}, {rn(rs)}, {imm}"
    elif op == 0x0C: return f"andi {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0D: return f"ori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x20: return f"lb {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x21: return f"lh {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x24: return f"lbu {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, {simm}({rn(rs)})"
    elif op == 0x31: return f"lwc1 $f{rt}, {simm}({rn(rs)})"
    elif op == 0x39: return f"swc1 $f{rt}, {simm}({rn(rs)})"
    elif op == 0x11:
        fmt = rs
        if fmt == 0x10:
            func2 = instr & 0x3F
            ft = rt; fd = rd; fs = (instr >> 11) & 0x1F
            ops = {0:'add.s',1:'sub.s',2:'mul.s',3:'div.s',6:'mov.s',36:'cvt.w.s',32:'cvt.s.w'}
            if func2 in ops:
                return f"{ops[func2]} $f{fd}, $f{fs}, $f{ft}" if func2 <= 3 else f"{ops[func2]} $f{fd}, $f{fs}"
            return f"cop1.s.{func2:02X}"
        elif fmt == 0x04: return f"mtc1 {rn(rt)}, $f{rd}"
        elif fmt == 0x00: return f"mfc1 {rn(rt)}, $f{rd}"
        elif fmt == 0x08:
            if rt == 0: return f"bc1f {simm}"
            elif rt == 1: return f"bc1t {simm}"
        return f"cop1.{fmt:02X}"
    elif op == 0x1F:
        func2 = instr & 0x3F
        if func2 == 0x00:
            pos = (instr >> 6) & 0x1F
            size = ((instr >> 11) & 0x1F) + 1
            return f"ext {rn(rt)}, {rn(rs)}, {pos}, {size}"
        elif func2 == 0x04:
            pos = (instr >> 6) & 0x1F
            size = ((instr >> 11) & 0x1F) + 1 - pos
            return f"ins {rn(rt)}, {rn(rs)}, {pos}, {size}"
        return f"special3.{func2:02X}"
    return f"op{op:02X}(0x{instr:08X})"

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

def dump(start, count, mark_addr=None):
    for i in range(count):
        addr = start + i * 4
        off = psp_to_offset(addr)
        if off + 4 <= len(data):
            instr = read_u32(data, off)
            d = disasm(instr)
            cw = addr - 0x08800000
            marker = " <<<" if addr == mark_addr else ""
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): 0x{instr:08X}  {d}{marker}")

# Find the full function containing 0x09D63A10
# Search backwards for addiu $sp, $sp, -N (function prologue)
target = 0x09D63A10
print(f"\n=== FULL FUNCTION CONTAINING 0x{target:08X} ===")

# Find function start by scanning back for stack frame setup
func_start = None
for i in range(1, 500):
    addr = target - i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        # Look for addiu $sp, $sp, -N (negative)
        if (instr >> 16) == 0x27BD:  # addiu $sp, $sp
            simm = instr & 0xFFFF
            if simm >= 0x8000:  # negative = function prologue
                func_start = addr
                break

# Find function end
func_end = None
for i in range(1, 500):
    addr = target + i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        if (instr & 0xFC1FFFFF) == 0x03E00008:  # jr $ra
            func_end = addr + 8
            break

if func_start and func_end:
    count = (func_end - func_start) // 4
    print(f"Function: 0x{func_start:08X} - 0x{func_end:08X} ({count} instructions)")
    dump(func_start, count, target)
else:
    print(f"Could not find function boundaries, dumping wide range")
    dump(target - 100*4, 200, target)

# Also dump the caller function at 0x088E7008 for reference
print(f"\n\n=== CURSOR SETTER FUNCTION 0x088E7008 ===")
dump(0x088E7008, 4)

# And 0x088E7048
print(f"\n=== FUNCTION 0x088E7048 ===")
dump(0x088E7048, 20)

# Also look at what calls the function containing 0x09D63A10
# The function likely starts around func_start. Search for JAL to it.
if func_start:
    jal_func = 0x0C000000 | (func_start >> 2)
    overlay_start = psp_to_offset(0x09C57C80)
    overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)

    print(f"\n\n=== CALLERS OF 0x{func_start:08X} ===")
    for off in range(overlay_start, overlay_end, 4):
        instr = read_u32(data, off)
        if instr == jal_func:
            psp = off - MEM_OFFSET + PSP_BASE
            print(f"\n  JAL at 0x{psp:08X}:")
            dump(psp - 8*4, 16)

    # Also search eboot
    eboot_start = psp_to_offset(0x08800000)
    eboot_end = min(psp_to_offset(0x08960000), len(data) - 4)
    for off in range(eboot_start, eboot_end, 4):
        instr = read_u32(data, off)
        if instr == jal_func:
            psp = off - MEM_OFFSET + PSP_BASE
            print(f"\n  [eboot] JAL at 0x{psp:08X}:")
            dump(psp - 8*4, 16)

# Dump 0x088E6FF0 (cursor init that's called from overlay)
print(f"\n\n=== CURSOR INIT FUNCTION 0x088E6FF0 ===")
dump(0x088E6E80, 60)

# Look at the function 0x09D5F584 which calls 0x088E6FF0
print(f"\n\n=== CONTEXT AROUND 0x09D5F584 (calls cursor init) ===")
dump(0x09D5F540, 40)

# Look at the function 0x09D63A3C which also calls 0x088E6FF0
print(f"\n\n=== CONTEXT AROUND 0x09D63A3C (calls cursor init) ===")
dump(0x09D63A00, 30)

print("\nDone!")
