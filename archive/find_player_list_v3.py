#!/usr/bin/env python3
"""Deeper analysis of player list rendering in MHP3rd overlay."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

REG_NAMES = {0:'$zero',1:'$at',2:'$v0',3:'$v1',4:'$a0',5:'$a1',6:'$a2',7:'$a3',
             8:'$t0',9:'$t1',10:'$t2',11:'$t3',12:'$t4',13:'$t5',14:'$t6',15:'$t7',
             16:'$s0',17:'$s1',18:'$s2',19:'$s3',20:'$s4',21:'$s5',22:'$s6',23:'$s7',
             24:'$t8',25:'$t9',28:'$gp',29:'$sp',30:'$fp',31:'$ra'}

def disasm(instr):
    """Extended MIPS disassembler."""
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    imm = instr & 0xFFFF
    simm = imm - 0x10000 if imm >= 0x8000 else imm
    rn = lambda r: REG_NAMES.get(r, f'${r}')

    if instr == 0:
        return "nop"
    elif op == 0:  # SPECIAL
        func = instr & 0x3F
        sa = (instr >> 6) & 0x1F
        if func == 0x08: return f"jr {rn(rs)}"
        elif func == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        elif func == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        elif func == 0x00: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x03: return f"sra {rn(rd)}, {rn(rt)}, {sa}"
        elif func == 0x04: return f"sllv {rn(rd)}, {rn(rt)}, {rn(rs)}"
        elif func == 0x0D: return f"break"
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
    elif op == 0x08: return f"addi {rn(rt)}, {rn(rs)}, {simm}"
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
    elif op == 0x35: return f"ldc1 $f{rt}, {simm}({rn(rs)})"
    elif op == 0x39: return f"swc1 $f{rt}, {simm}({rn(rs)})"
    elif op == 0x11:  # COP1
        fmt = rs
        if fmt == 0x10:  # single
            func = instr & 0x3F
            ft = rt
            fd = rd
            fs = (instr >> 11) & 0x1F
            ops = {0:'add.s',1:'sub.s',2:'mul.s',3:'div.s',5:'abs.s',6:'mov.s',
                   12:'round.w.s',13:'trunc.w.s',36:'cvt.w.s',32:'cvt.s.w'}
            if func in ops:
                return f"{ops[func]} $f{fd}, $f{fs}" if func in (5,6,12,13,36,32) else f"{ops[func]} $f{fd}, $f{fs}, $f{ft}"
            return f"cop1.s.{func:02X}"
        elif fmt == 0x14:  # W
            func = instr & 0x3F
            fd = rd
            fs = (instr >> 11) & 0x1F
            if func == 32: return f"cvt.s.w $f{fd}, $f{fs}"
            return f"cop1.w.{func:02X}"
        elif fmt == 0x04:  # MTC1
            return f"mtc1 {rn(rt)}, $f{rd}"
        elif fmt == 0x00:  # MFC1
            return f"mfc1 {rn(rt)}, $f{rd}"
        elif fmt == 0x08:  # BC1
            if rt == 0: return f"bc1f {simm}"
            elif rt == 1: return f"bc1t {simm}"
        return f"cop1.{fmt}.{instr&0x3F:02X}"
    elif op == 0x12:  # COP2 (VFPU)
        return f"vfpu 0x{instr:08X}"
    elif op == 0x36:  # lv.q (VFPU load quad)
        return f"lv.q 0x{instr:08X}"
    elif op == 0x34:  # lv.s (VFPU load single)
        return f"lv.s 0x{instr:08X}"
    elif op == 0x3C:  # sv.q
        return f"sv.q 0x{instr:08X}"
    elif op == 0x3E:  # sv.s or similar
        return f"vfpu_store 0x{instr:08X}"
    elif op == 0x1F:  # SPECIAL3 (ext, ins, etc.)
        func = instr & 0x3F
        if func == 0x00:
            pos = (instr >> 6) & 0x1F
            size = ((instr >> 11) & 0x1F) + 1
            return f"ext {rn(rt)}, {rn(rs)}, {pos}, {size}"
        return f"special3.{func:02X}"
    return f"op{op}({instr:08X})"

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

def dump_range(start_psp, count, label=""):
    """Dump disassembly for a range of instructions."""
    if label:
        print(f"\n--- {label} ---")
    for i in range(count):
        addr = start_psp + i * 4
        off = psp_to_offset(addr)
        if off + 4 <= len(data):
            instr = read_u32(data, off)
            d = disasm(instr)
            cw = addr - 0x08800000
            print(f"  0x{addr:08X} (CW 0x{cw:07X}): 0x{instr:08X}  {d}")

# ============================================================
# 1. Full function dump around overlay SH +0x120 at 0x09D34634
# Find function boundaries by looking for jr $ra before/after
# ============================================================
print("\n=== FUNCTION AROUND OVERLAY 0x09D34634 (sh $v1, 0x120($s0)) ===")
# Scan backwards to find function start (look for stack frame setup or previous jr $ra)
target = 0x09D34634
found_start = target - 200 * 4  # default
for i in range(1, 200):
    addr = target - i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        # jr $ra followed by nop/delay slot = end of previous function
        if (instr & 0xFC1FFFFF) == 0x03E00008:  # jr $ra
            found_start = addr + 8  # function starts after delay slot
            break

# Scan forward to find function end
found_end = target + 200 * 4
for i in range(1, 300):
    addr = target + i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        if (instr & 0xFC1FFFFF) == 0x03E00008:  # jr $ra
            found_end = addr + 8  # include delay slot
            break

count = (found_end - found_start) // 4
print(f"Function: 0x{found_start:08X} - 0x{found_end:08X} ({count} instructions)")
dump_range(found_start, min(count, 150), "")

# ============================================================
# 2. Full function dump around overlay SH +0x120 at 0x09D32B20
# ============================================================
print("\n\n=== FUNCTION AROUND OVERLAY 0x09D32B20 (sh $s3, 0x120($s1)) ===")
target2 = 0x09D32B20
found_start2 = target2 - 200 * 4
for i in range(1, 200):
    addr = target2 - i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        if (instr & 0xFC1FFFFF) == 0x03E00008:
            found_start2 = addr + 8
            break

found_end2 = target2 + 200 * 4
for i in range(1, 300):
    addr = target2 + i * 4
    off = psp_to_offset(addr)
    if off + 4 <= len(data):
        instr = read_u32(data, off)
        if (instr & 0xFC1FFFFF) == 0x03E00008:
            found_end2 = addr + 8
            break

count2 = (found_end2 - found_start2) // 4
print(f"Function: 0x{found_start2:08X} - 0x{found_end2:08X} ({count2} instructions)")
dump_range(found_start2, min(count2, 150), "")

# ============================================================
# 3. Dump the print settings structure
# ============================================================
print("\n\n=== PRINT SETTINGS STRUCTURE ===")
ps_ptr_addr = 0x09ADB910
ps_ptr_off = psp_to_offset(ps_ptr_addr)
ps_ptr = read_u32(data, ps_ptr_off)
print(f"Print settings pointer at 0x{ps_ptr_addr:08X} = 0x{ps_ptr:08X}")

if 0x08000000 <= ps_ptr <= 0x0A000000:
    ps_off = psp_to_offset(ps_ptr)
    print(f"\nDumping structure at 0x{ps_ptr:08X}:")
    for i in range(0, 0x180, 2):
        off = ps_off + i
        if off + 2 <= len(data):
            val = read_u16(data, off)
            sval = read_s16(data, off)
            addr = ps_ptr + i
            marker = ""
            if i == 0x120: marker = " <-- cursor X"
            elif i == 0x122: marker = " <-- cursor Y"
            elif i == 0x124: marker = " <-- cursor ??"
            elif i == 0x11E: marker = " <-- enable flag?"
            elif i == 0x130: marker = " <-- ??"
            elif i == 0x131: marker = " <-- ??"
            if marker or (val != 0 and i < 0x180):
                print(f"  +0x{i:03X} (0x{addr:08X}): 0x{val:04X} ({sval:6d}){marker}")

# ============================================================
# 4. Search for code that calls print/render functions with
#    player name or position arguments
# ============================================================
print("\n\n=== SEARCHING FOR JAL TO TEXT RENDERING FUNCTIONS FROM OVERLAY ===")
# Known text rendering functions:
# 0x088EAA64 - print function (already found 0 calls from overlay)
# 0x088E7008 - set cursor X/Y (small function)
# Let's find what functions the overlay DOES call for text rendering
# by searching for JAL to 0x088Exxxx range from overlay

overlay_start = psp_to_offset(0x09C57C80)
overlay_end = min(psp_to_offset(0x09DC0000), len(data) - 4)

jal_targets = {}
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if (instr >> 26) == 0x03:  # JAL
        target = (instr & 0x03FFFFFF) << 2
        if 0x088E0000 <= target <= 0x088F0000:  # text rendering area
            psp = off - MEM_OFFSET + PSP_BASE
            if target not in jal_targets:
                jal_targets[target] = []
            jal_targets[target].append(psp)

print(f"Overlay calls to 0x088E-088F range ({len(jal_targets)} unique targets):")
for target in sorted(jal_targets.keys()):
    callers = jal_targets[target]
    print(f"  0x{target:08X}: called from {len(callers)} places", end="")
    if len(callers) <= 5:
        print(f" [{', '.join(f'0x{c:08X}' for c in callers)}]")
    else:
        print(f" [{', '.join(f'0x{c:08X}' for c in callers[:3])}...]")

# ============================================================
# 5. The eboot function at 0x088E7008 is the cursor setter.
#    Find all calls to it from overlay.
# ============================================================
print("\n\n=== CALLS TO CURSOR SETTER (0x088E7008) FROM OVERLAY ===")
jal_cursor = 0x0C000000 | (0x088E7008 >> 2)
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    if instr == jal_cursor:
        psp = off - MEM_OFFSET + PSP_BASE
        print(f"\n  JAL 0x088E7008 at 0x{psp:08X}:")
        dump_range(psp - 10*4, 14)

# Also check the init function at 0x088E6F20 (zeros cursor)
jal_init = 0x0C000000 | (0x088E6F08 >> 2)  # function probably starts a bit before
# Actually 0x088E6F20 is inside a function. Let's find calls to 0x088E6F08 or nearby
print("\n\n=== CALLS TO CURSOR INIT AREA (0x088E6Exx-088E6Fxx) ===")
for func_start in range(0x088E6E00, 0x088E7000, 4):
    jal_test = 0x0C000000 | (func_start >> 2)
    for off in range(overlay_start, overlay_end, 4):
        instr = read_u32(data, off)
        if instr == jal_test:
            psp = off - MEM_OFFSET + PSP_BASE
            print(f"  JAL 0x{func_start:08X} at overlay 0x{psp:08X}")

# ============================================================
# 6. Search for SH to +0x0120 with ANY register in overlay
#    (broader than just +0x120 from print struct)
# ============================================================
print("\n\n=== ALL SH INSTRUCTIONS NEAR +0x0120 IN OVERLAY ===")
for off in range(overlay_start, overlay_end, 4):
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x29:  # SH
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            simm = imm - 0x10000
        else:
            simm = imm
        # Look for offsets that could be cursor-related
        if imm in (0x0120, 0x0122, 0x0124, 0x00F2, 0x00F0):
            rs = (instr >> 21) & 0x1F
            rt = (instr >> 16) & 0x1F
            psp = off - MEM_OFFSET + PSP_BASE
            print(f"  0x{psp:08X}: sh {REG_NAMES.get(rt, f'${rt}')}, 0x{imm:04X}({REG_NAMES.get(rs, f'${rs}')})")

# ============================================================
# 7. Look for addiu patterns setting position values before JAL
#    in the overlay near the player name reference locations
# ============================================================
print("\n\n=== CONTEXT AROUND PLAYER NAME REFS IN OVERLAY ===")
player_refs = [0x09C6137C, 0x09C65A74, 0x09C66414, 0x09C66810, 0x09C66C00]
for ref in player_refs:
    print(f"\n--- Around 0x{ref:08X} ---")
    dump_range(ref - 20*4, 50)

print("\nDone!")
