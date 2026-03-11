#!/usr/bin/env python3
"""Encode the map flag code cave as CWCheat lines."""

import struct

def encode_r(op, rs, rt, rd, shamt, funct):
    return (op << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct

def encode_i(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)

def encode_j(op, target):
    return (op << 26) | ((target >> 2) & 0x03FFFFFF)

# Register numbers
zero, at, v0, v1 = 0, 1, 2, 3
a0, a1, a2, a3 = 4, 5, 6, 7
t0, t1, t2, t3, t4, t5, t6, t7 = 8, 9, 10, 11, 12, 13, 14, 15
s0, s1, s2, s3, s4, s5, s6, s7 = 16, 17, 18, 19, 20, 21, 22, 23
t8, t9 = 24, 25
sp, fp, ra = 29, 30, 31

NOP = 0x00000000

def beq(rs, rt, offset):
    """offset is in instructions (signed)"""
    return encode_i(4, rs, rt, offset & 0xFFFF)

def bne(rs, rt, offset):
    return encode_i(5, rs, rt, offset & 0xFFFF)

def lui(rt, imm):
    return encode_i(15, 0, rt, imm)

def lw(rt, offset, base):
    return encode_i(0x23, base, rt, offset & 0xFFFF)

def sw(rt, offset, base):
    return encode_i(0x2B, base, rt, offset & 0xFFFF)

def lbu(rt, offset, base):
    return encode_i(0x24, base, rt, offset & 0xFFFF)

def sb(rt, offset, base):
    return encode_i(0x28, base, rt, offset & 0xFFFF)

def addiu(rt, rs, imm):
    return encode_i(9, rs, rt, imm & 0xFFFF)

def sltiu(rt, rs, imm):
    return encode_i(0x0B, rs, rt, imm & 0xFFFF)

def xori(rt, rs, imm):
    return encode_i(0x0E, rs, rt, imm)

def andi(rt, rs, imm):
    return encode_i(0x0C, rs, rt, imm)

def addu(rd, rs, rt):
    return encode_r(0, rs, rt, rd, 0, 0x21)

def sllv(rd, rt, rs):
    return encode_r(0, rs, rt, rd, 0, 0x04)

def j(target):
    return encode_j(2, target)

def jal(target):
    return encode_j(3, target)

# Code cave at 0x08800C00
# Flag written to 0x08800BF0
CAVE_BASE = 0x08800C00
FLAG_ADDR = 0x08800BF0

code = []
labels = {}
pc = CAVE_BASE

def emit(instr, comment=""):
    global pc
    code.append((pc, instr, comment))
    pc += 4

def current_offset():
    return (pc - CAVE_BASE) // 4

# Save $v0 and $at (minimal register usage)
emit(addiu(sp, sp, -8), "save stack frame")
emit(sw(v0, 0, sp), "save $v0")
emit(sw(at, 4, sp), "save $at")

# Follow pointer chain
emit(lui(at, 0x09BB), "$at = 0x09BB0000")
emit(lw(at, 0x7A80, at), "$at = *(0x09BB7A80) = ptr1")
# beq $at, $zero, .store (branch offset calculated later)
store_beq1_idx = len(code)
emit(0, "beq $at, $zero, .store (placeholder)")
emit(addiu(v0, zero, 0), "$v0 = 0 (default: inactive) [delay slot]")

emit(lw(at, 8, at), "$at = *(ptr1+8) = ptr2")
# beq $at, $zero, .store
store_beq2_idx = len(code)
emit(0, "beq $at, $zero, .store (placeholder)")
emit(NOP, "nop [delay slot]")

emit(lbu(at, 98, at), "$at = state byte @(ptr2+98)")

# Compute (1 << state) & 0x0470
# Use $v0 as temp for shift
emit(addiu(v0, zero, 1), "$v0 = 1")
emit(sllv(v0, v0, at), "$v0 = 1 << state")
emit(andi(v0, v0, 0x0470), "$v0 &= 0x0470 (active states mask)")
# Now v0 != 0 if active. We want v0 = 1 if active, 0 if not.
# sltu $v0, $zero, $v0 : v0 = (0 < v0) = (v0 != 0)
emit(encode_r(0, zero, v0, v0, 0, 0x2B), "$v0 = ($v0 != 0) ? 1 : 0 [sltu]")

# .store label
labels['store'] = len(code)
emit(lui(at, 0x0880), "$at = 0x08800000")
emit(sb(v0, 0x0BF0 & 0xFFFF, at), "*(0x08800BF0) = flag")

# Restore
emit(lw(v0, 0, sp), "restore $v0")
emit(lw(at, 4, sp), "restore $at")
emit(addiu(sp, sp, 8), "restore stack")

# Jump to original return target
emit(j(0x09D30F18), "j 0x09D30F18 (original return)")
emit(NOP, "nop [delay slot]")

# Fix up branch targets
store_pc = CAVE_BASE + labels['store'] * 4

# beq1: at store_beq1_idx, branch to .store
beq1_pc = CAVE_BASE + store_beq1_idx * 4
beq1_offset = (store_pc - (beq1_pc + 4)) // 4
code[store_beq1_idx] = (beq1_pc, beq(at, zero, beq1_offset), f"beq $at, $zero, .store (offset={beq1_offset})")

# beq2: at store_beq2_idx, branch to .store
beq2_pc = CAVE_BASE + store_beq2_idx * 4
beq2_offset = (store_pc - (beq2_pc + 4)) // 4
code[store_beq2_idx] = (beq2_pc, beq(at, zero, beq2_offset), f"beq $at, $zero, .store (offset={beq2_offset})")

# Print assembly listing
print("=== CODE CAVE ASSEMBLY ===")
for addr, instr, comment in code:
    cw_addr = addr - 0x08800000
    print(f"  0x{addr:08X}: {instr:08X}  ; {comment}")

# Generate CWCheat lines
print("\n=== CWCHEAT LINES ===")
print("_C0 Map Show - Code Cave (state flag writer)")
print("; Code cave at 0x08800C00: reads selector state via pointer chain,")
print("; writes 1/0 flag to 0x08800BF0. Hooks transmog input handler exit.")
for addr, instr, comment in code:
    cw_addr = addr - 0x08800000
    print(f"_L 0x2{cw_addr:07X} 0x{instr:08X}")

# Hook: change the j target in transmog input handler
# Current: 0x088009C8 = j 0x09D30F18 (0x0A74C3C6)
# New:     0x088009C8 = j 0x08800C00
hook_instr = j(0x08800C00)
hook_cw = 0x088009C8 - 0x08800000
print(f"; Hook: redirect input handler exit to cave")
print(f"_L 0x2{hook_cw:07X} 0x{hook_instr:08X}")

# D-type conditional on the flag
print()
print("_C0 Map Show - GameState via Cave")
print("; Uses flag at 0x08800BF0 written by the code cave above")
print("; D-type IfNotEqual(0) on 8-bit: show map when flag == 1")
flag_cw = FLAG_ADDR - 0x08800000
print(f"_L 0x215902B0 0x07D007D0")
print(f"_L 0xD{flag_cw:07X} 0x20100000")
print(f"_L 0x215902B0 0x0016013E")

# Verify encoding
print("\n=== VERIFICATION ===")
print(f"Cave: {len(code)} instructions, 0x{CAVE_BASE:08X}-0x{CAVE_BASE + len(code)*4 - 4:08X}")
print(f"Flag at: 0x{FLAG_ADDR:08X} (CW 0x{flag_cw:07X})")
print(f"Hook at: 0x088009C8 (CW 0x{hook_cw:07X})")
print(f"Hook instruction: 0x{hook_instr:08X} = j 0x{CAVE_BASE:08X}")

# Verify branch offsets
for idx, label in [(store_beq1_idx, 'store'), (store_beq2_idx, 'store')]:
    src_pc = CAVE_BASE + idx * 4
    tgt_pc = CAVE_BASE + labels[label] * 4
    offset = (tgt_pc - (src_pc + 4)) // 4
    actual_target = src_pc + 4 + offset * 4
    print(f"  Branch at 0x{src_pc:08X} -> 0x{tgt_pc:08X} (offset={offset}): target=0x{actual_target:08X} {'OK' if actual_target == tgt_pc else 'WRONG'}")
