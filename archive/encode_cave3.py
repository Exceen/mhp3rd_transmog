#!/usr/bin/env python3
"""Encode fixed cave that reads 0x09BB5CA7 directly (not via wrong pointer chain)."""

CAVE_BASE = 0x08800100
FLAG_ADDR = 0x088000F0
HOOK_ADDR = 0x08901168
RETURN_ADDR = 0x0890116C
DISPLACED = 0x27BDFFE0  # addiu $sp, $sp, -32

def j(target):
    return 0x08000000 | ((target >> 2) & 0x03FFFFFF)

# 0x09BB5CA7: lui 0x09BB + offset 0x5CA7 (positive, fits signed 16-bit)
code = [
    (0x27BDFFF8, "addiu $sp, $sp, -8"),
    (0xAFA20000, "sw $v0, 0($sp)"),
    (0xAFA10004, "sw $at, 4($sp)"),
    # Read state byte directly at 0x09BB5CA7
    (0x3C0109BB, "lui $at, 0x09BB"),
    (0x90215CA7, "lbu $at, 0x5CA7($at)    ; state = *(0x09BB5CA7)"),
    # Compute (1 << state) & 0x0470
    (0x24020001, "addiu $v0, $zero, 1"),
    (0x00221004, "sllv $v0, $v0, $at       ; v0 = 1 << state"),
    (0x30420470, "andi $v0, $v0, 0x0470    ; mask active states 4,5,6,10"),
    (0x0002102B, "sltu $v0, $zero, $v0     ; v0 = (v0!=0) ? 1 : 0"),
    # Write flag
    (0x3C010880, "lui $at, 0x0880"),
    (0xA02200F0, f"sb $v0, 0xF0($at)       ; *(0x{FLAG_ADDR:08X}) = flag"),
    # Restore
    (0x8FA20000, "lw $v0, 0($sp)"),
    (0x8FA10004, "lw $at, 4($sp)"),
    (0x27BD0008, "addiu $sp, $sp, 8"),
    # Displaced + return
    (DISPLACED,  "addiu $sp, $sp, -32      ; displaced from sprite render"),
    (j(RETURN_ADDR), f"j 0x{RETURN_ADDR:08X}"),
    (0x00000000, "nop"),
]

print("=== ASSEMBLY ===")
for i, (instr, comment) in enumerate(code):
    addr = CAVE_BASE + i*4
    print(f"  0x{addr:08X}: {instr:08X}  {comment}")

print(f"\n=== CWCHEAT ===")
hook_instr = j(CAVE_BASE)
flag_cw = FLAG_ADDR - 0x08800000

for i, (instr, comment) in enumerate(code):
    cw = (CAVE_BASE + i*4) - 0x08800000
    print(f"_L 0x2{cw:07X} 0x{instr:08X}")
print(f"_L 0x2{(HOOK_ADDR-0x08800000):07X} 0x{hook_instr:08X}")
print(f"_L 0x215902B0 0x07D007D0")
print(f"_L 0xD{flag_cw:07X} 0x20100000")
print(f"_L 0x215902B0 0x0016013E")

print(f"\nTotal: {len(code)+4} lines, cave at 0x{CAVE_BASE:08X}-0x{CAVE_BASE+len(code)*4-4:08X}")
