#!/usr/bin/env python3
"""Encode standalone map flag code cave hooking sprite render 0x08901168."""

# Cave at 0x08800100, flag at 0x088000F0
CAVE_BASE = 0x08800100
FLAG_ADDR = 0x088000F0
HOOK_ADDR = 0x08901168  # sprite render function start
RETURN_ADDR = 0x0890116C  # second instruction of sprite render
DISPLACED = 0x27BDFFE0  # addiu $sp, $sp, -32

def j(target):
    return 0x08000000 | ((target >> 2) & 0x03FFFFFF)

code = [
    (0x27BDFFF8, "addiu $sp, $sp, -8       ; save frame"),
    (0xAFA20000, "sw $v0, 0($sp)           ; save $v0"),
    (0xAFA10004, "sw $at, 4($sp)           ; save $at"),
    (0x3C0109BB, "lui $at, 0x09BB"),
    (0x8C217A80, "lw $at, 0x7A80($at)      ; ptr1 = *(0x09BB7A80)"),
    (0x10200009, "beq $at, $zero, .store    ; null check → flag=0"),
    (0x24020000, "addiu $v0, $zero, 0       ; v0=0 default [delay slot]"),
    (0x8C210008, "lw $at, 8($at)            ; ptr2 = *(ptr1+8)"),
    (0x10200006, "beq $at, $zero, .store    ; null check → flag=0"),
    (0x00000000, "nop"),
    (0x90210062, "lbu $at, 98($at)          ; state = byte@(ptr2+98)"),
    (0x24020001, "addiu $v0, $zero, 1       ; v0 = 1"),
    (0x00221004, "sllv $v0, $v0, $at        ; v0 = 1 << state"),
    (0x30420470, "andi $v0, $v0, 0x0470     ; v0 &= 0x0470 (states 4,5,6,10)"),
    (0x0002102B, "sltu $v0, $zero, $v0      ; v0 = (v0 != 0) ? 1 : 0"),
    # .store:
    (0x3C010880, "lui $at, 0x0880"),
    (0xA02200F0, f"sb $v0, 0x00F0($at)      ; *(0x{FLAG_ADDR:08X}) = flag"),
    (0x8FA20000, "lw $v0, 0($sp)            ; restore $v0"),
    (0x8FA10004, "lw $at, 4($sp)            ; restore $at"),
    (0x27BD0008, "addiu $sp, $sp, 8         ; restore stack"),
    (DISPLACED,  f"addiu $sp, $sp, -32      ; displaced from 0x{HOOK_ADDR:08X}"),
    (j(RETURN_ADDR), f"j 0x{RETURN_ADDR:08X}                ; return to function body"),
    (0x00000000, "nop                        ; delay slot"),
]

# Verify branch offsets
# beq at index 5 (addr CAVE_BASE+5*4=0x08800114), target .store at index 15 (0x0880013C)
beq1_addr = CAVE_BASE + 5*4
store_addr = CAVE_BASE + 15*4
offset1 = (store_addr - (beq1_addr + 4)) // 4
assert offset1 == 9, f"beq1 offset should be 9, got {offset1}"
assert code[5][0] == 0x10200009, f"beq1 encoding wrong"

# beq at index 8 (addr CAVE_BASE+8*4=0x08800120), target .store at 0x0880013C
beq2_addr = CAVE_BASE + 8*4
offset2 = (store_addr - (beq2_addr + 4)) // 4
assert offset2 == 6, f"beq2 offset should be 6, got {offset2}"
assert code[8][0] == 0x10200006, f"beq2 encoding wrong"

print("=== ASSEMBLY LISTING ===")
for i, (instr, comment) in enumerate(code):
    addr = CAVE_BASE + i*4
    print(f"  0x{addr:08X}: {instr:08X}  ; {comment}")

print(f"\n=== CWCHEAT CODE ===")
print(f"_C1  Map Show - GameState Flag Cave")
print(f"; Hooks sprite render 0x{HOOK_ADDR:08X} to compute selector state flag.")
print(f"; Follows pointer chain, checks (1<<state)&0x0470 for active states 4,5,6,10.")
print(f"; Writes 1/0 to 0x{FLAG_ADDR:08X}. D-type shows map when flag != 0.")

# Cave code
for i, (instr, comment) in enumerate(code):
    cw_offset = (CAVE_BASE + i*4) - 0x08800000
    print(f"_L 0x2{cw_offset:07X} 0x{instr:08X}")

# Hook: replace first instruction of sprite render
hook_cw = HOOK_ADDR - 0x08800000
hook_instr = j(CAVE_BASE)
print(f"; Hook: 0x{HOOK_ADDR:08X} → j 0x{CAVE_BASE:08X}")
print(f"_L 0x2{hook_cw:07X} 0x{hook_instr:08X}")

# D-type conditional
flag_cw = FLAG_ADDR - 0x08800000
print(f"; Map visibility: hide by default, show when flag at 0x{FLAG_ADDR:08X} != 0")
print(f"_L 0x215902B0 0x07D007D0")
print(f"_L 0xD{flag_cw:07X} 0x20100000")
print(f"_L 0x215902B0 0x0016013E")

# Summary
print(f"\n=== SUMMARY ===")
print(f"Cave: {len(code)} instructions at 0x{CAVE_BASE:08X}-0x{CAVE_BASE+len(code)*4-4:08X}")
print(f"Flag: 0x{FLAG_ADDR:08X} (CW 0x{flag_cw:07X})")
print(f"Hook: 0x{HOOK_ADDR:08X} displaced '{DISPLACED:08X}' → j 0x{CAVE_BASE:08X} ({hook_instr:08X})")
print(f"Return: j 0x{RETURN_ADDR:08X}")
print(f"Total CWCheat lines: {len(code) + 1 + 3} (cave + hook + D-type)")
