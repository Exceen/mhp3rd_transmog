#!/usr/bin/env python3
"""Cave with latch/counter to debounce the cycling state byte.
When active: flag=0xFF, counter=255
When not active: counter--, clear flag only when counter==0
"""

CAVE_BASE = 0x08800100
FLAG_ADDR = 0x088000F0  # 1 byte flag
CTR_ADDR  = 0x088000F4  # 1 byte counter
HOOK_ADDR = 0x08901168
RETURN_ADDR = 0x0890116C
DISPLACED = 0x27BDFFE0

def j_enc(target):
    return 0x08000000 | ((target >> 2) & 0x03FFFFFF)

# Registers: $v0=2, $at=1, $zero=0, $sp=29
# Strategy: read state into $v0, compute mask into $at, then use $v0 as base addr

code = []
pc = CAVE_BASE

def emit(instr, comment):
    global pc
    code.append((pc, instr, comment))
    pc += 4

# Save
emit(0x27BDFFF8, "addiu $sp, $sp, -8")
emit(0xAFA20000, "sw $v0, 0($sp)")
emit(0xAFA10004, "sw $at, 4($sp)")

# Read state byte at 0x09BB5CA7
emit(0x3C0209BB, "lui $v0, 0x09BB")
emit(0x90425CA7, "lbu $v0, 0x5CA7($v0)     ; state = *(0x09BB5CA7)")

# Compute (1 << state) & 0x0470
emit(0x24010001, "addiu $at, $zero, 1")
emit(0x00410804, "sllv $at, $at, $v0        ; $at = 1 << state")
emit(0x30210470, "andi $at, $at, 0x0470     ; mask active states 4,5,6,10")

# Load base for flag/counter
emit(0x3C020880, "lui $v0, 0x0880           ; $v0 = 0x08800000")

# Branch: active or not?
# bne $at, $zero, .active
active_branch_idx = len(code)
emit(None, "bne $at, $zero, .active")  # placeholder
emit(0x00000000, "nop")

# --- NOT ACTIVE path ---
emit(0x904100F4, "lbu $at, 0xF4($v0)       ; $at = counter")
# beq $at, $zero, .clear
clear_branch_idx = len(code)
emit(None, "beq $at, $zero, .clear")  # placeholder
emit(0x00000000, "nop")
# counter > 0: decrement and store
emit(0x2421FFFF, "addiu $at, $at, -1        ; counter--")
# j .done with sb in delay slot
done_j1_idx = len(code)
emit(None, "j .done")  # placeholder
emit(0xA04100F4, "sb $at, 0xF4($v0)         ; store counter [delay slot]")

# --- .clear: counter was 0, clear flag ---
clear_label = len(code)
# j .done with sb zero in delay slot
done_j2_idx = len(code)
emit(None, "j .done")  # placeholder
emit(0xA04000F0, "sb $zero, 0xF0($v0)       ; flag = 0 [delay slot]")

# --- .active: set counter=255, flag=255 ---
active_label = len(code)
emit(0x240100FF, "addiu $at, $zero, 0xFF    ; $at = 255")
emit(0xA04100F4, "sb $at, 0xF4($v0)         ; counter = 255")
emit(0xA04100F0, "sb $at, 0xF0($v0)         ; flag = 255 (non-zero)")

# --- .done: restore and return ---
done_label = len(code)
emit(0x8FA20000, "lw $v0, 0($sp)")
emit(0x8FA10004, "lw $at, 4($sp)")
emit(0x27BD0008, "addiu $sp, $sp, 8")
emit(DISPLACED,  "addiu $sp, $sp, -32       ; displaced from 0x08901168")
emit(j_enc(RETURN_ADDR), f"j 0x{RETURN_ADDR:08X}")
emit(0x00000000, "nop")

# Fix up branches
def branch_offset(src_idx, tgt_idx):
    src_pc = CAVE_BASE + src_idx * 4
    tgt_pc = CAVE_BASE + tgt_idx * 4
    return (tgt_pc - (src_pc + 4)) // 4

# bne $at, $zero, .active
off = branch_offset(active_branch_idx, active_label)
code[active_branch_idx] = (CAVE_BASE + active_branch_idx*4,
    0x14200000 | (off & 0xFFFF), f"bne $at, $zero, .active (off={off})")

# beq $at, $zero, .clear
off = branch_offset(clear_branch_idx, clear_label)
code[clear_branch_idx] = (CAVE_BASE + clear_branch_idx*4,
    0x10200000 | (off & 0xFFFF), f"beq $at, $zero, .clear (off={off})")

# j .done (from not-active decrement path)
done_pc = CAVE_BASE + done_label * 4
code[done_j1_idx] = (CAVE_BASE + done_j1_idx*4,
    j_enc(done_pc), f"j .done (0x{done_pc:08X})")

# j .done (from clear path)
code[done_j2_idx] = (CAVE_BASE + done_j2_idx*4,
    j_enc(done_pc), f"j .done (0x{done_pc:08X})")

# Print
print("=== ASSEMBLY ===")
for addr, instr, comment in code:
    print(f"  0x{addr:08X}: {instr:08X}  {comment}")

print(f"\n=== CWCHEAT ===")
print(f"_C1  Map Show - GameState Latch Cave")
print(f"; Hooks sprite render 0x{HOOK_ADDR:08X}. Reads state at 0x09BB5CA7.")
print(f"; Active (states 4,5,6,10): flag=1, counter=255.")
print(f"; Not active: counter--, flag=0 only when counter reaches 0.")
print(f"; Debounces the cycling state byte for stable map visibility.")

for addr, instr, comment in code:
    cw = addr - 0x08800000
    print(f"_L 0x2{cw:07X} 0x{instr:08X}")

hook_instr = j_enc(CAVE_BASE)
hook_cw = HOOK_ADDR - 0x08800000
print(f"_L 0x2{hook_cw:07X} 0x{hook_instr:08X}")

flag_cw = FLAG_ADDR - 0x08800000
print(f"_L 0x215902B0 0x07D007D0")
print(f"_L 0xD{flag_cw:07X} 0x20100000")
print(f"_L 0x215902B0 0x0016013E")

print(f"\nTotal: {len(code)+4} lines")
print(f"Cave: 0x{CAVE_BASE:08X}-0x{CAVE_BASE+(len(code)-1)*4:08X} ({len(code)} instructions)")

# Verify branches
print(f"\n=== BRANCH VERIFICATION ===")
for i, (addr, instr, comment) in enumerate(code):
    if instr is not None and (instr >> 26) in (4, 5):  # beq/bne
        off = instr & 0xFFFF
        if off >= 0x8000: off -= 0x10000
        target = addr + 4 + off * 4
        print(f"  0x{addr:08X}: {comment} → target 0x{target:08X}")
    elif instr is not None and (instr >> 26) == 2:  # j
        target = (instr & 0x03FFFFFF) << 2 | (addr & 0xF0000000)
        print(f"  0x{addr:08X}: {comment} → target 0x{target:08X}")
