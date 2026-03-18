#!/usr/bin/env python3
"""Fixed cave: relocated to 0x08800200, delay slot NOP'd, two displaced instructions."""

CAVE_BASE = 0x08800200
FLAG_ADDR = 0x088001F0
CTR_ADDR  = 0x088001F4
HOOK_ADDR = 0x08901168
RETURN_ADDR = 0x08901170  # THIRD instruction (skip both displaced)

def j_enc(target):
    return 0x08000000 | ((target >> 2) & 0x03FFFFFF)

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

# Read state
emit(0x3C0209BB, "lui $v0, 0x09BB")
emit(0x90425CA7, "lbu $v0, 0x5CA7($v0)     ; state = *(0x09BB5CA7)")

# Compute mask
emit(0x24010001, "addiu $at, $zero, 1")
emit(0x00410804, "sllv $at, $at, $v0        ; 1 << state")
emit(0x30210470, "andi $at, $at, 0x0470     ; active mask")

# Base address for flag/counter
emit(0x3C020880, "lui $v0, 0x0880")

# Branch on active
active_idx = len(code)
emit(None, "bne $at, $zero, .active")
emit(0x00000000, "nop")

# NOT ACTIVE: check counter
emit(0x904101F4, "lbu $at, 0x1F4($v0)      ; counter")
clear_idx = len(code)
emit(None, "beq $at, $zero, .clear")
emit(0x00000000, "nop")
# Decrement counter
emit(0x2421FFFF, "addiu $at, $at, -1")
done_j1 = len(code)
emit(None, "j .done")
emit(0xA04101F4, "sb $at, 0x1F4($v0)       ; counter-- [delay slot]")

# .clear
clear_label = len(code)
done_j2 = len(code)
emit(None, "j .done")
emit(0xA04001F0, "sb $zero, 0x1F0($v0)     ; flag=0 [delay slot]")

# .active
active_label = len(code)
emit(0x240100FF, "addiu $at, $zero, 0xFF")
emit(0xA04101F4, "sb $at, 0x1F4($v0)       ; counter=255")
emit(0xA04101F0, "sb $at, 0x1F0($v0)       ; flag=255")

# .done
done_label = len(code)
emit(0x8FA20000, "lw $v0, 0($sp)")
emit(0x8FA10004, "lw $at, 4($sp)")
emit(0x27BD0008, "addiu $sp, $sp, 8")
# Two displaced instructions
emit(0x27BDFFE0, "addiu $sp, $sp, -32       ; displaced #1 from 0x08901168")
emit(0xAFBF0010, "sw $ra, 16($sp)           ; displaced #2 from 0x0890116C")
emit(j_enc(RETURN_ADDR), f"j 0x{RETURN_ADDR:08X}")
emit(0x00000000, "nop")

# Fix branches
def br_off(src, tgt):
    return (CAVE_BASE + tgt*4 - (CAVE_BASE + src*4 + 4)) // 4

off = br_off(active_idx, active_label)
code[active_idx] = (CAVE_BASE + active_idx*4, 0x14200000 | (off & 0xFFFF),
    f"bne $at, $zero, .active (off={off})")

off = br_off(clear_idx, clear_label)
code[clear_idx] = (CAVE_BASE + clear_idx*4, 0x10200000 | (off & 0xFFFF),
    f"beq $at, $zero, .clear (off={off})")

done_pc = CAVE_BASE + done_label*4
code[done_j1] = (CAVE_BASE + done_j1*4, j_enc(done_pc), f"j .done (0x{done_pc:08X})")
code[done_j2] = (CAVE_BASE + done_j2*4, j_enc(done_pc), f"j .done (0x{done_pc:08X})")

# Print
print("=== ASSEMBLY ===")
for addr, instr, comment in code:
    print(f"  0x{addr:08X}: {instr:08X}  {comment}")

print(f"\n=== CWCHEAT ===")
for addr, instr, _ in code:
    cw = addr - 0x08800000
    print(f"_L 0x2{cw:07X} 0x{instr:08X}")

# Hook: j cave + NOP delay slot
hook_j = j_enc(CAVE_BASE)
print(f"_L 0x2{(HOOK_ADDR - 0x08800000):07X} 0x{hook_j:08X}")
print(f"_L 0x2{(0x0890116C - 0x08800000):07X} 0x00000000")

# D-type
flag_cw = FLAG_ADDR - 0x08800000
print(f"_L 0x215902B0 0x07D007D0")
print(f"_L 0xD{flag_cw:07X} 0x20100000")
print(f"_L 0x215902B0 0x0016013E")

print(f"\nTotal: {len(code)+5} lines")
print(f"Cave: 0x{CAVE_BASE:08X}-0x{CAVE_BASE+(len(code)-1)*4:08X}")

# Verify
print(f"\n=== VERIFY ===")
for addr, instr, comment in code:
    if instr >> 26 in (4, 5):
        off = instr & 0xFFFF
        if off >= 0x8000: off -= 0x10000
        tgt = addr + 4 + off*4
        print(f"  0x{addr:08X} branch → 0x{tgt:08X}  {comment}")
    elif instr >> 26 == 2:
        tgt = (instr & 0x03FFFFFF) << 2 | (addr & 0xF0000000)
        print(f"  0x{addr:08X} jump   → 0x{tgt:08X}  {comment}")
