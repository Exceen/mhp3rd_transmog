#!/usr/bin/env python3
"""Generate CWCheat codes for scaling MHP3rd item selector wheel elements.

Hooks call #6 (jal 0x08900BF0 at 0x09D60EA8) in the item selector render
function 0x09D60D88. Scales the 36-byte sprite entries in-place before
rendering via a code cave with a scale subroutine.

Sprite entry format (36 bytes):
  +0:  v0_x (s16) — quad vertex 0 X (size)
  +2:  v0_y (s16) — quad vertex 0 Y (size)
  +4:  v1_x (s16) — quad vertex 1 X (size)
  +6:  v1_y (s16) — quad vertex 1 Y (size)
  +8..+23: texture coords, other data (NOT modified)
  +24: X (s16) — screen position relative to batch offset
  +26: Y (s16) — screen position relative to batch offset

Scaling modifies v0/v1 (sprite size) and X/Y (element position) so elements
get smaller AND closer together. The batch offset ($t1/$t2 from position
codes) anchors the scaled result on screen.

Memory layout:
  0x097F0800: main code cave (hook target)
  0x097F0A00: scale subroutine

Replaces "Hide Buttons/Elements B" when using hide+scale variants.
Compatible with existing ItemSel position codes (Text+BG, Wheel X/Y).
"""

# --- Constants ---
CW_BASE = 0x08800000
CAVE_BASE = 0x097F0800
SCALE_SUB = 0x097F0A00
HOOK_ADDR = 0x09D60EA8       # jal site in overlay render function
OVERLAY_GUARD = 0x09C57C90   # sentinel for overlay-loaded check
OVERLAY_VAL = 0x5FA0
BATCH_RENDER = 0x08900BF0

# --- MIPS registers ---
ZERO, A0, A1, A2, A3 = 0, 4, 5, 6, 7
T0, T1, T2, T3, T4, T5, T6 = 8, 9, 10, 11, 12, 13, 14
S4, S5, S6, S7 = 20, 21, 22, 23
SP, RA = 29, 31
NOP = 0x00000000


# --- MIPS instruction encoders ---
def addiu(rt, rs, imm):
    return 0x24000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)

def li(rt, imm):
    return addiu(rt, ZERO, imm)

def sw(rt, off, base):
    return 0xAC000000 | (base << 21) | (rt << 16) | (off & 0xFFFF)

def lw(rt, off, base):
    return 0x8C000000 | (base << 21) | (rt << 16) | (off & 0xFFFF)

def lh(rt, off, base):
    return 0x84000000 | (base << 21) | (rt << 16) | (off & 0xFFFF)

def sh(rt, off, base):
    return 0xA4000000 | (base << 21) | (rt << 16) | (off & 0xFFFF)

def move(rd, rs):
    return 0x00000021 | (rs << 21) | (rd << 11)  # addu rd, rs, $zero

def sra(rd, rt, sa):
    return 0x00000003 | (rt << 16) | (rd << 11) | (sa << 6)

def subu(rd, rs, rt):
    return 0x00000023 | (rs << 21) | (rt << 16) | (rd << 11)

def beq(rs, rt, offset):
    return 0x10000000 | (rs << 21) | (rt << 16) | (offset & 0xFFFF)

def bne(rs, rt, offset):
    return 0x14000000 | (rs << 21) | (rt << 16) | (offset & 0xFFFF)

def jal(target):
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)

def jr(rs):
    return 0x00000008 | (rs << 21)


# --- CWCheat formatting ---
def cw_32(addr, val):
    off = addr - CW_BASE
    return f"_L 0x2{off:07X} 0x{val:08X}"

def cw_guard():
    """Overlay guard D-type (28-bit offset, 16-bit if-equal)."""
    off = OVERLAY_GUARD - CW_BASE
    return f"_L 0xD{off:07X} 0x0000{OVERLAY_VAL:04X}"

def cw_hook():
    off = HOOK_ADDR - CW_BASE
    return cw_32(HOOK_ADDR, jal(CAVE_BASE))


# --- Scale subroutine generators ---
# Input: $a0 = entry table ptr, $a1 = count
# Clobbers: $t4, $t5 (50%) or $t4, $t5, $t6 (75%)
# Scales v0_x(+0), v0_y(+2), v1_x(+4), v1_y(+6), X(+24), Y(+26) in-place

FIELD_OFFSETS = [0, 2, 4, 6, 24, 26]

def gen_scale_sub_50():
    """50%: field = field >> 1 (arithmetic shift right)"""
    code = []
    # beq $a1, $zero, .ret  (skip over loop to jr $ra)
    # Loop body: 6 fields × 3 instrs = 18, plus 4 loop control = 22 instrs
    # .ret is at instruction 24 from here
    code.append(beq(A1, ZERO, 22))  # PC+4 is instr 1; +22 = instr 23 = .ret?
    # Wait: beq at index 0. PC+4 is after index 0. offset=22 means target = index 1+22 = index 23.
    # But .ret (jr $ra) is at index 24. Let me recount.
    # 0: beq
    # 1: move (delay slot)
    # 2..19: 6 fields × 3 = 18 instructions
    # 20: addiu $a1, -1
    # 21: addiu $t4, +36
    # 22: bne
    # 23: nop
    # 24: jr $ra
    # 25: nop
    # beq offset: target is index 24. From PC+4 (= index 1), offset = 24-1 = 23.
    code[0] = beq(A1, ZERO, 23)
    code.append(move(T4, A0))       # delay slot
    for off in FIELD_OFFSETS:
        code.append(lh(T5, off, T4))
        code.append(sra(T5, T5, 1))
        code.append(sh(T5, off, T4))
    code.append(addiu(A1, A1, (-1) & 0xFFFF))
    code.append(addiu(T4, T4, 36))
    # bne $a1, $zero, .loop — .loop is index 2, bne is index 22
    # From PC+4 (= index 23), offset = 2 - 23 = -21
    code.append(bne(A1, ZERO, (-21) & 0xFFFF))
    code.append(NOP)
    code.append(jr(RA))             # .ret
    code.append(NOP)
    assert len(code) == 26
    return code


def gen_scale_sub_75():
    """75%: field = field - (field >> 2)"""
    code = []
    # 0: beq
    # 1: move (delay)
    # 2..25: 6 fields × 4 = 24 instructions
    # 26: addiu -1
    # 27: addiu +36
    # 28: bne
    # 29: nop
    # 30: jr $ra
    # 31: nop
    # beq offset: target index 30, from PC+4 (index 1), offset = 30-1 = 29
    code.append(beq(A1, ZERO, 29))
    code.append(move(T4, A0))
    for off in FIELD_OFFSETS:
        code.append(lh(T5, off, T4))
        code.append(sra(T6, T5, 2))
        code.append(subu(T5, T5, T6))
        code.append(sh(T5, off, T4))
    code.append(addiu(A1, A1, (-1) & 0xFFFF))
    code.append(addiu(T4, T4, 36))
    # bne: index 28, target index 2, offset = 2 - 29 = -27
    code.append(bne(A1, ZERO, (-27) & 0xFFFF))
    code.append(NOP)
    code.append(jr(RA))
    code.append(NOP)
    assert len(code) == 32
    return code


# --- Main cave generators ---

def gen_cave_hide_scale():
    """Main cave: scale all 13 entries, then render in 2 sub-batches
    (hiding elements 6, 11, 12 = square bg, square sprite, L-button).
    Replaces 'Hide Buttons/Elements B'."""
    code = []
    # Prologue
    code.append(addiu(SP, SP, (-0x30) & 0xFFFF))  # allocate stack
    code.append(sw(RA, 0x00, SP))
    code.append(sw(S4, 0x04, SP))
    code.append(sw(S5, 0x08, SP))
    code.append(sw(S6, 0x0C, SP))
    code.append(move(S4, A0))       # save ctx
    code.append(move(S5, A1))       # save table_ptr
    code.append(move(S6, A2))       # save flags
    code.append(sw(T0, 0x14, SP))
    code.append(sw(T1, 0x18, SP))
    code.append(sw(T2, 0x1C, SP))
    code.append(sw(T3, 0x20, SP))

    # Scale all 13 entries in-place
    code.append(move(A0, S5))       # table ptr
    code.append(li(A1, 13))         # total entry count
    code.append(jal(SCALE_SUB))
    code.append(NOP)

    # Sub-batch 1: elements 0-5 (wheel + background), count=6
    code.append(move(A0, S4))
    code.append(move(A1, S5))
    code.append(move(A2, S6))
    code.append(li(A3, 6))
    code.append(lw(T0, 0x14, SP))
    code.append(lw(T1, 0x18, SP))
    code.append(lw(T2, 0x1C, SP))
    code.append(lw(T3, 0x20, SP))
    code.append(jal(BATCH_RENDER))
    code.append(NOP)

    # Sub-batch 2: elements 7-10 (counter bg, counter text, unknown, icon)
    # offset = 7 * 36 = 252 = 0xFC, count=4
    code.append(move(A0, S4))
    code.append(addiu(A1, S5, 0xFC))
    code.append(move(A2, S6))
    code.append(li(A3, 4))
    code.append(lw(T0, 0x14, SP))
    code.append(lw(T1, 0x18, SP))
    code.append(lw(T2, 0x1C, SP))
    code.append(lw(T3, 0x20, SP))
    code.append(jal(BATCH_RENDER))
    code.append(NOP)

    # Skip sub-batch 3 (elements 11-12 = buttons, hidden)

    # Epilogue
    code.append(lw(RA, 0x00, SP))
    code.append(lw(S4, 0x04, SP))
    code.append(lw(S5, 0x08, SP))
    code.append(lw(S6, 0x0C, SP))
    code.append(jr(RA))
    code.append(addiu(SP, SP, 0x30))  # delay slot
    assert len(code) == 42
    return code


def gen_cave_scale_only():
    """Main cave: scale entries and render all (no hiding).
    Preserves all original elements including buttons."""
    code = []
    # Prologue (need $s7 for count)
    code.append(addiu(SP, SP, (-0x28) & 0xFFFF))
    code.append(sw(RA, 0x00, SP))
    code.append(sw(S4, 0x04, SP))
    code.append(sw(S5, 0x08, SP))
    code.append(sw(S6, 0x0C, SP))
    code.append(sw(S7, 0x10, SP))
    code.append(move(S4, A0))       # ctx
    code.append(move(S5, A1))       # table_ptr
    code.append(move(S6, A2))       # flags
    code.append(move(S7, A3))       # count
    code.append(sw(T0, 0x14, SP))
    code.append(sw(T1, 0x18, SP))
    code.append(sw(T2, 0x1C, SP))
    code.append(sw(T3, 0x20, SP))

    # Scale entries
    code.append(move(A0, S5))
    code.append(move(A1, S7))
    code.append(jal(SCALE_SUB))
    code.append(NOP)

    # Render all with original args
    code.append(move(A0, S4))
    code.append(move(A1, S5))
    code.append(move(A2, S6))
    code.append(move(A3, S7))
    code.append(lw(T0, 0x14, SP))
    code.append(lw(T1, 0x18, SP))
    code.append(lw(T2, 0x1C, SP))
    code.append(lw(T3, 0x20, SP))
    code.append(jal(BATCH_RENDER))
    code.append(NOP)

    # Epilogue
    code.append(lw(RA, 0x00, SP))
    code.append(lw(S4, 0x04, SP))
    code.append(lw(S5, 0x08, SP))
    code.append(lw(S6, 0x0C, SP))
    code.append(lw(S7, 0x10, SP))
    code.append(jr(RA))
    code.append(addiu(SP, SP, 0x28))
    assert len(code) == 35
    return code


# --- Code generation ---

def format_code(name, cave_instrs, scale_instrs, max_per_block=30):
    """Format a complete CWCheat code with guard, hook, cave, and scale sub."""
    lines = []

    # Guard + hook (overlay address, needs guard)
    lines.append(cw_guard())
    lines.append(cw_hook())

    # Main cave at CAVE_BASE (regular memory, no guard needed)
    for i, instr in enumerate(cave_instrs):
        lines.append(cw_32(CAVE_BASE + i * 4, instr))

    # Scale subroutine at SCALE_SUB
    for i, instr in enumerate(scale_instrs):
        lines.append(cw_32(SCALE_SUB + i * 4, instr))

    # Split into blocks
    blocks = []
    block_max = max_per_block - 1  # reserve 1 for _C header
    chunks = [lines[i:i+block_max] for i in range(0, len(lines), block_max)]
    for ci, chunk in enumerate(chunks):
        part = f" ({ci+1}/{len(chunks)})" if len(chunks) > 1 else ""
        blocks.append(f"_C0  {name}{part}")
        blocks.extend(chunk)

    return blocks


def generate_all():
    """Generate all scale code variants."""
    cave_hide = gen_cave_hide_scale()
    cave_only = gen_cave_scale_only()
    sub_50 = gen_scale_sub_50()
    sub_75 = gen_scale_sub_75()

    all_codes = []

    all_codes.extend(format_code("Scale Wheel 50% + Hide Btns", cave_hide, sub_50))
    all_codes.append("")
    all_codes.extend(format_code("Scale Wheel 75% + Hide Btns", cave_hide, sub_75))
    all_codes.append("")
    all_codes.extend(format_code("Scale Wheel 50%", cave_only, sub_50))
    all_codes.append("")
    all_codes.extend(format_code("Scale Wheel 75%", cave_only, sub_75))

    return all_codes


if __name__ == "__main__":
    codes = generate_all()
    print("\n=== ITEM SELECTOR SCALE CODES ===")
    print("NOTE: These codes write to 0x097F0800+ and 0x097F0A00+.")
    print("Disable 'Hide Buttons/Elements A/B/C' when using hide+scale variants.")
    print("Only enable ONE scale code at a time.\n")
    for line in codes:
        print(line)
