#!/usr/bin/env python3
"""
MHP3rd (ULJM-05800) Monster HP Display CWCheat Generator

Hook point: 0x09D63E0C (dynamic render code), return: 0x09D63A64
Render context: $fp-relative (LW $a0, 0x9F18($fp))
Code injection: 0x08A8CA00 (EBOOT BSS, confirmed zero across all save states)

Previous CODE_BASE 0x097F0000 was in dynamic heap — crashed with new save data.
0x08A8C900-0x08AACA00 (131KB) verified zero across 16 save states.
"""

import struct

# =============================================================================
# CONFIGURABLE PARAMETERS
# =============================================================================

FONT_HEIGHT = 14        # Font size byte written to render context +0x12E
LINE_SPACE = -10 & 0xFFFF  # Default: stack up 10px (0xFFF6 signed)
X_POS = 0x38            # Default X position
Y_POS = 258             # Default Y position (0x102)
MAX_MONSTERS = 3       # Max monsters to display (MONSTER_POINTER has 3 quest target slots)

# =============================================================================
# GAME-SPECIFIC CONSTANTS (MHP3rd ULJM-05800)
# =============================================================================

# Memory layout - EBOOT BSS region (confirmed zero across all save states)
# 0x08A8C900-0x08AACA00 = 131KB free. LUI base 0x08A9, all offsets < 0x8000.
CODE_BASE       = 0x08A90000   # Start of injected code (LUI-aligned)
DATA_BASE       = 0x08A90280   # Start of format strings
BITMASK_BASE    = 0x08A902C0   # Large monster bitmask

# LUI base = 0x08A9 — all offsets 0x0000-0x0300, safe for both ORI and load/store
SAVE_AREA       = 0x08A902D0   # Register save area (s0-s5, 6 words)
REENTRY_FLAG    = 0x08A902F0   # Re-entry guard byte (0=not running, 1=running)
INIT_FLAG_ADDR  = 0x08A902F1   # Initialized flag (0=fresh start, 1=initialized)
FONT_SIZE_ADDR  = 0x08A902F4   # Font size byte
DISPLAY_MODE_ADDR = 0x08A902F8 # Display mode flag (0=absolute, 1=percent)
TOGGLE_FLAG_ADDR = 0x08A902FC  # Toggle flag byte (0=OFF, non-zero=ON)
COLOR_ADDR      = 0x08A90300   # Color/style byte

# Hook (dynamic render code - confirmed working for visible text)
HOOK_ADDR       = 0x09D63E0C   # Where we place our jump (in render pipeline)
RETURN_ADDR     = 0x09D63A64   # Where we return after our code
GUARD_ADDR      = 0x08C57C90   # Quest active flag address (CW offset 0x457C90)
GUARD_VALUE     = 0x5FA0       # If != this value, we're in quest

# Game functions
SET_FONT_SIZE   = 0x088E6FF0   # set_font_size(context, size, style)
TEXT_RENDER     = 0x088EAA64   # text_render(context, fmt, ...)

# Button input
BUTTON_ADDR     = 0x08B3885C   # Button input register (halfword)
BTN_TOGGLE_ON   = 0x0101       # L + Select = show HP
BTN_TOGGLE_OFF  = 0x0201       # R + Select = hide HP

# Game data
ENTITY_TABLE    = 0x09DA9860   # Monster entity pointer table (5 entries)
NAME_TABLE_BASE = 0x08A39F4C   # Monster name pointer table base
NAME_BIAS       = 382          # Index bias for name lookup

# Entity struct offsets
ENT_TYPE_ID     = 0x062        # u8: monster type ID
ENT_HP_CUR      = 0x246        # s16: current HP
ENT_HP_MAX      = 0x288        # s16: max HP

# CWCheat base
CW_BASE = 0x08800000

# =============================================================================
# MIPS ASSEMBLER
# =============================================================================

_REG = {
    '$zero': 0, '$at': 1, '$v0': 2, '$v1': 3,
    '$a0': 4, '$a1': 5, '$a2': 6, '$a3': 7,
    '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11,
    '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15,
    '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19,
    '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,
    '$t8': 24, '$t9': 25, '$k0': 26, '$k1': 27,
    '$gp': 28, '$sp': 29, '$fp': 30, '$ra': 31,
}

def reg(name):
    if isinstance(name, int):
        return name
    return _REG[name]

def _r_type(rs, rt, rd, shamt, funct):
    return ((0 << 26) | (reg(rs) << 21) | (reg(rt) << 16) |
            (reg(rd) << 11) | ((shamt & 0x1F) << 6) | (funct & 0x3F))

def _i_type(op, rs, rt, imm):
    return ((op << 26) | (reg(rs) << 21) | (reg(rt) << 16) | (imm & 0xFFFF))

def _j_type(op, target):
    return (op << 26) | ((target >> 2) & 0x03FFFFFF)

def NOP():       return 0x00000000
def SLL(rd, rt, shamt): return _r_type('$zero', rt, rd, shamt, 0x00)
def SRL(rd, rt, shamt): return _r_type('$zero', rt, rd, shamt, 0x02)
def JR(rs):      return _r_type(rs, '$zero', '$zero', 0, 0x08)
def ADDU(rd, rs, rt): return _r_type(rs, rt, rd, 0, 0x21)
def AND(rd, rs, rt):  return _r_type(rs, rt, rd, 0, 0x24)
def OR(rd, rs, rt):   return _r_type(rs, rt, rd, 0, 0x25)
def MOVE(rd, rs): return _r_type(rs, '$zero', rd, 0, 0x21)
def SLTU(rd, rs, rt): return _r_type(rs, rt, rd, 0, 0x2B)
def MULT(rs, rt): return _r_type(rs, rt, '$zero', 0, 0x18)
def DIV(rs, rt):  return _r_type(rs, rt, '$zero', 0, 0x1A)
def MFLO(rd):    return _r_type('$zero', '$zero', rd, 0, 0x12)
def MFHI(rd):    return _r_type('$zero', '$zero', rd, 0, 0x10)
def J(target):   return _j_type(0x02, target)
def JAL(target): return _j_type(0x03, target)
def BEQ(rs, rt, offset): return _i_type(0x04, rs, rt, offset & 0xFFFF)
def BNE(rs, rt, offset): return _i_type(0x05, rs, rt, offset & 0xFFFF)
def BLEZ(rs, offset):    return _i_type(0x06, rs, '$zero', offset & 0xFFFF)
def ADDIU(rt, rs, imm):  return _i_type(0x09, rs, rt, imm & 0xFFFF)
def SLTI(rt, rs, imm):   return _i_type(0x0A, rs, rt, imm & 0xFFFF)
def ANDI(rt, rs, imm):   return _i_type(0x0C, rs, rt, imm & 0xFFFF)
def ORI(rt, rs, imm):    return _i_type(0x0D, rs, rt, imm & 0xFFFF)
def LUI(rt, imm):        return _i_type(0x0F, '$zero', rt, imm & 0xFFFF)
def LH(rt, offset, base):  return _i_type(0x21, base, rt, offset & 0xFFFF)
def LW(rt, offset, base):  return _i_type(0x23, base, rt, offset & 0xFFFF)
def LBU(rt, offset, base): return _i_type(0x24, base, rt, offset & 0xFFFF)
def SB(rt, offset, base):  return _i_type(0x28, base, rt, offset & 0xFFFF)
def SH(rt, offset, base):  return _i_type(0x29, base, rt, offset & 0xFFFF)
def SW(rt, offset, base):  return _i_type(0x2B, base, rt, offset & 0xFFFF)
def LI(rt, imm): return ORI(rt, '$zero', imm & 0xFFFF)


# =============================================================================
# CODE BUILDER
# =============================================================================

class CodeBuilder:
    def __init__(self, base_addr):
        self.base = base_addr
        self.words = {}
        self.cur = base_addr

    def org(self, addr):
        self.cur = addr

    def emit(self, word):
        self.words[self.cur] = word & 0xFFFFFFFF
        self.cur += 4

    def emit_at(self, addr, word):
        self.words[addr] = word & 0xFFFFFFFF

    def addr(self):
        return self.cur

    def branch_offset(self, from_addr, to_addr):
        return (to_addr - (from_addr + 4)) >> 2

    def emit_string(self, s):
        data = s.encode('utf-8') + b'\x00'
        while len(data) % 4 != 0:
            data += b'\x00'
        for i in range(0, len(data), 4):
            word = struct.unpack('<I', data[i:i+4])[0]
            self.emit(word)

    def get_all_writes(self):
        return sorted(self.words.items())


def to_cw_offset(psp_addr):
    return psp_addr - CW_BASE

def cw_line_32(psp_addr, value):
    offset = to_cw_offset(psp_addr)
    return f"_L 0x2{offset:07X} 0x{value & 0xFFFFFFFF:08X}"

def cw_line_16(psp_addr, value):
    offset = to_cw_offset(psp_addr)
    return f"_L 0x1{offset:07X} 0x0000{value & 0xFFFF:04X}"

def cw_line_8(psp_addr, value):
    offset = to_cw_offset(psp_addr)
    return f"_L 0x0{offset:07X} 0x000000{value & 0xFF:02X}"

def cw_cond_16(psp_addr, value):
    """D-type 16-bit equal: execute next line if halfword == value."""
    offset = to_cw_offset(psp_addr)
    return f"_L 0xD0{offset:06X} 0x0000{value & 0xFFFF:04X}"

def cw_cond_16_ne(psp_addr, value):
    offset = to_cw_offset(psp_addr)
    return f"_L 0xD1{offset:06X} 0x0000{value & 0xFFFF:04X}"


# =============================================================================
# CODE GENERATION
# =============================================================================

def generate():
    cb = CodeBuilder(CODE_BASE)
    LUI_BASE = (CODE_BASE >> 16) & 0xFFFF  # 0x097F

    # =========================================================================
    # FORMAT STRINGS at DATA_BASE
    # =========================================================================
    cb.org(DATA_BASE)
    fmt_absolute = DATA_BASE
    cb.emit_string("%s: %d/%d")

    fmt_percent = cb.addr()
    cb.emit_string("%s: %d%%")

    # Large monster bitmask (bit N = type_id N is a large monster)
    cb.org(BITMASK_BASE)
    cb.emit(0x039DD3FE)   # type_ids 0-31
    cb.emit(0x7FF8FF01)   # type_ids 32-63

    # =========================================================================
    # SUBROUTINE: text_render_wrapper
    # Uses $fp for render context (same as original working cheat)
    # Args: $a1=font_size, $a2=x, $a3=y, $t0=fmt, $t1-$t6=varargs
    # =========================================================================
    TEXT_RENDER_WRAPPER = CODE_BASE + 0x01A0
    cb.org(TEXT_RENDER_WRAPPER)
    cb.emit(LW('$a0', 0x9F18, '$fp'))        # $a0 = render context via $fp
    cb.emit(NOP())
    cb.emit(SB('$a1', 0x012E, '$a0'))        # style byte
    cb.emit(SH('$a2', 0x0120, '$a0'))        # X pos
    cb.emit(SH('$a3', 0x0122, '$a0'))        # Y pos
    cb.emit(MOVE('$a1', '$t0'))              # fmt string
    cb.emit(MOVE('$a2', '$t1'))              # arg1 (name)
    cb.emit(MOVE('$a3', '$t2'))              # arg2 (hp_cur)
    cb.emit(MOVE('$t0', '$t3'))              # arg3 (hp_max)
    cb.emit(MOVE('$t1', '$t4'))
    cb.emit(MOVE('$t2', '$t5'))
    cb.emit(MOVE('$t3', '$t6'))
    cb.emit(J(TEXT_RENDER))                  # tail call
    cb.emit(NOP())

    # =========================================================================
    # SUBROUTINE: get_monster_name
    # Args: $t1=type_id, Returns: $t1=name_string_ptr
    # =========================================================================
    GET_NAME = CODE_BASE + 0x01E0
    cb.org(GET_NAME)
    cb.emit(LUI('$at', (NAME_TABLE_BASE >> 16) & 0xFFFF))
    cb.emit(ORI('$at', '$at', NAME_TABLE_BASE & 0xFFFF))
    cb.emit(ADDIU('$v0', '$t1', NAME_BIAS))
    cb.emit(SLL('$v0', '$v0', 2))
    cb.emit(ADDU('$v0', '$at', '$v0'))
    cb.emit(LW('$v0', 0, '$v0'))
    cb.emit(ADDU('$t1', '$v0', '$at'))
    cb.emit(JR('$ra'))
    cb.emit(NOP())

    # =========================================================================
    # SUBROUTINE: is_large_monster
    # Args: $s2=entity_ptr, $s5=LUI_base
    # Returns: $v0=1 if large, 0 if not
    # =========================================================================
    IS_LARGE = cb.addr()
    cb.emit(LBU('$t6', ENT_TYPE_ID, '$s2'))
    # Bounds check: type_id >= 64 → not large (bitmask only covers 0-63)
    cb.emit(SLTI('$v0', '$t6', 64))
    is_large_oob = cb.addr()
    cb.emit(0)  # placeholder BEQ $v0, $zero → return 0
    cb.emit(NOP())
    cb.emit(ORI('$v0', '$s5', BITMASK_BASE & 0xFFFF))
    cb.emit(SRL('$t7', '$t6', 3))
    cb.emit(ADDU('$v0', '$v0', '$t7'))
    cb.emit(LBU('$v1', 0, '$v0'))
    cb.emit(ANDI('$t6', '$t6', 7))
    cb.emit(LI('$v0', 1))
    sllv_addr = cb.addr()
    cb.emit(0)  # placeholder SLLV
    cb.emit(AND('$v0', '$v0', '$v1'))
    cb.emit(JR('$ra'))
    cb.emit(NOP())
    # Out-of-bounds: return 0
    is_large_ret0 = cb.addr()
    cb.emit(LI('$v0', 0))
    cb.emit(JR('$ra'))
    cb.emit(NOP())
    cb.emit_at(sllv_addr, _r_type('$t6', '$v0', '$v0', 0, 0x04))  # SLLV $v0,$v0,$t6
    cb.emit_at(is_large_oob, BEQ('$v0', '$zero', cb.branch_offset(is_large_oob, is_large_ret0)))

    # =========================================================================
    # BAIL: clear re-entry flag and return (used by all bail paths)
    # =========================================================================
    BAIL_ADDR = CODE_BASE + 0x0140
    cb.org(BAIL_ADDR)
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(SB('$zero', REENTRY_FLAG & 0xFFFF, '$v0'))
    cb.emit(J(RETURN_ADDR))
    cb.emit(NOP())
    # BAIL_CLEAR is now the same as BAIL (merged)
    BAIL_CLEAR_ADDR = BAIL_ADDR

    # =========================================================================
    # EXIT: clear re-entry flag, restore registers and return to game
    # =========================================================================
    EXIT_ADDR = CODE_BASE + 0x0160
    cb.org(EXIT_ADDR)
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(SB('$zero', REENTRY_FLAG & 0xFFFF, '$v0'))
    cb.emit(LW('$s5', (SAVE_AREA + 20) & 0xFFFF, '$v0'))
    cb.emit(LW('$s4', (SAVE_AREA + 16) & 0xFFFF, '$v0'))
    cb.emit(LW('$s3', (SAVE_AREA + 12) & 0xFFFF, '$v0'))
    cb.emit(LW('$s2', (SAVE_AREA +  8) & 0xFFFF, '$v0'))
    cb.emit(LW('$s1', (SAVE_AREA +  4) & 0xFFFF, '$v0'))
    cb.emit(LW('$s0', (SAVE_AREA +  0) & 0xFFFF, '$v0'))
    cb.emit(J(RETURN_ADDR))                  # return to game render code
    cb.emit(NOP())

    # =========================================================================
    # MAIN CODE @ CODE_BASE
    # =========================================================================
    cb.org(CODE_BASE)

    # Re-entry guard — bail if already running (prevents double execution)
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(LBU('$v1', REENTRY_FLAG & 0xFFFF, '$v0'))
    reentry_bail = cb.addr()
    cb.emit(0)  # placeholder BNE $v1, $zero, BAIL
    cb.emit(NOP())
    # Set re-entry flag (v0 still = LUI_BASE)
    cb.emit(LI('$v1', 1))
    cb.emit(SB('$v1', REENTRY_FLAG & 0xFFFF, '$v0'))

    # Validate $fp — if invalid, bail
    cb.emit(LUI('$v0', 0x0880))
    cb.emit(SLTU('$v0', '$fp', '$v0'))
    fp_bail = cb.addr()
    cb.emit(0)  # placeholder BNE $v0, $zero, BAIL (clears reentry flag)
    cb.emit(NOP())

    # Verify overlay sentinel is still valid
    TC_SENTINEL = 0x09C57CA0
    cb.emit(LUI('$v0', (TC_SENTINEL >> 16) & 0xFFFF))
    cb.emit(LH('$v0', TC_SENTINEL & 0xFFFF, '$v0'))
    cb.emit(ADDIU('$v0', '$v0', -0x6167 & 0xFFFF))
    sentinel_bail = cb.addr()
    cb.emit(0)  # placeholder BNE $v0, $zero, BAIL
    cb.emit(NOP())

    # Save registers to fixed memory area
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(SW('$s5', (SAVE_AREA + 20) & 0xFFFF, '$v0'))
    cb.emit(SW('$s4', (SAVE_AREA + 16) & 0xFFFF, '$v0'))
    cb.emit(SW('$s3', (SAVE_AREA + 12) & 0xFFFF, '$v0'))
    cb.emit(SW('$s2', (SAVE_AREA +  8) & 0xFFFF, '$v0'))
    cb.emit(SW('$s1', (SAVE_AREA +  4) & 0xFFFF, '$v0'))
    cb.emit(SW('$s0', (SAVE_AREA +  0) & 0xFFFF, '$v0'))

    # Initialize counters
    cb.emit(LI('$s0', 0))                                      # loop counter
    cb.emit(LI('$s1', 0))                                      # Y offset
    cb.emit(LBU('$s4', FONT_SIZE_ADDR & 0xFFFF, '$v0'))        # font size
    cb.emit(LUI('$s5', LUI_BASE))                              # $s5 = base for data refs

    # Monster loop start
    loop_start = cb.addr()

    # Validate render context each iteration
    cb.emit(LW('$a0', 0x9F18, '$fp'))                          # $a0 = render context
    skip_bad_ctx = cb.addr()
    cb.emit(0)  # placeholder BEQ $a0, $zero, EXIT
    cb.emit(NOP())

    # Font setup
    cb.emit(MOVE('$a1', '$s4'))                                 # font size
    cb.emit(JAL(SET_FONT_SIZE))
    cb.emit(MOVE('$a2', '$s4'))                                 # delay slot: style

    # Entity table lookup
    cb.emit(LUI('$v0', (ENTITY_TABLE >> 16) & 0xFFFF))
    cb.emit(ORI('$v0', '$v0', ENTITY_TABLE & 0xFFFF))
    cb.emit(SLL('$v1', '$s0', 2))
    cb.emit(ADDU('$v0', '$v0', '$v1'))
    cb.emit(LW('$s2', 0, '$v0'))

    # Skip null entities
    skip_monster = cb.addr()
    cb.emit(0)  # placeholder BEQ $s2, $zero, loop_ctrl
    cb.emit(NOP())

    # Validate entity pointer range (>= 0x08800000)
    cb.emit(LUI('$v0', 0x0880))
    cb.emit(SLTU('$v0', '$s2', '$v0'))
    skip_invalid = cb.addr()
    cb.emit(0)  # placeholder BNE $v0, $zero, loop_ctrl
    cb.emit(NOP())

    # HP check: skip dead monsters (HP <= 0)
    cb.emit(LH('$v0', ENT_HP_CUR, '$s2'))
    skip_dead = cb.addr()
    cb.emit(0)  # placeholder: BLEZ $v0, loop_ctrl
    cb.emit(NOP())

    # Large monster filter
    cb.emit(JAL(IS_LARGE))
    cb.emit(NOP())
    skip_not_large = cb.addr()
    cb.emit(0)  # placeholder BEQ $v0, $zero, loop_ctrl
    cb.emit(NOP())

    # Get monster name
    cb.emit(JAL(GET_NAME))
    cb.emit(LBU('$t1', ENT_TYPE_ID, '$s2'))                    # delay slot

    # Validate name pointer (must be >= 0x08800000)
    cb.emit(LUI('$v0', 0x0880))
    cb.emit(SLTU('$v0', '$t1', '$v0'))
    skip_bad_name = cb.addr()
    cb.emit(0)  # placeholder BNE $v0, $zero, loop_ctrl
    cb.emit(NOP())

    # Load HP
    cb.emit(LH('$t2', ENT_HP_CUR, '$s2'))
    cb.emit(LH('$t3', ENT_HP_MAX, '$s2'))

    # Prepare render args
    x_pos_addr = cb.addr()
    cb.emit(LI('$a2', X_POS & 0xFFFF))                         # X
    y_pos_addr = cb.addr()
    cb.emit(LI('$a3', Y_POS & 0xFFFF))                         # base Y
    cb.emit(ADDU('$a3', '$a3', '$s1'))                          # Y + offset

    cb.emit(LBU('$a1', COLOR_ADDR & 0xFFFF, '$s5'))             # color/style byte

    # Load format string (absolute mode)
    cb.emit(ORI('$t0', '$s5', fmt_absolute & 0xFFFF))

    # Check display mode
    cb.emit(LBU('$t7', DISPLAY_MODE_ADDR & 0xFFFF, '$s5'))
    mode_branch = cb.addr()
    cb.emit(0)  # placeholder BEQ $t7, $zero, do_render

    # Line spacing (delay slot - always executes)
    line_spacing_addr = cb.addr()
    cb.emit(ADDIU('$s1', '$s1', LINE_SPACE & 0xFFFF))

    # Percent mode computation
    cb.emit(ORI('$t6', '$zero', 100))
    cb.emit(MULT('$t2', '$t6'))
    cb.emit(MFLO('$t2'))
    cb.emit(DIV('$t2', '$t3'))
    cb.emit(MFLO('$t2'))
    cb.emit(ORI('$t0', '$s5', fmt_percent & 0xFFFF))

    # Render call
    do_render = cb.addr()
    cb.emit(JAL(TEXT_RENDER_WRAPPER))
    cb.emit(NOP())

    # Loop control
    loop_ctrl = cb.addr()
    cb.emit(SLTI('$v0', '$s0', MAX_MONSTERS - 1))
    loop_back_addr = cb.addr()
    cb.emit(BNE('$v0', '$zero', cb.branch_offset(loop_back_addr, loop_start)))
    cb.emit(ADDIU('$s0', '$s0', 1))                            # delay slot

    # Jump to exit
    cb.emit(J(EXIT_ADDR))
    cb.emit(NOP())

    # Fix placeholders
    # reentry_bail: bail if already running (no regs modified yet)
    cb.emit_at(reentry_bail, BNE('$v1', '$zero', cb.branch_offset(reentry_bail, BAIL_ADDR)))
    # fp_bail / sentinel_bail: bail + clear reentry flag
    cb.emit_at(fp_bail, BNE('$v0', '$zero', cb.branch_offset(fp_bail, BAIL_ADDR)))
    cb.emit_at(sentinel_bail, BNE('$v0', '$zero', cb.branch_offset(sentinel_bail, BAIL_ADDR)))
    cb.emit_at(skip_bad_ctx, BEQ('$a0', '$zero', cb.branch_offset(skip_bad_ctx, EXIT_ADDR)))
    cb.emit_at(skip_bad_name, BNE('$v0', '$zero', cb.branch_offset(skip_bad_name, loop_ctrl)))
    cb.emit_at(skip_monster, BEQ('$s2', '$zero', cb.branch_offset(skip_monster, loop_ctrl)))
    cb.emit_at(skip_invalid, BNE('$v0', '$zero', cb.branch_offset(skip_invalid, loop_ctrl)))
    cb.emit_at(skip_dead, BLEZ('$v0', cb.branch_offset(skip_dead, loop_ctrl)))
    cb.emit_at(skip_not_large, BEQ('$v0', '$zero', cb.branch_offset(skip_not_large, loop_ctrl)))
    cb.emit_at(mode_branch, BEQ('$t7', '$zero', cb.branch_offset(mode_branch, do_render)))

    # =========================================================================
    # GENERATE CWCheat OUTPUT
    # =========================================================================
    import sys
    print(f"Addresses: X=0x{x_pos_addr:08X} Y=0x{y_pos_addr:08X} LS=0x{line_spacing_addr:08X}", file=sys.stderr)

    lines = []

    # Part 0: Guard + hook + button → flag byte writes
    # Flag at TOGGLE_FLAG_ADDR: 0=OFF, 1=ON. Code reads flag and branches.
    # No patchable instruction — all code is in bulk writes, no garbage memory risk.
    part0 = []
    # MHFU-style: install/uninstall hook via button press
    # L+Select = install hook (enable HP display)
    TC_SENTINEL = 0x09C57CA0
    TC_SENTINEL_CW = to_cw_offset(TC_SENTINEL)
    part0.append(cw_cond_16(BUTTON_ADDR, BTN_TOGGLE_ON))
    part0.append(cw_line_32(HOOK_ADDR, J(CODE_BASE)))
    # R+Select = uninstall hook (disable HP display) — write NOP to skip
    part0.append(cw_cond_16(BUTTON_ADDR, BTN_TOGGLE_OFF))
    part0.append(cw_line_32(HOOK_ADDR, NOP()))

    # Collect all code/data writes (toggle is now code, not a gap)
    all_writes = cb.get_all_writes()
    code_lines = [cw_line_32(addr, val) for addr, val in all_writes]

    # Build parts: part0 first, then code write chunks
    MAX_PER_PART = 20
    parts = [part0]
    for i in range(0, len(code_lines), MAX_PER_PART):
        parts.append(code_lines[i:i+MAX_PER_PART])

    total_parts = len(parts)
    for i, part in enumerate(parts):
        header = f"_C1  HP_Display {i + 1}/{total_parts}"
        lines.append(header)
        for l in part:
            lines.append(l)

    # =========================================================================
    # CUSTOMIZATION CODES
    # =========================================================================
    lines.append("")

    # Font size
    for label, val, default in [
        ("HP Font 6",  0x06, False),
        ("HP Font 8",  0x08, False),
        ("HP Font 10", 0x0A, True),
        ("HP Font 14", 0x0E, False),
    ]:
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_8(FONT_SIZE_ADDR, val))

    lines.append("")

    # X position
    for label, val, default in [
        ("HP X=6",   0x0006, False),
        ("HP X=20",  0x0014, False),
        ("HP X=100", 0x0064, False),
    ]:
        instr = ORI('$a2', '$zero', val)
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_32(x_pos_addr, instr))

    lines.append("")

    # Y position
    for label, val, default in [
        ("HP Y=20",  0x0014, False),
        ("HP Y=100", 0x0064, False),
        ("HP Y=134", 0x0086, False),
        ("HP Y=200", 0x00C8, False),
    ]:
        instr = ORI('$a3', '$zero', val)
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_32(y_pos_addr, instr))

    lines.append("")

    # Line spacing
    for label, val, default in [
        ("HP Stack Down 10px", 0x000A, False),
        ("HP Stack Down 14px", 0x000E, False),
        ("HP Stack Down 20px", 0x0014, False),
    ]:
        instr = ADDIU('$s1', '$s1', val)
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_32(line_spacing_addr, instr))

    lines.append("")

    # Color
    for label, val, default in [
        ("HP Color White", 0x00, True),
        ("HP Color Grey",  0x0A, False),
    ]:
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_8(COLOR_ADDR, val))

    lines.append("")

    # Display mode
    lines.append("_C0 HP Absolute")
    lines.append(cw_line_8(DISPLAY_MODE_ADDR, 0x00))
    lines.append("_C1 HP Percent")
    lines.append(cw_line_8(DISPLAY_MODE_ADDR, 0x01))

    return '\n'.join(lines)


if __name__ == '__main__':
    output = generate()
    print(output)
