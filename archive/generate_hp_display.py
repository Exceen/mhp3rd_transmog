#!/usr/bin/env python3
"""
MHP3rd (ULJM-05800) Monster HP Display CWCheat Generator

Hook: 0x088E6D64 — replaces `jal 0x088EBAB8` in EBOOT render loop
  - EBOOT address (static, always present)
  - Proper jal replacement (no instruction destruction)
  - NOP delay slot
  - $s2 = 0x09BF0000 at hook point (render context base)
  - Called every frame in the render loop (bne at 0x088E6D7C loops)

Code cave: 0x08A90000 (EBOOT BSS, verified zero across save states)

Toggle: branch instruction inside code cave (not at hook site)
  - L+Select = NOP at toggle addr (HP display ON)
  - R+Select = BEQ at toggle addr (HP display OFF, skip to exit)
  - Default: NOP (ON) since BSS is zeroed

Exit: chains through kurogami's HP bar code at 0x08801DA4 if present
      (runtime check), otherwise tail-calls original function 0x088EBAB8.
      Both paths return to 0x088E6D6C via $ra set by the hook's jal.
"""

import struct
import sys

# =============================================================================
# CONFIGURABLE PARAMETERS
# =============================================================================

FONT_HEIGHT = 14
LINE_SPACE = -10 & 0xFFFF
X_POS = 0x38
Y_POS = 258
MAX_MONSTERS = 3

# =============================================================================
# GAME-SPECIFIC CONSTANTS (MHP3rd ULJM-05800)
# =============================================================================

# Hook point — jal in EBOOT render loop function (0x088E6C40)
HOOK_ADDR       = 0x088E6D64   # Original: jal 0x088EBAB8
ORIG_FUNC       = 0x088EBAB8   # Function we're replacing the call to
# After our code cave runs, we tail-call ORIG_FUNC (or chain target).
# ORIG_FUNC does jr $ra → 0x088E6D6C (set by the jal at HOOK_ADDR).

# Kurogami's HP bar code (baked into save states via mhp3rd_monster_hp_bar).
# Also hooks 0x088E6D64. We chain through it so both HP bar + damage numbers work.
CHAIN_TARGET    = 0x08801DA4   # kurogami's code cave entry point

# Code cave in EBOOT BSS (verified zero across save states)
CODE_BASE       = 0x08A90000
DATA_BASE       = 0x08A90280
BITMASK_BASE    = 0x08A902C0

LUI_BASE        = (CODE_BASE >> 16) & 0xFFFF  # 0x08A9

# Register save area
SAVE_AREA       = 0x08A902D0   # s0-s5 (6 words, 0x2D0-0x2E7)
SAVE_RA         = 0x08A902E8   # $ra
SAVE_A0         = 0x08A902EC   # $a0

# Configurable data addresses
FONT_SIZE_ADDR  = 0x08A902F0
DISPLAY_MODE_ADDR = 0x08A902F4
COLOR_ADDR      = 0x08A902F8

# Overlay sentinel (verify quest is active)
GUARD_ADDR      = 0x09C57CA0
GUARD_VALUE     = 0x6167       # halfword at GUARD_ADDR when overlay loaded

# Game functions
SET_FONT_SIZE   = 0x088E6FF0
TEXT_RENDER     = 0x088EAA64

# Render context base (loaded via lui + lw, not register-dependent)
RENDER_CTX_HI   = 0x09BF
RENDER_CTX_OFF  = 0x9F18       # sign-extended: 0x09BF0000 + (-0x60E8) = 0x09BE9F18

# Button input
BUTTON_ADDR     = 0x08B3885C
BTN_TOGGLE_ON   = 0x0101       # L + Select
BTN_TOGGLE_OFF  = 0x0201       # R + Select

# Game data
ENTITY_TABLE    = 0x09DA9860
NAME_TABLE_BASE = 0x08A39F4C
NAME_BIAS       = 382

# Entity struct offsets
ENT_TYPE_ID     = 0x062
ENT_HP_CUR      = 0x246
ENT_HP_MAX      = 0x288

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
    if isinstance(name, int): return name
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
    return f"_L 0x2{to_cw_offset(psp_addr):07X} 0x{value & 0xFFFFFFFF:08X}"

def cw_line_16(psp_addr, value):
    return f"_L 0x1{to_cw_offset(psp_addr):07X} 0x0000{value & 0xFFFF:04X}"

def cw_line_8(psp_addr, value):
    return f"_L 0x0{to_cw_offset(psp_addr):07X} 0x000000{value & 0xFF:02X}"

def cw_cond_16(psp_addr, value):
    return f"_L 0xD0{to_cw_offset(psp_addr):06X} 0x0000{value & 0xFFFF:04X}"


# =============================================================================
# CODE GENERATION
# =============================================================================

def generate():
    cb = CodeBuilder(CODE_BASE)

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
    # Loads render context via direct LUI/LW (not register-dependent).
    # Args: $a1=font_size, $a2=x, $a3=y, $t0=fmt, $t1-$t6=varargs
    # =========================================================================
    TEXT_RENDER_WRAPPER = CODE_BASE + 0x01A0
    cb.org(TEXT_RENDER_WRAPPER)
    cb.emit(LUI('$a0', RENDER_CTX_HI))              # $a0 = 0x09BF0000
    cb.emit(LW('$a0', RENDER_CTX_OFF, '$a0'))        # $a0 = render context ptr
    cb.emit(BEQ('$a0', '$zero', 3))                  # skip render if null
    cb.emit(NOP())
    cb.emit(SB('$a1', 0x012E, '$a0'))                # style byte
    cb.emit(SH('$a2', 0x0120, '$a0'))                # X pos
    cb.emit(SH('$a3', 0x0122, '$a0'))                # Y pos
    cb.emit(MOVE('$a1', '$t0'))                       # fmt string
    cb.emit(MOVE('$a2', '$t1'))                       # arg1 (name)
    cb.emit(MOVE('$a3', '$t2'))                       # arg2 (hp_cur)
    cb.emit(MOVE('$t0', '$t3'))                       # arg3 (hp_max)
    cb.emit(MOVE('$t1', '$t4'))
    cb.emit(MOVE('$t2', '$t5'))
    cb.emit(MOVE('$t3', '$t6'))
    cb.emit(J(TEXT_RENDER))                           # tail call
    cb.emit(NOP())
    # null context: just return
    cb.emit(JR('$ra'))
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
    cb.emit(SLTI('$v0', '$t6', 64))
    is_large_oob = cb.addr()
    cb.emit(0)  # placeholder
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
    is_large_ret0 = cb.addr()
    cb.emit(LI('$v0', 0))
    cb.emit(JR('$ra'))
    cb.emit(NOP())
    cb.emit_at(sllv_addr, _r_type('$t6', '$v0', '$v0', 0, 0x04))
    cb.emit_at(is_large_oob, BEQ('$v0', '$zero', cb.branch_offset(is_large_oob, is_large_ret0)))

    # =========================================================================
    # EXIT: restore s0-s5, $ra, $a0, chain to kurogami or tail-call original
    # =========================================================================
    EXIT_RESTORE = CODE_BASE + 0x0140
    cb.org(EXIT_RESTORE)
    # Restore s0-s5
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(LW('$s5', (SAVE_AREA + 20) & 0xFFFF, '$v0'))
    cb.emit(LW('$s4', (SAVE_AREA + 16) & 0xFFFF, '$v0'))
    cb.emit(LW('$s3', (SAVE_AREA + 12) & 0xFFFF, '$v0'))
    cb.emit(LW('$s2', (SAVE_AREA +  8) & 0xFFFF, '$v0'))
    cb.emit(LW('$s1', (SAVE_AREA +  4) & 0xFFFF, '$v0'))
    cb.emit(LW('$s0', (SAVE_AREA +  0) & 0xFFFF, '$v0'))
    # Fall through to EXIT_TAILCALL

    EXIT_TAILCALL = cb.addr()
    # Restore $ra and $a0
    # ($v0 still = LUI_BASE from above, or reloaded below)
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(LW('$ra', SAVE_RA & 0xFFFF, '$v0'))
    cb.emit(LW('$a0', SAVE_A0 & 0xFFFF, '$v0'))
    cb.emit(MOVE('$a1', '$zero'))                     # a1 = 0
    # Check if kurogami's code is present at CHAIN_TARGET
    cb.emit(LUI('$v1', (CHAIN_TARGET >> 16) & 0xFFFF))
    cb.emit(LW('$v0', CHAIN_TARGET & 0xFFFF, '$v1'))
    chain_branch = cb.addr()
    cb.emit(0)                                        # placeholder BNE → chain_kuro
    cb.emit(LI('$a2', 1))                             # delay slot (always runs)
    # No chain target — call original function directly
    cb.emit(J(ORIG_FUNC))
    cb.emit(NOP())
    # Chain through kurogami's code (it calls ORIG_FUNC itself)
    chain_kuro = cb.addr()
    cb.emit(J(CHAIN_TARGET))
    cb.emit(NOP())
    cb.emit_at(chain_branch, BNE('$v0', '$zero', cb.branch_offset(chain_branch, chain_kuro)))

    # =========================================================================
    # MAIN CODE @ CODE_BASE
    # =========================================================================
    cb.org(CODE_BASE)

    # Save $ra and $a0 (needed for tail-call exit)
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(SW('$ra', SAVE_RA & 0xFFFF, '$v0'))
    cb.emit(SW('$a0', SAVE_A0 & 0xFFFF, '$v0'))

    # Toggle instruction at CODE_BASE + 0x0C
    # Emitted as branch (OFF by default). L+Select writes NOP (ON).
    TOGGLE_ADDR = cb.addr()  # CODE_BASE + 0x0C
    assert TOGGLE_ADDR == CODE_BASE + 0x0C
    # Placeholder — patched after EXIT_TAILCALL address is known
    cb.emit(0)

    # Overlay sentinel guard (skip HP rendering if not in quest)
    cb.emit(LUI('$v0', (GUARD_ADDR >> 16) & 0xFFFF))
    cb.emit(LH('$v0', GUARD_ADDR & 0xFFFF, '$v0'))
    cb.emit(ADDIU('$v0', '$v0', (-GUARD_VALUE) & 0xFFFF))
    sentinel_bail = cb.addr()
    cb.emit(0)  # placeholder BNE → EXIT_TAILCALL
    cb.emit(NOP())

    # Save s0-s5 to fixed memory
    cb.emit(LUI('$v0', LUI_BASE))
    cb.emit(SW('$s5', (SAVE_AREA + 20) & 0xFFFF, '$v0'))
    cb.emit(SW('$s4', (SAVE_AREA + 16) & 0xFFFF, '$v0'))
    cb.emit(SW('$s3', (SAVE_AREA + 12) & 0xFFFF, '$v0'))
    cb.emit(SW('$s2', (SAVE_AREA +  8) & 0xFFFF, '$v0'))
    cb.emit(SW('$s1', (SAVE_AREA +  4) & 0xFFFF, '$v0'))
    cb.emit(SW('$s0', (SAVE_AREA +  0) & 0xFFFF, '$v0'))

    # Initialize loop counters
    cb.emit(LI('$s0', 0))                             # loop counter
    cb.emit(LI('$s1', 0))                             # Y offset
    cb.emit(LBU('$s4', FONT_SIZE_ADDR & 0xFFFF, '$v0'))  # font size
    cb.emit(LUI('$s5', LUI_BASE))                     # base for data refs

    # =========================================================================
    # Monster loop
    # =========================================================================
    loop_start = cb.addr()

    # Load and validate render context each iteration
    cb.emit(LUI('$a0', RENDER_CTX_HI))
    cb.emit(LW('$a0', RENDER_CTX_OFF, '$a0'))
    skip_bad_ctx = cb.addr()
    cb.emit(0)  # placeholder BEQ $a0, $zero → EXIT_RESTORE
    cb.emit(NOP())

    # Set font size
    cb.emit(MOVE('$a1', '$s4'))
    cb.emit(JAL(SET_FONT_SIZE))
    cb.emit(MOVE('$a2', '$s4'))                        # delay slot

    # Entity table lookup
    cb.emit(LUI('$v0', (ENTITY_TABLE >> 16) & 0xFFFF))
    cb.emit(ORI('$v0', '$v0', ENTITY_TABLE & 0xFFFF))
    cb.emit(SLL('$v1', '$s0', 2))
    cb.emit(ADDU('$v0', '$v0', '$v1'))
    cb.emit(LW('$s2', 0, '$v0'))

    # Skip null entities
    skip_monster = cb.addr()
    cb.emit(0)  # placeholder BEQ $s2, $zero → loop_ctrl
    cb.emit(NOP())

    # Validate entity pointer range
    cb.emit(LUI('$v0', 0x0880))
    cb.emit(SLTU('$v0', '$s2', '$v0'))
    skip_invalid = cb.addr()
    cb.emit(0)  # placeholder BNE → loop_ctrl
    cb.emit(NOP())

    # Skip dead monsters (HP <= 0)
    cb.emit(LH('$v0', ENT_HP_CUR, '$s2'))
    skip_dead = cb.addr()
    cb.emit(0)  # placeholder BLEZ → loop_ctrl
    cb.emit(NOP())

    # Large monster filter
    cb.emit(JAL(IS_LARGE))
    cb.emit(NOP())
    skip_not_large = cb.addr()
    cb.emit(0)  # placeholder BEQ $v0, $zero → loop_ctrl
    cb.emit(NOP())

    # Get monster name
    cb.emit(JAL(GET_NAME))
    cb.emit(LBU('$t1', ENT_TYPE_ID, '$s2'))           # delay slot

    # Validate name pointer
    cb.emit(LUI('$v0', 0x0880))
    cb.emit(SLTU('$v0', '$t1', '$v0'))
    skip_bad_name = cb.addr()
    cb.emit(0)  # placeholder BNE → loop_ctrl
    cb.emit(NOP())

    # Load HP values
    cb.emit(LH('$t2', ENT_HP_CUR, '$s2'))
    cb.emit(LH('$t3', ENT_HP_MAX, '$s2'))

    # Prepare render args
    x_pos_addr = cb.addr()
    cb.emit(LI('$a2', X_POS & 0xFFFF))                # X
    y_pos_addr = cb.addr()
    cb.emit(LI('$a3', Y_POS & 0xFFFF))                # base Y
    cb.emit(ADDU('$a3', '$a3', '$s1'))                 # Y + offset

    cb.emit(LBU('$a1', COLOR_ADDR & 0xFFFF, '$s5'))   # color/style

    # Format string (absolute mode default)
    cb.emit(ORI('$t0', '$s5', fmt_absolute & 0xFFFF))

    # Check display mode
    cb.emit(LBU('$t7', DISPLAY_MODE_ADDR & 0xFFFF, '$s5'))
    mode_branch = cb.addr()
    cb.emit(0)  # placeholder BEQ $t7, $zero → do_render

    # Line spacing (delay slot — always executes)
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
    cb.emit(ADDIU('$s0', '$s0', 1))                   # delay slot

    # Done — jump to EXIT_RESTORE (restores s0-s5, then tail-calls)
    cb.emit(J(EXIT_RESTORE))
    cb.emit(NOP())

    # =========================================================================
    # Fix all placeholder branches
    # =========================================================================
    cb.emit_at(sentinel_bail, BNE('$v0', '$zero', cb.branch_offset(sentinel_bail, EXIT_TAILCALL)))
    cb.emit_at(skip_bad_ctx, BEQ('$a0', '$zero', cb.branch_offset(skip_bad_ctx, EXIT_RESTORE)))
    cb.emit_at(skip_monster, BEQ('$s2', '$zero', cb.branch_offset(skip_monster, loop_ctrl)))
    cb.emit_at(skip_invalid, BNE('$v0', '$zero', cb.branch_offset(skip_invalid, loop_ctrl)))
    cb.emit_at(skip_dead, BLEZ('$v0', cb.branch_offset(skip_dead, loop_ctrl)))
    cb.emit_at(skip_not_large, BEQ('$v0', '$zero', cb.branch_offset(skip_not_large, loop_ctrl)))
    cb.emit_at(skip_bad_name, BNE('$v0', '$zero', cb.branch_offset(skip_bad_name, loop_ctrl)))
    cb.emit_at(mode_branch, BEQ('$t7', '$zero', cb.branch_offset(mode_branch, do_render)))

    # Compute toggle branch (BEQ $zero,$zero → EXIT_TAILCALL)
    toggle_off_branch = BEQ('$zero', '$zero', cb.branch_offset(TOGGLE_ADDR, EXIT_TAILCALL))
    # Emit toggle into code builder (default OFF). The code writes are guarded
    # by an E-type conditional so they only run once (when cave not yet written).
    # After initial write, only button D-type presses modify the toggle.
    cb.emit_at(TOGGLE_ADDR, toggle_off_branch)

    # =========================================================================
    # GENERATE CWCheat OUTPUT
    # =========================================================================
    print(f"Hook: 0x{HOOK_ADDR:08X} (jal 0x{ORIG_FUNC:08X})", file=sys.stderr)
    print(f"Toggle: 0x{TOGGLE_ADDR:08X} (OFF=0x{toggle_off_branch:08X})", file=sys.stderr)
    print(f"Addresses: X=0x{x_pos_addr:08X} Y=0x{y_pos_addr:08X} LS=0x{line_spacing_addr:08X}", file=sys.stderr)

    lines = []

    # Part 0: Hook install (guarded) + button toggle (always)
    # Hook must NOT be installed before code cave is written — game would
    # jump to zeroed memory and crash. Use E-type to guard the hook write.
    #
    # E-type: if halfword at CODE_BASE+2 != 0x3C02, skip next N lines
    # (0x3C02 = upper half of "lui $v0, 0x08A9", the first cave instruction)

    # Collect all code/data writes (includes toggle default OFF)
    all_writes = cb.get_all_writes()
    code_lines = [cw_line_32(addr, val) for addr, val in all_writes]

    # Sentinel: use the LAST written address. All E-type guards check this.
    # Parts 2..N-1 write earlier addresses → sentinel stays 0 → guards pass.
    # Part N writes the last chunk including sentinel → guards fail on next frame.
    last_addr, last_val = all_writes[-1]
    sentinel_hw = (last_val >> 16) & 0xFFFF  # upper halfword of last word
    sentinel_offset = to_cw_offset(last_addr)

    def etype_not_written(n_lines):
        """E-type: execute next n_lines only if sentinel NOT yet written."""
        return f"_L 0xE0{n_lines:02X}{sentinel_hw:04X} 0x1{sentinel_offset + 2:07X}"

    def etype_is_written(n_lines):
        """E-type: execute next n_lines only if sentinel IS written."""
        return f"_L 0xE1{n_lines:02X}{sentinel_hw:04X} 0x1{sentinel_offset + 2:07X}"

    part0 = []
    # Hook install — only after code cave is fully written
    part0.append(etype_is_written(1))
    part0.append(cw_line_32(HOOK_ADDR, JAL(CODE_BASE)))
    # L+Select = enable HP display (NOP at toggle)
    part0.append(cw_cond_16(BUTTON_ADDR, BTN_TOGGLE_ON))
    part0.append(cw_line_32(TOGGLE_ADDR, NOP()))
    # R+Select = disable HP display (branch at toggle)
    part0.append(cw_cond_16(BUTTON_ADDR, BTN_TOGGLE_OFF))
    part0.append(cw_line_32(TOGGLE_ADDR, toggle_off_branch))

    MAX_PER_PART = 20
    parts = [part0]
    for i in range(0, len(code_lines), MAX_PER_PART):
        chunk = code_lines[i:i+MAX_PER_PART]
        n_lines = len(chunk)
        etype_line = etype_not_written(n_lines)
        parts.append([etype_line] + chunk)

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

    for label, val, default in [
        ("HP Font 6",  0x06, False),
        ("HP Font 8",  0x08, False),
        ("HP Font 10", 0x0A, True),
        ("HP Font 14", 0x0E, False),
    ]:
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_8(FONT_SIZE_ADDR, val))

    lines.append("")

    for label, val, default in [
        ("HP X=6",   0x0006, False),
        ("HP X=20",  0x0014, False),
        ("HP X=100", 0x0064, False),
    ]:
        instr = ORI('$a2', '$zero', val)
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_32(x_pos_addr, instr))

    lines.append("")

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

    for label, val, default in [
        ("HP Stack Down 10px", 0x000A, False),
        ("HP Stack Down 14px", 0x000E, False),
        ("HP Stack Down 20px", 0x0014, False),
    ]:
        instr = ADDIU('$s1', '$s1', val)
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_32(line_spacing_addr, instr))

    lines.append("")

    for label, val, default in [
        ("HP Color White", 0x00, True),
        ("HP Color Grey",  0x0A, False),
    ]:
        lines.append(f"_C{'1' if default else '0'} {label}")
        lines.append(cw_line_8(COLOR_ADDR, val))

    lines.append("")

    lines.append("_C0 HP Absolute")
    lines.append(cw_line_8(DISPLAY_MODE_ADDR, 0x00))
    lines.append("_C1 HP Percent")
    lines.append(cw_line_8(DISPLAY_MODE_ADDR, 0x01))

    return '\n'.join(lines)


if __name__ == '__main__':
    output = generate()
    print(output)
