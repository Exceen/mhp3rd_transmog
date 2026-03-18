#!/usr/bin/env python3
"""
Minimal HP display test — renders "HP TEST" unconditionally.
Tests whether the hook fires and text rendering works.
"""

import struct

# MIPS assembler (minimal)
_REG = {
    '$zero': 0, '$at': 1, '$v0': 2, '$v1': 3,
    '$a0': 4, '$a1': 5, '$a2': 6, '$a3': 7,
    '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11,
    '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19,
    '$s4': 20, '$s5': 21,
    '$t6': 14, '$t7': 15,
    '$sp': 29, '$fp': 30, '$ra': 31,
}
def reg(name):
    return _REG[name] if isinstance(name, str) else name

def NOP():       return 0x00000000
def JR(rs):      return (reg(rs) << 21) | 0x08
def J(target):   return (0x02 << 26) | ((target >> 2) & 0x03FFFFFF)
def JAL(target): return (0x03 << 26) | ((target >> 2) & 0x03FFFFFF)
def LUI(rt, imm): return (0x0F << 26) | (reg(rt) << 16) | (imm & 0xFFFF)
def ORI(rt, rs, imm): return (0x0D << 26) | (reg(rs) << 21) | (reg(rt) << 16) | (imm & 0xFFFF)
def LI(rt, imm): return ORI(rt, '$zero', imm)
def LW(rt, off, base): return (0x23 << 26) | (reg(base) << 21) | (reg(rt) << 16) | (off & 0xFFFF)
def SW(rt, off, base): return (0x2B << 26) | (reg(base) << 21) | (reg(rt) << 16) | (off & 0xFFFF)
def SB(rt, off, base): return (0x28 << 26) | (reg(base) << 21) | (reg(rt) << 16) | (off & 0xFFFF)
def SH(rt, off, base): return (0x29 << 26) | (reg(base) << 21) | (reg(rt) << 16) | (off & 0xFFFF)
def ADDIU(rt, rs, imm): return (0x09 << 26) | (reg(rs) << 21) | (reg(rt) << 16) | (imm & 0xFFFF)
def MOVE(rd, rs): return (reg(rs) << 16) | (reg(rd) << 11) | 0x21  # ADDU rd, $zero, rs

# Game constants
CW_BASE         = 0x08800000
CODE_BASE       = 0x097F0000
DATA_BASE       = 0x097F1000
SET_FONT_SIZE   = 0x088E6FF0
TEXT_RENDER     = 0x088EAA64
RENDER_CTX_PTR  = 0x09BF  # LUI base (actual addr after sign-ext = 0x09BE9F18... or 0x09BF9F18?)
RENDER_CTX_OFF  = 0x9F18  # LW offset (sign-extended)

# Three candidate hook points to test
HOOKS = [
    ("0x0888C630", 0x0888C630),  # HUD text function
    ("0x088E6DE0", 0x088E6DE0),  # Text render wrapper
    ("0x08821738", 0x08821738),  # Top-level render callback
]

def to_cw(addr, val):
    return f"_L 0x2{(addr - CW_BASE):07X} 0x{val & 0xFFFFFFFF:08X}"

def to_cw8(addr, val):
    return f"_L 0x0{(addr - CW_BASE):07X} 0x000000{val & 0xFF:02X}"

def emit_string_words(s):
    data = s.encode('utf-8') + b'\x00'
    while len(data) % 4 != 0:
        data += b'\x00'
    words = []
    for i in range(0, len(data), 4):
        words.append(struct.unpack('<I', data[i:i+4])[0])
    return words

def generate_test(hook_addr, hook_name):
    """Generate minimal test: hook -> save regs -> render 'HP TEST' -> restore -> JR $ra"""
    lines = []

    # Format string at DATA_BASE
    fmt_words = emit_string_words("HP TEST")

    code = []
    pc = CODE_BASE

    # Prologue: save $ra, $v0, $v1, $a0-$a3
    code.append(ADDIU('$sp', '$sp', 0xFFE0))   # -32
    code.append(SW('$ra', 28, '$sp'))
    code.append(SW('$v0', 24, '$sp'))
    code.append(SW('$v1', 20, '$sp'))
    code.append(SW('$a0', 16, '$sp'))
    code.append(SW('$a1', 12, '$sp'))
    code.append(SW('$a2', 8, '$sp'))
    code.append(SW('$a3', 4, '$sp'))

    # Load render context
    code.append(LUI('$v0', RENDER_CTX_PTR))      # $v0 = 0x09BF0000
    code.append(LW('$a0', RENDER_CTX_OFF, '$v0')) # $a0 = render context

    # Set font size: set_font_size(context, 14, 14)
    code.append(LI('$a1', 14))
    code.append(JAL(SET_FONT_SIZE))
    code.append(LI('$a2', 14))                    # delay slot

    # Reload render context (clobbered by SET_FONT_SIZE)
    code.append(LUI('$v0', RENDER_CTX_PTR))
    code.append(LW('$a0', RENDER_CTX_OFF, '$v0'))

    # Set style, X, Y on render context
    code.append(LI('$v1', 0x0A))                  # color/style = 10
    code.append(SB('$v1', 0x012E, '$a0'))          # context+0x12E = style
    code.append(LI('$v1', 6))                      # X = 6
    code.append(SH('$v1', 0x0120, '$a0'))          # context+0x120 = X
    code.append(LI('$v1', 134))                    # Y = 134
    code.append(SH('$v1', 0x0122, '$a0'))          # context+0x122 = Y

    # Call text_render(context, "HP TEST")
    code.append(LUI('$a1', (DATA_BASE >> 16) & 0xFFFF))
    code.append(ORI('$a1', '$a1', DATA_BASE & 0xFFFF))  # $a1 = fmt string
    code.append(JAL(TEXT_RENDER))
    code.append(NOP())

    # Epilogue: restore regs
    code.append(LW('$a3', 4, '$sp'))
    code.append(LW('$a2', 8, '$sp'))
    code.append(LW('$a1', 12, '$sp'))
    code.append(LW('$a0', 16, '$sp'))
    code.append(LW('$v1', 20, '$sp'))
    code.append(LW('$v0', 24, '$sp'))
    code.append(LW('$ra', 28, '$sp'))
    code.append(ADDIU('$sp', '$sp', 0x0020))
    code.append(JR('$ra'))
    code.append(NOP())

    # Emit hook (unconditional — always active)
    lines.append(f"_C1 HP Test {hook_name}")
    lines.append(to_cw(hook_addr, J(CODE_BASE)))

    # Emit code
    for i, word in enumerate(code):
        lines.append(to_cw(CODE_BASE + i * 4, word))

    # Emit format string
    for i, word in enumerate(fmt_words):
        lines.append(to_cw(DATA_BASE + i * 4, word))

    lines.append("")
    return lines

# Generate tests for all three hook candidates
all_lines = []
all_lines.append("; === HP Display Hook Tests ===")
all_lines.append("; Enable ONLY ONE at a time to test which hook point works")
all_lines.append("")

for name, addr in HOOKS:
    test = generate_test(addr, name)
    # First one enabled, rest disabled
    if addr == HOOKS[0][1]:
        all_lines.extend(test)
    else:
        # Change _C1 to _C0
        test[0] = test[0].replace("_C1", "_C0")
        all_lines.extend(test)

print('\n'.join(all_lines))
