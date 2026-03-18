#!/usr/bin/env python3
"""
FINAL SUMMARY SCRIPT: Item selector active state variable in MHP3rd.

Findings:
- HUD object at 0x09DD0CF0 (in overlay BSS, found via vtable 0x09DCAE60)
- Item selector active flag: byte at object+0x54 = absolute 0x09DD0D44
- State machine byte: object+0x34 = absolute 0x09DD0D24
  - State 5 = item selector active
- Flag values: 0=not active, 1=active/rendering
- The flag is in overlay BSS which is loaded with the game_task overlay (0101.mwo)
  at base 0x09C57C80, so this address should be STABLE.

This script verifies the finding and checks if the object address is reachable
via a known global pointer chain.
"""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F; sa = (instr >> 6) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x08: return f"jr {REGS[rs]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23: return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25: return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00: return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02: return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"raw=0x{instr:08X}"

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

OBJ_ADDR = 0x09DD0CF0
FLAG_ADDR = OBJ_ADDR + 0x54  # 0x09DD0D44
STATE_ADDR = OBJ_ADDR + 0x34  # 0x09DD0D24

print(f"\n{'='*70}")
print("=== ITEM SELECTOR STATE VARIABLE ANALYSIS ===")
print(f"{'='*70}")
print(f"\nHUD Object address: 0x{OBJ_ADDR:08X}")
print(f"Vtable pointer at object+0: 0x{read_u32(data, psp_to_offset(OBJ_ADDR)):08X}")
print(f"State machine byte (object+0x34): {data[psp_to_offset(STATE_ADDR)]} (state 5 = item selector)")
print(f"Item selector flag (object+0x54): {data[psp_to_offset(FLAG_ADDR)]}")

# Dump some surrounding fields for context
print(f"\nObject field dump (first 0x60 bytes):")
for off in range(0, 0x60, 4):
    addr = OBJ_ADDR + off
    val = read_u32(data, psp_to_offset(addr))
    notes = ""
    if off == 0: notes = " (vtable ptr)"
    if off == 0x34: notes = " (state machine byte at +0x34)"
    if off == 0x54: notes = f" (item_sel_flag at +0x54, byte={data[psp_to_offset(addr)]})"
    print(f"  +0x{off:02X}: 0x{val:08X}{notes}")

# Check if this object address is referenced by a global pointer
print(f"\n{'='*70}")
print("=== Search for pointer to HUD object (0x{:08X}) ===".format(OBJ_ADDR))
print(f"{'='*70}")
obj_bytes = struct.pack('<I', OBJ_ADDR)
for region, start, end in [
    ("EBOOT_DATA", 0x08900000, 0x08C00000),
    ("OVERLAY", 0x09C57C80, 0x09E00000),
]:
    s = psp_to_offset(start)
    e = min(psp_to_offset(end), len(data))
    pos = s
    while pos < e:
        idx = data.find(obj_bytes, pos, e)
        if idx == -1: break
        pa = idx - MEM_OFFSET + PSP_BASE
        print(f"  Found at 0x{pa:08X} ({region})")
        pos = idx + 4

# The object is at 0x09DD0CF0 which is in overlay BSS
# It's likely a static/global object within the overlay, not heap-allocated
# Let's verify: is the address within the overlay code+data range?
overlay_base = 0x09C57C80
print(f"\n  Object offset from overlay base: 0x{OBJ_ADDR - overlay_base:X}")
print(f"  This is in the overlay's BSS/data section")

# Check if there's a simpler way: the object might be a known global
# Let's search for lui+addiu patterns that form this address
hi16 = (OBJ_ADDR >> 16) & 0xFFFF  # 0x09DD
# If low 16 is negative, lui is incremented by 1
lo16 = OBJ_ADDR & 0xFFFF  # 0x0CF0
if lo16 >= 0x8000:
    hi16 += 1
    lo16_signed = lo16 - 0x10000
else:
    lo16_signed = lo16

print(f"\n  Address decomposition: lui 0x{hi16:04X} + addiu {lo16_signed}")
# Search for lui $reg, 0x09DD in overlay code
lui_pattern = (0x0F << 26) | (hi16)  # lui with imm=0x09DD, rt=any
print(f"  Searching for 'lui $reg, 0x{hi16:04X}' near 'addiu/ori 0x{lo16:04X}':")
for addr in range(0x09C57C80, 0x09DA0000, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    op = instr >> 26
    imm = instr & 0xFFFF
    if op == 0x0F and imm == hi16:  # lui $reg, 0x09DD
        # Check next few instructions for addiu with lo16
        for delta in range(4, 20, 4):
            next_off = psp_to_offset(addr + delta)
            next_instr = read_u32(data, next_off)
            next_op = next_instr >> 26
            next_imm = next_instr & 0xFFFF
            if next_op == 0x09 and next_imm == (lo16 & 0xFFFF):  # addiu with lo16
                d1 = disasm(instr, addr)
                d2 = disasm(next_instr, addr + delta)
                print(f"    0x{addr:08X}: {d1}")
                print(f"    0x{addr+delta:08X}: {d2}")
                print()
                break

# Step 2: Verify the CWCheat address
cw_offset = FLAG_ADDR - 0x08800000
print(f"\n{'='*70}")
print("=== CWCheat Addresses ===")
print(f"{'='*70}")
print(f"\nItem Selector Active Flag:")
print(f"  PSP address: 0x{FLAG_ADDR:08X}")
print(f"  CWCheat offset: 0x{cw_offset:07X}")
print(f"  Read flag:  _L 0x0{cw_offset:07X} 0x00000001  (8-bit, 1=active)")
print(f"  NOTE: This is in overlay BSS - address is STATIC while overlay is loaded")

print(f"\nState Machine (which HUD mode is active):")
cw_state = STATE_ADDR - 0x08800000
print(f"  PSP address: 0x{STATE_ADDR:08X}")
print(f"  CWCheat offset: 0x{cw_state:07X}")
print(f"  States: 0=init, 1=opening_anim, 2=normal_scroll, 3-4=transitions,")
print(f"          5=item_selector, 6=closing, 7-9=page_transitions")

# Step 3: Also check the function 0x09D64440 (vtable+0xAC, the render dispatch)
# which calls vtable+0xA0 for item selector
# vtable+0xAC = 0x09DCAE60+0xAC = 0x09DCAF0C
print(f"\n{'='*70}")
print("=== Render dispatch function analysis ===")
print(f"{'='*70}")
vt_ac = read_u32(data, psp_to_offset(0x09DCAE60 + 0xAC))
print(f"vtable+0xAC = 0x{vt_ac:08X}")
print(f"This is the render function (0x09D64440) that calls vtable+0xA0 (item selector)")
print(f"It's called from the state machine when state==5 and flag==1")

# Cross-verify: at 0x09D6C14C, the flag is read as $a2 arg to 0x0884C6E0
# lbu $a2, 84($s2) at 0x09D6C14C
print(f"\n{'='*70}")
print("=== Flag used as render parameter ===")
print(f"{'='*70}")
print("At 0x09D6C14C: lbu $a2, 84($s2) -- flag loaded as 3rd arg")
print("At 0x09D6C158: jal 0x0884C6E0 -- called with ($s0, $v0, flag)")
print("This means the flag byte is ALSO passed to an EBOOT function as a parameter")
print("(likely controlling some render mode or layer)")

print(f"\n{'='*70}")
print("=== FINAL ANSWER ===")
print(f"{'='*70}")
print(f"""
ITEM SELECTOR ACTIVE STATE VARIABLE:
  Address: 0x{FLAG_ADDR:08X} (byte)
  Object: 0x{OBJ_ADDR:08X} + 0x54
  Values: 0 = item selector closed, 1 = item selector open/rendering
  Location: Overlay BSS (static while game_task overlay loaded)
  CWCheat: _L 0x0{cw_offset:07X} 0x00000001

STATE MACHINE VARIABLE (which HUD panel is active):
  Address: 0x{STATE_ADDR:08X} (byte)
  Object: 0x{OBJ_ADDR:08X} + 0x34
  State 5 = item selector panel
  CWCheat: _L 0x0{cw_state:07X} 0x00000005

VTABLE INFO:
  Vtable base: 0x09DCAE60
  +0xA0 = 0x09D60998 (item selector render)
  +0xE0 = 0x09D6B934 (HUD state machine update)
  +0xAC = 0x09D64440 (render dispatch, calls item selector)
""")

print("Done!")
