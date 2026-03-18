#!/usr/bin/env python3
"""Trace the item selector state by disassembling key functions.

The HUD object at 0x09DD0CF0 gets destroyed when item selector opens,
so we need to find the PARENT's state variable that controls this.

Key functions to analyze:
- 0x09D6C498: Parent function (main HUD render orchestrator)
- 0x09D6B934: vtable+0xE0 (HUD state machine update)
- 0x09D6C700-0x09D6CA00: The rendering section of the parent

We're looking for: a load instruction (lb/lbu/lh/lw) that reads a flag
which is checked to decide whether the item selector is open.
"""

import struct
import zstandard as zstd

PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

STATE_CLOSED = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_3.ppst"
STATE_OPEN   = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"

def load_state(path):
    with open(path, "rb") as f:
        data = f.read()
    compressed = data[0xB0:]
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=256*1024*1024)

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
        if func == 0x03: return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x24: return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A: return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B: return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0A: return f"movz {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x0B: return f"movn {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21: return f"lh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25: return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20: return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24: return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B: return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29: return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28: return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x04: return f"beq {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x05: return f"bne {REGS[rs]}, {REGS[rt]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x06: return f"blez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x07: return f"bgtz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x01:
        rt_v = rt
        if rt_v == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt_v == 0x11: return f"bgezal {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x31: return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39: return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11: return f"cop1 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

def dump_func(data, start, max_instrs=400, label=""):
    """Disassemble a function, stopping at jr $ra."""
    print(f"\n{'='*70}")
    print(f"=== {label} at 0x{start:08X} ===")
    print(f"{'='*70}")
    for i in range(max_instrs):
        addr = start + i * 4
        off = psp_to_offset(addr)
        if off + 4 > len(data):
            print(f"  0x{addr:08X}: OUT OF RANGE")
            break
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        m = ""
        if "jal " in d and "jalr" not in d:
            target = (instr & 0x03FFFFFF) << 2
            loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
            m = f" [{loc}]"
        if "jalr" in d:
            m = " [INDIRECT]"
        if "jr $ra" in d:
            m = " [RETURN]"
            print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")
            break
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{m}")

print("Loading save states...")
mem_c = load_state(STATE_CLOSED)
mem_o = load_state(STATE_OPEN)

# Use the closed state for disassembly (overlay code should be same in both)
data = mem_c

# First, let's look at the parent function 0x09D6C498
# This is the main HUD rendering orchestrator
dump_func(data, 0x09D6C498, 300, "Parent HUD orchestrator 0x09D6C498")

# Now let's look specifically at the section 0x09D6C700-0x09D6CA00
# which handles the rendering decisions
print(f"\n\n{'='*70}")
print("=== Detailed analysis of 0x09D6C700-0x09D6CA00 ===")
print(f"{'='*70}")
print("Looking for state checks (lb/lbu/lw followed by beq/bne):")
for addr in range(0x09D6C700, 0x09D6CA00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    d = disasm(instr, addr)
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    simm = (instr & 0xFFFF)
    if simm >= 0x8000: simm -= 0x10000

    # Highlight load and branch instructions
    is_load = op in (0x20, 0x24, 0x21, 0x25, 0x23)  # lb, lbu, lh, lhu, lw
    is_branch = op in (0x04, 0x05, 0x06, 0x07, 0x01)
    is_store = op in (0x28, 0x29, 0x2B)

    marker = ""
    if is_load:
        marker = " <<<< LOAD"
    elif is_branch:
        marker = " <<<< BRANCH"
    elif is_store:
        marker = " <<<< STORE"

    if marker or "jal" in d or "jr" in d:
        print(f"  0x{addr:08X}: 0x{instr:08X}  {d}{marker}")

# Let's also look at the vtable+0xE0 state machine update 0x09D6B934
dump_func(data, 0x09D6B934, 200, "State machine update vtable+0xE0")

# Now let's check: what is $s0/$s1/$s2/$fp in the parent function?
# The parent likely receives the HUD object as $a0, saves it to $sX
# Let's look at the prologue of 0x09D6C498 for register saves

# ALSO: Let's look for any timer/counter that differs between states
# Focus on the overlay DATA region near known UI addresses
print(f"\n\n{'='*70}")
print("=== Targeted state comparison: overlay DATA region ===")
print("=== Looking for small integer changes (animation state/timer) ===")
print(f"{'='*70}")

# Check specific regions known to have UI state
regions = [
    ("Overlay data 0x09D8E000-0x09D90000", 0x09D8E000, 0x09D90000),
    ("Overlay data 0x09D90000-0x09DA0000", 0x09D90000, 0x09DA0000),
    ("Overlay data 0x09DA0000-0x09DAA000", 0x09DA0000, 0x09DAA000),
    ("Overlay BSS 0x09DC0000-0x09DE0000", 0x09DC0000, 0x09DE0000),
]

for name, start, end in regions:
    changes = []
    for addr in range(start, end, 1):
        off = psp_to_offset(addr)
        if off >= len(mem_c) or off >= len(mem_o):
            break
        bc = mem_c[off]
        bo = mem_o[off]
        if bc != bo:
            changes.append((addr, bc, bo))

    if changes:
        print(f"\n  {name}: {len(changes)} byte differences")
        # Show only small integer changes (likely state flags, not floats/ptrs)
        for addr, bc, bo in changes:
            # Filter: only show if one of them is 0 and the other is small (1-10)
            if (bc == 0 and 1 <= bo <= 10) or (bo == 0 and 1 <= bc <= 10):
                # Check alignment and neighbors
                aligned4 = addr & ~3
                region_tag = ""
                if 0x09DA9300 <= addr <= 0x09DA9800:
                    region_tag = " [NEAR UI SCALES]"
                if 0x09DD0000 <= addr <= 0x09DE0000:
                    region_tag = " [NEAR HUD OBJECT]"
                print(f"    0x{addr:08X}: CLOSED={bc} OPEN={bo}{region_tag}")

# Also check the heap region for the HUD manager area
print(f"\n  Heap 0x09BF5200-0x09BF5C00:")
changes = []
for addr in range(0x09BF5200, 0x09BF5C00, 1):
    off = psp_to_offset(addr)
    bc = mem_c[off]
    bo = mem_o[off]
    if bc != bo and ((bc == 0 and 1 <= bo <= 10) or (bo == 0 and 1 <= bc <= 10)):
        changes.append((addr, bc, bo))
        print(f"    0x{addr:08X}: CLOSED={bc} OPEN={bo}")

# Now, let's check what's at the HUD object address in BOTH states
print(f"\n\n{'='*70}")
print("=== HUD object 0x09DD0CF0 comparison ===")
print(f"{'='*70}")
for off in range(0, 0x80, 4):
    addr = 0x09DD0CF0 + off
    vc = read_u32(mem_c, addr)
    vo = read_u32(mem_o, addr)
    m = " ***DIFF***" if vc != vo else ""
    notes = ""
    if off == 0: notes = " (vtable ptr)"
    if off == 0x34: notes = " (state machine?)"
    if off == 0x54: notes = " (flag?)"
    print(f"  +0x{off:02X}: C=0x{vc:08X}  O=0x{vo:08X}{m}{notes}")

print("\nDone!")
