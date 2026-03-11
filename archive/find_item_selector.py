#!/usr/bin/env python3
"""Find item selector rendering code by scanning overlay for render function callers."""

import struct
import zstandard as zstd

PPST_FILE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_4.ppst"
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

def decompress_ppst(path):
    with open(path, 'rb') as f:
        f.seek(0xB0)
        compressed = f.read()
    return zstd.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    if off + 4 > len(data): return None
    return struct.unpack_from('<I', data, off)[0]

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
        if func == 0x18: return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x10: return f"mfhi {REGS[rd]}"
        if func == 0x12: return f"mflo {REGS[rd]}"
        return f"special func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F: return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C: return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0A: return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"
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
        if rt == 0x01: return f"bgez {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
        if rt == 0x00: return f"bltz {REGS[rs]}, 0x{addr + 4 + (simm << 2):08X}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x02: return f"j 0x{(instr & 0x03FFFFFF) << 2:08X}"
    if op == 0x1F: return f"special3 raw=0x{instr:08X}"
    return f"op=0x{op:02X} raw=0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

RENDER_FUNCS = {
    0x0890112C: "SPRITE_112C",
    0x08901000: "SPRITE_1000",
    0x08901168: "SPRITE_1168",
    0x089012D8: "RENDER_12D8",
    0x088FF8F0: "SPRITE_F8F0",
    0x08901C48: "BAR_1C48",
    0x08900BF0: "BG_BF0",
    0x088FFF0C: "SPRITE_FF0C",
}

KNOWN_FUNCS = {
    0x09D60280: "CLOCK1",
    0x09D6172C: "CLOCK2",
    0x09D5E8D0: "COMMON1 (sharpness bg setup)",
    0x09D5E9C0: "COMMON2 (sharpness bg render)",
    0x09D648AC: "OWN_HP_STAMINA",
    0x09D6380C: "PLAYER_LIST_NAMES",
    0x09D624D4: "PLAYER_LIST_HP",
    0x09D6309C: "PLAYER_LIST_BARS",
    0x09D62B30: "PLAYER_LIST_LOOP2",
}

# Step 1: Dump the main HUD parent function 0x09D6C498 to find ALL jal targets
print("=== PARENT HUD FUNCTION 0x09D6C498 - ALL JAL CALLS ===")
parent_calls = []
for addr in range(0x09D6C498, 0x09D6CC00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    op = instr >> 26
    if op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        name = KNOWN_FUNCS.get(target, RENDER_FUNCS.get(target, ""))
        parent_calls.append((addr, target, name))
        print(f"  0x{addr:08X}: jal 0x{target:08X}  {name}")

# Step 2: Find ALL overlay functions that call render functions
print("\n\n=== OVERLAY RENDER FUNCTION CALLERS (0x09C50000-0x09DA0000) ===")

# Group callers by containing function (approximate: find nearest function start)
render_callers = {}  # caller_addr -> (target_name, target_addr)

for addr in range(0x09C50000, 0x09DA0000, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    op = instr >> 26
    if op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS:
            render_callers[addr] = (RENDER_FUNCS[target], target)
    elif op == 0x02:  # j (tail call)
        target = (instr & 0x03FFFFFF) << 2
        if target in RENDER_FUNCS:
            render_callers[addr] = ("TAIL:" + RENDER_FUNCS[target], target)

# Group by 0x100-aligned blocks to approximate function grouping
from collections import defaultdict
blocks = defaultdict(list)
for caller, (name, target) in sorted(render_callers.items()):
    # Find function start: scan backwards for addiu $sp,$sp,-N
    func_start = None
    for scan in range(caller, caller - 0x400, -4):
        soff = psp_to_offset(scan)
        si = read_u32(data, soff)
        if si is None: break
        # addiu $sp, $sp, -N (negative immediate, op=0x09, rs=rt=$sp=29)
        if (si >> 16) == 0x27BD and (si & 0x8000):  # addiu $sp,$sp,-N
            func_start = scan
            break
    if func_start is None:
        func_start = caller & 0xFFFFFF00
    blocks[func_start].append((caller, name, target))

print(f"\nFound {len(render_callers)} render calls in {len(blocks)} functions:\n")

for func_start in sorted(blocks.keys()):
    calls = blocks[func_start]
    known = KNOWN_FUNCS.get(func_start, "")
    # Check if this function is called from parent
    parent_target = any(t == func_start for _, t, _ in parent_calls)
    marker = " [CALLED FROM PARENT]" if parent_target else ""
    print(f"  Function 0x{func_start:08X}{' (' + known + ')' if known else ''}{marker}:")
    for caller, name, target in calls:
        print(f"    0x{caller:08X}: {name}")
    print()

# Step 3: Find parent calls to functions NOT yet identified
print("\n=== UNIDENTIFIED PARENT CALLS ===")
for addr, target, name in parent_calls:
    if not name and target not in render_callers:
        # Check if this target calls any render functions
        sub_calls = []
        for scan in range(target, target + 0x800, 4):
            soff = psp_to_offset(scan)
            si = read_u32(data, soff)
            if si is None: break
            sop = si >> 26
            if sop == 0x03:
                st = (si & 0x03FFFFFF) << 2
                if st in RENDER_FUNCS:
                    sub_calls.append((scan, RENDER_FUNCS[st]))
            # Stop at jr $ra
            if si & 0xFC00003F == 0x00000008 and ((si >> 21) & 0x1F) == 31:
                break
        if sub_calls:
            print(f"  0x{addr:08X}: jal 0x{target:08X} -> renders:")
            for sc, sn in sub_calls:
                print(f"    0x{sc:08X}: {sn}")

print("\nDone!")
