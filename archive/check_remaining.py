#!/usr/bin/env python3
"""Check remaining $t0/$t1 settings near render calls in HP bar functions."""

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

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm_short(instr, addr):
    op = instr >> 26; rs = (instr >> 21) & 0x1F; rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F; func = instr & 0x3F
    imm = instr & 0xFFFF; simm = imm if imm < 0x8000 else imm - 0x10000
    if instr == 0: return "nop"
    if op == 0:
        if func == 0x21: return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x09: return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x08: return f"jr {REGS[rs]}"
    if op == 0x09: return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x03: return f"jal 0x{(instr & 0x03FFFFFF) << 2:08X}"
    return f"0x{instr:08X}"

data = decompress_ppst(PPST_FILE)

# Check 10 instructions before each render call
render_calls = [
    (0x09D618D4, "bg_BF0 in 0x09D61838"),
    (0x09D61930, "bg_BF0 in 0x09D61838 #2"),
    (0x09D6195C, "bg_BF0 in 0x09D61838 #3"),
    (0x09D619E0, "bg_BF0 in 0x09D61838 #4"),
    (0x09D61A9C, "bg_BF0 in 0x09D61838 #5"),
    (0x09D61630, "sprite_1168 in 0x09D61558"),
    (0x09D61520, "bg_BF0 in 0x09D614EC"),
    (0x09D619B0, "sprite_1000 in 0x09D61838"),
]

for call_addr, desc in render_calls:
    print(f"\n--- Before {desc} at 0x{call_addr:08X} ---")
    for k in range(8, 0, -1):
        a = call_addr - k * 4
        off = psp_to_offset(a)
        instr = read_u32(data, off)
        d = disasm_short(instr, a)
        mark = ""
        if "$t0" in d: mark = " <<< T0"
        if "$t1" in d: mark = " <<< T1"
        if "$t2" in d: mark = " <<< T2"
        print(f"  0x{a:08X}: {d}{mark}")
    print(f"  0x{call_addr:08X}: {disasm_short(read_u32(data, psp_to_offset(call_addr)), call_addr)} [CALL]")

print("\nDone!")
