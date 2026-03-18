#!/usr/bin/env python3
"""Find ALL unique jal targets from the HUD overlay area to identify sharpness renderer."""

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

data = decompress_ppst(PPST_FILE)

# Scan the entire game_task overlay area for jal instructions to eboot functions
# The overlay is loaded at 0x09C57C80, spans a large area
# Focus on areas near known HUD code

# First: find ALL jal targets from 0x09D50000-0x09D70000 (broad HUD area)
print("=== ALL jal targets from overlay HUD area (0x09D50000-0x09D70000) ===")
jal_targets = {}
for addr in range(0x09D50000, 0x09D70000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        if target not in jal_targets:
            jal_targets[target] = []
        jal_targets[target].append(addr)

# Sort by target address and show
for target in sorted(jal_targets.keys()):
    callers = jal_targets[target]
    # Mark eboot vs overlay
    loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
    print(f"  0x{target:08X} ({loc}) called {len(callers)}x from:",
          " ".join(f"0x{c:08X}" for c in callers[:10]),
          "..." if len(callers) > 10 else "")

# Now specifically look at the sharpness area (0x09D5D000-0x09D5F000)
print(f"\n=== jal targets specifically from sharpness area (0x09D5D000-0x09D5F000) ===")
for target in sorted(jal_targets.keys()):
    callers_in_sharp = [c for c in jal_targets[target] if 0x09D5D000 <= c < 0x09D5F000]
    if callers_in_sharp:
        loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
        print(f"  0x{target:08X} ({loc}) called {len(callers_in_sharp)}x from:",
              " ".join(f"0x{c:08X}" for c in callers_in_sharp))

# Also check: are there jalr (indirect calls) in the sharpness area?
print(f"\n=== jalr instructions in sharpness area (0x09D5D000-0x09D5F000) ===")
for addr in range(0x09D5D000, 0x09D5F000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    func = instr & 0x3F
    if op == 0 and func == 0x09:  # jalr
        rs = (instr >> 21) & 0x1F
        rd = (instr >> 11) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        print(f"  0x{addr:08X}: jalr {REGS[rd]}, {REGS[rs]}")

# Check: what about the broader area 0x09D5A000-0x09D5D000?
print(f"\n=== jal targets from 0x09D5A000-0x09D5D000 (before sharpness) ===")
jal2 = {}
for addr in range(0x09D5A000, 0x09D5D000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        if target not in jal2:
            jal2[target] = []
        jal2[target].append(addr)

for target in sorted(jal2.keys()):
    callers = jal2[target]
    loc = "EBOOT" if target < 0x09000000 else "OVERLAY"
    print(f"  0x{target:08X} ({loc}) called {len(callers)}x from:",
          " ".join(f"0x{c:08X}" for c in callers[:10]),
          "..." if len(callers) > 10 else "")

print("\nDone!")
