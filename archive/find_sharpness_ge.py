#!/usr/bin/env python3
"""Find how the sharpness indicator is rendered - look for GE display list submission."""

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

# sceGeListEnQueue = 0x08960CF8 (from kurogami's code)
# Search for jal to this function from the entire overlay area
jal_ge = 0x0C000000 | (0x08960CF8 >> 2)
print("=== Calls to sceGeListEnQueue (0x08960CF8) from overlay ===")
for addr in range(0x09C50000, 0x09D80000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_ge:
        print(f"  0x{addr:08X}: jal sceGeListEnQueue")

# Also search in eboot render area
print("\n=== Calls to sceGeListEnQueue from eboot (0x0888-0x0892) ===")
for addr in range(0x08880000, 0x08920000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    if instr == jal_ge:
        print(f"  0x{addr:08X}: jal sceGeListEnQueue")

# Search for sceGuDrawArray or sceGuStart - common GE rendering functions
# Let's look for other sceGe/sceGu function calls
# First find the import stubs - they're usually at fixed addresses
# sceGu functions are typically wrappers that build GE command lists
# Let's look for what functions the overlay HUD area calls that we haven't tested

# Let me also check: what eboot functions are called from the ENTIRE overlay
# that we haven't tested yet, specifically in rendering-related ranges
print("\n=== Untested eboot functions called from 0x09D5A000-0x09D70000 ===")
tested = {0x089012D8, 0x088C926C, 0x08900464, 0x088FA2B0, 0x0884C3C0,
           0x089035C0, 0x08902688, 0x08904570, 0x0880E1D4, 0x088FF8F0}
jal_targets = {}
for addr in range(0x09D5A000, 0x09D70000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x03:  # jal
        target = (instr & 0x03FFFFFF) << 2
        if target < 0x09000000 and target not in tested:  # eboot only, untested
            if target not in jal_targets:
                jal_targets[target] = []
            jal_targets[target].append(addr)

for target in sorted(jal_targets.keys()):
    callers = jal_targets[target]
    print(f"  0x{target:08X} called {len(callers)}x")

# Now let's also look at what sceGu* stubs exist
# PSP SDK stubs are typically in a specific range
# Let's find all jal targets in the 0x0895-0x0897 range (SDK stubs area)
print("\n=== SDK-area function calls (0x0895-0x0897) from HUD overlay ===")
sdk_calls = {}
for addr in range(0x09D5A000, 0x09D70000, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data): break
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        if 0x08950000 <= target < 0x08970000:
            if target not in sdk_calls:
                sdk_calls[target] = []
            sdk_calls[target].append(addr)

for target in sorted(sdk_calls.keys()):
    callers = sdk_calls[target]
    print(f"  0x{target:08X} called {len(callers)}x from:",
          " ".join(f"0x{c:08X}" for c in callers[:5]),
          "..." if len(callers) > 5 else "")

print("\nDone!")
