#!/usr/bin/env python3
"""Check the NOP delay slots in 0x09D648AC that we can patch for HP bar X offset."""

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

data = decompress_ppst(PPST_FILE)

# Check the two jal 0x08901000 call sites in 0x09D648AC
# From v12 analysis:
# First call: 0x09D64914 jal 0x08901000, 0x09D64918 nop
# Second call: 0x09D6497C jal 0x08901000, 0x09D64980 nop
call_sites = [
    (0x09D64914, 0x09D64918),  # first call + delay slot
    (0x09D6497C, 0x09D64980),  # second call + delay slot
]

for jal_addr, ds_addr in call_sites:
    jal_off = psp_to_offset(jal_addr)
    ds_off = psp_to_offset(ds_addr)
    jal_instr = read_u32(data, jal_off)
    ds_instr = read_u32(data, ds_off)
    jal_target = (jal_instr & 0x03FFFFFF) << 2
    cw = ds_addr - 0x08800000
    print(f"0x{jal_addr:08X}: 0x{jal_instr:08X} -> jal 0x{jal_target:08X}")
    print(f"0x{ds_addr:08X} (CW 0x{cw:07X}): 0x{ds_instr:08X} -> {'nop' if ds_instr == 0 else 'NOT NOP!'}")

    # Also show the lh $t0 before each call
    for prev in range(jal_addr - 24, jal_addr, 4):
        prev_off = psp_to_offset(prev)
        pi = read_u32(data, prev_off)
        op = pi >> 26
        rt = (pi >> 16) & 0x1F
        if op == 0x21 and rt == 8:  # lh $t0
            rs = (pi >> 21) & 0x1F
            imm = pi & 0xFFFF
            simm = imm if imm < 0x8000 else imm - 0x10000
            REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                    '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                    '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                    '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
            print(f"  Before: 0x{prev:08X}: lh $t0, {simm}({REGS[rs]})")
    print()

# Also check if there's a third call to 0x08901000
target_jal = (0x03 << 26) | (0x08901000 >> 2)
print("All calls to 0x08901000 in 0x09D648AC-0x09D64B00:")
for addr in range(0x09D648AC, 0x09D64B00, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr == target_jal:
        ds_off = psp_to_offset(addr + 4)
        ds = read_u32(data, ds_off)
        cw_ds = (addr + 4) - 0x08800000
        print(f"  0x{addr:08X}: jal 0x08901000, delay slot @ 0x{addr+4:08X} (CW 0x{cw_ds:07X}) = 0x{ds:08X} ({'nop' if ds == 0 else 'NOT nop'})")

print("\nDone!")
