#!/usr/bin/env python3
"""Verify the raw instruction at 0x09D6C988 and test alternative hook approaches."""

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
    return struct.unpack_from('<I', data, off)[0]

data = decompress_ppst(PPST_FILE)

# Verify raw instruction at 0x09D6C988
print("=== RAW INSTRUCTION VERIFICATION ===")
for addr in range(0x09D6C980, 0x09D6C9A0, 4):
    off = psp_to_offset(addr)
    raw = read_u32(data, off)
    print(f"  0x{addr:08X}: raw=0x{raw:08X}")
    # Decode
    op = raw >> 26
    if op == 3:  # jal
        target = (raw & 0x03FFFFFF) << 2
        print(f"    -> jal 0x{target:08X}")
    elif op == 2:  # j
        target = (raw & 0x03FFFFFF) << 2
        print(f"    -> j 0x{target:08X}")
    elif raw == 0:
        print(f"    -> nop")
    elif op == 0:
        func = raw & 0x3F
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        rd = (raw >> 11) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        if func == 0x21:
            print(f"    -> addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}")
        elif func == 0x08:
            print(f"    -> jr {REGS[rs]}")
    elif op == 9:
        rs = (raw >> 21) & 0x1F
        rt = (raw >> 16) & 0x1F
        imm = raw & 0xFFFF
        simm = imm if imm < 0x8000 else imm - 0x10000
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        print(f"    -> addiu {REGS[rt]}, {REGS[rs]}, {simm}")

# Check if code cave area is truly free
print("\n=== CODE CAVE AREA 0x08800380-0x088003A0 ===")
for addr in range(0x08800380, 0x088003A0, 4):
    off = psp_to_offset(addr)
    raw = read_u32(data, off)
    status = "FREE" if raw == 0 else f"USED: 0x{raw:08X}"
    print(f"  0x{addr:08X}: {status}")

# Check if 0x08800200 area (weapon transmog cave) exists
print("\n=== WEAPON TRANSMOG CAVE 0x08800200-0x08800220 ===")
for addr in range(0x08800200, 0x08800220, 4):
    off = psp_to_offset(addr)
    raw = read_u32(data, off)
    print(f"  0x{addr:08X}: 0x{raw:08X}")

# Verify existing working hook at 0x088F1D0C
print("\n=== EXISTING WORKING HOOK at 0x088F1D0C ===")
off = psp_to_offset(0x088F1D0C)
raw = read_u32(data, off)
print(f"  0x088F1D0C: raw=0x{raw:08X}")
op = raw >> 26
if op == 2:
    target = (raw & 0x03FFFFFF) << 2
    print(f"    -> j 0x{target:08X}")
elif op == 3:
    target = (raw & 0x03FFFFFF) << 2
    print(f"    -> jal 0x{target:08X}")
else:
    print(f"    -> opcode {op}")

# Also check: what's the original instruction at 0x088F1D0C (without cheat)?
# The cheat writes j 0x08800200 = 0x0A200080
# The original should be: lhu $a3, 0x492($v0)
# lhu = opcode 0x25, rs=$v0(2), rt=$a3(7), imm=0x492
# = 0x94470492
print(f"  Expected original: lhu $a3, 0x492($v0) = 0x94470492")

# Check what instruction the game uses to call from overlay to eboot
# Look at existing overlay->eboot calls near our hook point
print("\n=== OVERLAY->EBOOT CALLS NEAR 0x09D6C988 ===")
for addr in range(0x09D6C498, 0x09D6C9A0, 4):
    off = psp_to_offset(addr)
    raw = read_u32(data, off)
    op = raw >> 26
    if op == 3:  # jal
        target = (raw & 0x03FFFFFF) << 2
        if 0x08800000 <= target <= 0x08A00000:
            print(f"  0x{addr:08X}: jal 0x{target:08X} (OVERLAY->EBOOT)")
    elif op == 2:  # j
        target = (raw & 0x03FFFFFF) << 2
        if 0x08800000 <= target <= 0x08A00000:
            print(f"  0x{addr:08X}: j 0x{target:08X} (OVERLAY->EBOOT)")

# Verify encoding of our hook instruction
print("\n=== HOOK ENCODING VERIFICATION ===")
# jal 0x08800380
target = 0x08800380
jal_enc = (3 << 26) | (target >> 2)
j_enc = (2 << 26) | (target >> 2)
print(f"  jal 0x{target:08X} = 0x{jal_enc:08X}")
print(f"  j   0x{target:08X} = 0x{j_enc:08X}")

# Verify cave instructions
print("\n=== CAVE INSTRUCTION ENCODING ===")
# jal 0x09D60D88
target = 0x09D60D88
enc = (3 << 26) | (target >> 2)
print(f"  jal 0x{target:08X} = 0x{enc:08X}")
# j 0x09D6C7E8
target = 0x09D6C7E8
enc = (2 << 26) | (target >> 2)
print(f"  j   0x{target:08X} = 0x{enc:08X}")

print("\nDone!")
