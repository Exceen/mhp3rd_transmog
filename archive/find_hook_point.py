#!/usr/bin/env python3
"""Find a good per-frame eboot function to hook for the map flag cave.
Candidates:
- 0x08901168: sprite render (called many times per frame, but idempotent cave is fine)
- Functions near the game's main loop
- Input polling functions
"""

import struct
import zstandard as zstd

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

def disasm_simple(word, addr):
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    shamt = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target = (word & 0x03FFFFFF) << 2 | (addr & 0xF0000000)
    rn = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
          '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
          '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
          '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
    if word == 0: return "nop"
    if op == 0:
        if funct == 0x08: return f"jr {rn[rs]}"
        if funct == 0x09: return f"jalr {rn[rd]}, {rn[rs]}"
        if funct == 0x21: return f"addu {rn[rd]}, {rn[rs]}, {rn[rt]}"
        if funct == 0x00 and rd == 0: return "nop"
        if funct == 0x00: return f"sll {rn[rd]}, {rn[rt]}, {shamt}"
        return f"R op0 fn=0x{funct:02X} {rn[rs]} {rn[rt]} {rn[rd]}"
    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04: return f"beq {rn[rs]}, {rn[rt]}, 0x{addr+4+simm*4:08X}"
    if op == 0x05: return f"bne {rn[rs]}, {rn[rt]}, 0x{addr+4+simm*4:08X}"
    if op == 0x09: return f"addiu {rn[rt]}, {rn[rs]}, {simm}"
    if op == 0x0F: return f"lui {rn[rt]}, 0x{imm:04X}"
    if op == 0x23: return f"lw {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x2B: return f"sw {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x28: return f"sb {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x24: return f"lbu {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x25: return f"lhu {rn[rt]}, {simm}({rn[rs]})"
    if op == 0x0C: return f"andi {rn[rt]}, {rn[rs]}, 0x{imm:04X}"
    return f"op=0x{op:02X} {rn[rs]} {rn[rt]} imm=0x{imm:04X}"

data = decompress_ppst("/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_1.ppst")

# Check 0x08901168 (sprite render - called many times per frame)
print("=== 0x08901168 (sprite render) - first 8 instructions ===")
for i in range(8):
    addr = 0x08901168 + i*4
    word = read_u32(data, psp_to_offset(addr))
    print(f"  0x{addr:08X}: {word:08X}  {disasm_simple(word, addr)}")

# Check 0x088FF1F0 (called by sprite render)
print("\n=== 0x088FF1F0 (render helper) - first 8 instructions ===")
for i in range(8):
    addr = 0x088FF1F0 + i*4
    word = read_u32(data, psp_to_offset(addr))
    print(f"  0x{addr:08X}: {word:08X}  {disasm_simple(word, addr)}")

# Look for the game's main loop / VBlank wait
# sceDisplayWaitVblankStart is typically a syscall
# On PSP, syscalls are: syscall NNNN (R-type with funct=0x0C)
# Or jal to import stub
# Let's look for common game loop patterns
# Also check if there's a good function near the input handler

# Check the function at 0x088628BC (was used by transmog init)
print("\n=== 0x088628BC (former transmog init hook) ===")
for i in range(16):
    addr = 0x088628BC + i*4
    word = read_u32(data, psp_to_offset(addr))
    print(f"  0x{addr:08X}: {word:08X}  {disasm_simple(word, addr)}")

# Look for who calls 0x088628BC
# jal 0x088628BC = opcode 3 | (0x088628BC >> 2)
# 0x088628BC >> 2 = 0x02218A2F
# jal = 0x0C000000 | 0x02218A2F = 0x0E218A2F
target_jal = 0x0C000000 | (0x088628BC >> 2)
print(f"\n=== Searching for jal 0x088628BC (0x{target_jal:08X}) in eboot ===")
for addr in range(0x08800000, 0x08960000, 4):
    word = read_u32(data, psp_to_offset(addr))
    if word == target_jal:
        print(f"  Found at 0x{addr:08X}")
        # Show context
        for j in range(-4, 8):
            a = addr + j*4
            w = read_u32(data, psp_to_offset(a))
            marker = " <<<<" if j == 0 else ""
            print(f"    0x{a:08X}: {w:08X}  {disasm_simple(w, a)}{marker}")

# Also search for a simple function that just does sceDisplayWaitVblankStart
# or sceKernelDelayThread - common per-frame functions
# Let's search for the game's vsync/frame loop by finding sceDisplayWaitVblank
# import stubs at 0x08800000-0x08820000

# Search for nop-filled areas in eboot code cave space
print("\n=== FREE EBOOT SPACE (consecutive zeros) ===")
for addr in range(0x08800000, 0x08802000, 4):
    word = read_u32(data, psp_to_offset(addr))
    if word == 0:
        # Count consecutive zeros
        count = 0
        for check in range(addr, addr + 0x1000, 4):
            if read_u32(data, psp_to_offset(check)) == 0:
                count += 1
            else:
                break
        if count >= 8:
            print(f"  0x{addr:08X}: {count*4} bytes free (0x{count*4:X})")
            addr += count * 4  # skip ahead

# Check the very start of user memory for import stubs or vectors
print("\n=== 0x08804000 area (typical import stubs) ===")
for i in range(16):
    addr = 0x08804000 + i*4
    word = read_u32(data, psp_to_offset(addr))
    print(f"  0x{addr:08X}: {word:08X}  {disasm_simple(word, addr)}")

print("\nDone!")
