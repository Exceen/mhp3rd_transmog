#!/usr/bin/env python3
"""Trace the item selector active flag pointer chain from save state."""

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

def read_u8(data, off):
    return struct.unpack_from('<B', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

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

# =============================================
# 1. Dump function 0x088B51B8 (returns object pointer)
# =============================================
print("=== FUNCTION 0x088B51B8 (returns selector object) ===")
jr_count = 0
for addr in range(0x088B51B8, 0x088B51B8 + 400, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: {d}")
    if "jr $ra" in d:
        jr_count += 1
        if jr_count >= 1:
            break

# =============================================
# 2. Dump function 0x088A3984 (reads byte at obj+98)
# =============================================
print("\n=== FUNCTION 0x088A3984 (checks selector state) ===")
jr_count = 0
for addr in range(0x088A3984, 0x088A3984 + 200, 4):
    off = psp_to_offset(addr)
    instr = read_u32(data, off)
    if instr is None: break
    d = disasm(instr, addr)
    print(f"  0x{addr:08X}: {d}")
    if "jr $ra" in d:
        jr_count += 1
        if jr_count >= 1:
            break

# =============================================
# 3. Trace the pointer chain from known globals
# =============================================
print("\n\n=== POINTER CHAIN TRACE ===")

# Step 1: Read *(0x09BB7A80) - global pointer
ptr1_addr = 0x09BB7A80
ptr1_off = psp_to_offset(ptr1_addr)
ptr1_val = read_u32(data, ptr1_off)
print(f"  *(0x{ptr1_addr:08X}) = 0x{ptr1_val:08X}")

# Step 2: Read *(0x08AACE80) - another global
ptr2_addr = 0x08AACE80
ptr2_off = psp_to_offset(ptr2_addr)
ptr2_val = read_u32(data, ptr2_off)
print(f"  *(0x{ptr2_addr:08X}) = 0x{ptr2_val:08X}")

# Step 3: Read byte at ptr2_val + 38
if ptr2_val and 0x08000000 <= ptr2_val <= 0x0A000000:
    byte_off = psp_to_offset(ptr2_val + 38)
    byte_val = read_u8(data, byte_off)
    print(f"  byte at 0x{ptr2_val + 38:08X} (*(0x08AACE80)+38) = {byte_val}")

    # This byte is $a1 to 0x088B51B8
    # Step 4: Now we need to understand what 0x088B51B8 does with $a0=ptr1_val, $a1=byte_val
    # It should return an object pointer. Let's try to follow its logic from the disasm above.

# =============================================
# 4. Also check known UI context pointer locations
# =============================================
print("\n\n=== SEARCHING FOR UI CONTEXT (item selector) ===")

# The flag is at UI_context + 1814 (0x716)
# Let's check various likely global pointers that might hold the UI context

# Check 0x09BB0000 area (overlay BSS)
print("\nScanning 0x09BB0000-0x09BC0000 for pointers to 0x09D8xxxx-0x09DAxxxx range:")
found = []
for scan_addr in range(0x09BB0000, 0x09BC0000, 4):
    off = psp_to_offset(scan_addr)
    val = read_u32(data, off)
    if val and 0x09D80000 <= val <= 0x09DB0000:
        found.append((scan_addr, val))
if found:
    for addr, val in found[:30]:
        print(f"  0x{addr:08X} -> 0x{val:08X}")
        # Check if val + 1814 has a meaningful byte (0 or 1)
        flag_off = psp_to_offset(val + 1814)
        if flag_off + 1 <= len(data):
            flag_val = read_u8(data, flag_off)
            if flag_val <= 1:
                print(f"    -> byte at +1814 (0x{val+1814:08X}) = {flag_val} *** POSSIBLE FLAG ***")

# Also try scanning the 0x08AA-0x08AC area (eboot BSS)
print("\nScanning 0x08AA0000-0x08AC0000 for pointers to 0x09D8xxxx-0x09DAxxxx range:")
found2 = []
for scan_addr in range(0x08AA0000, 0x08AC0000, 4):
    off = psp_to_offset(scan_addr)
    val = read_u32(data, off)
    if val and 0x09D80000 <= val <= 0x09DB0000:
        found2.append((scan_addr, val))
if found2:
    for addr, val in found2[:30]:
        print(f"  0x{addr:08X} -> 0x{val:08X}")
else:
    print("  (none found)")

# =============================================
# 5. Alternative: check what 0x088B51B8 returns
#    by simulating its logic on the save state data
# =============================================
# We know: $a0 = ptr1_val, $a1 = byte_val
# Let's try to manually trace through the function

print("\n\n=== MANUAL TRACE OF 0x088B51B8 ===")
print(f"  $a0 = 0x{ptr1_val:08X}, $a1 = {byte_val}")

# Read some fields from the $a0 object
if ptr1_val and 0x08000000 <= ptr1_val <= 0x0A000000:
    for field_off in [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48]:
        off = psp_to_offset(ptr1_val + field_off)
        val = read_u32(data, off)
        if val is not None:
            print(f"  *(0x{ptr1_val:08X} + {field_off}) = 0x{val:08X}")

print("\nDone!")
