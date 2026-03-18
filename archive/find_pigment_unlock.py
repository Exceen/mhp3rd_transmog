#!/usr/bin/env python3
"""
Search for global pigment unlock flag and understand the pigment rendering pipeline.
"""
import struct, zstandard

PPST = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
STATE_OFFSET_BASE = 0x48

def psp_to_state(addr):
    return addr - PSP_BASE + STATE_OFFSET_BASE

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u8(data, off):
    return data[off]

def read_bytes(data, off, n):
    return data[off:off+n]

rnames = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
          's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']

def rn(r):
    return f"${rnames[r]}"

def disasm(word, addr):
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    sa = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target = (word & 0x03FFFFFF) << 2

    if op == 0:
        if funct == 0x00: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x19: return f"multu {rn(rs)}, {rn(rt)}"
        if funct == 0x10: return f"mfhi {rn(rd)}"
        return f"special func=0x{funct:02X} {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
    elif op == 0x01:
        if rt == 0x00: return f"bltz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        if rt == 0x01: return f"bgez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        return f"regimm rt={rt} {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x02: return f"j 0x{target:08X}"
    elif op == 0x03: return f"jal 0x{target:08X}"
    elif op == 0x04: return f"beq {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x05: return f"bne {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x06: return f"blez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x07: return f"bgtz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x08: return f"addi {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x09: return f"addiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0A: return f"slti {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0B: return f"sltiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0C: return f"andi {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0D: return f"ori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x20: return f"lb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x21: return f"lh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x24: return f"lbu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    else: return f"op=0x{op:02X} {rn(rt)}, {rn(rs)}, 0x{imm:04X}"

# Load save state
with open(PPST, 'rb') as f:
    raw = f.read()
compressed = raw[HEADER_SIZE:]
data = zstandard.ZstdDecompressor().decompress(compressed, max_output_size=64*1024*1024)
print(f"Decompressed: {len(data)} bytes")

# 1. Look at the pigment color table at 0x089E2388 (used by caller 0x0883D380 with result*3)
print("\n=== Pigment color table at 0x089E2388 (3-byte entries) ===")
for i in range(12):
    addr = 0x089E2388 + i * 3
    soff = psp_to_state(addr)
    r, g, b = data[soff], data[soff+1], data[soff+2]
    print(f"  Entry {i}: ({r:3d}, {g:3d}, {b:3d})  #{r:02X}{g:02X}{b:02X}")

# 2. Dump the RGBA pigment color table at 0x089E21E0
print("\n=== RGBA Pigment table at 0x089E21E0 (4-byte entries) ===")
color_names = ['White','Black','Red','Pink','Orange','Yellow','Green','Cyan','DarkBlue','Blue','Purple']
for i in range(11):
    addr = 0x089E21E0 + i * 4
    soff = psp_to_state(addr)
    val = read_u32(data, soff)
    r = (val >> 24) & 0xFF
    g = (val >> 16) & 0xFF
    b = (val >> 8) & 0xFF
    a = val & 0xFF
    name = color_names[i] if i < len(color_names) else f"?{i}"
    print(f"  [{i:2d}] {name:10s}: 0x{val:08X} = ({r},{g},{b},{a})")

# 3. Look at what's stored on the player entity
# The callers write to $s0+0x05AB. Let's find the player entity.
# global_ptr at 0x089C7508 -> player entity base is typically somewhere in that region
# Let's check the entity pigment field
print("\n=== Player entity pigment fields ===")
# From memory notes: global_ptr at 0x089C7508
gp_addr = 0x089C7508
gp_soff = psp_to_state(gp_addr)
gp_val = read_u32(data, gp_soff)
print(f"  global_ptr at 0x{gp_addr:08X} = 0x{gp_val:08X}")

# The player entity is usually at a fixed offset from the global pointer or a separate pointer
# Let's search for entity base by looking at the 0x05AB offset area
# The caller at 0x0883EB48 context shows:
#   lw $a0, 0x345C($s1)  -- $s1 has some base, 0x345C offset loads context
# Let's check 0x08A3345C (from lui 0x08A3 at caller 0x0883D374)
ctx_addr = 0x08A3345C
ctx_soff = psp_to_state(ctx_addr)
ctx_val = read_u32(data, ctx_soff)
print(f"  Context ptr at 0x{ctx_addr:08X} = 0x{ctx_val:08X}")

# 4. Now let's look at what happens BEFORE the callers are reached.
# Is there a global pigment unlock check that gates the callers?
# Let's look at the parent functions of key callers

# Caller 0x0883EB48 is in a function that starts somewhere before it
# Let's trace back to find the function start
print("\n=== Function containing caller 0x0883EB48 ===")
# Look for function prologue (addiu $sp, $sp, -N)
for addr in range(0x0883EB48, 0x0883EA00, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:  # addiu $sp, $sp, -N
        print(f"  Function starts at 0x{addr:08X}")
        # Dump from here
        for a in range(addr, min(addr + 0x80, 0x0883EB68), 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == 0x0883EB48 else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")
        break

# 5. Look at caller 0x0883D380 parent function
print("\n=== Function containing caller 0x0883D380 ===")
for addr in range(0x0883D380, 0x0883D200, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        print(f"  Function starts at 0x{addr:08X}")
        for a in range(addr, min(addr + 0x100, 0x0883D3D0), 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <-- jal get_pigment_flag" if a == 0x0883D380 else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")
        break

# 6. Search EBOOT for references to 0x05AB offset (entity pigment field)
# This might reveal where pigment is read for rendering or UI
print("\n=== Searching for lbu/lb with offset 0x05AB ===")
eboot_start = 0x08804000
eboot_end = 0x08900000  # approximate
count = 0
for addr in range(eboot_start, eboot_end, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data):
        break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    imm = word & 0xFFFF
    if imm == 0x05AB and op in (0x20, 0x24, 0x28):  # lb, lbu, sb
        print(f"  0x{addr:08X}: 0x{word:08X}  {disasm(word, addr)}")
        count += 1
print(f"  Found {count} references to offset 0x05AB")

# 7. Also check for references to 0x089E2388 (pigment color table)
print("\n=== Searching for references to pigment color table 0x089E2388 ===")
# lui 0x089E
count = 0
for addr in range(eboot_start, eboot_end, 4):
    soff = psp_to_state(addr)
    if soff + 8 > len(data):
        break
    word = read_u32(data, soff)
    if word == 0x3C02089E:  # lui $v0, 0x089E
        next_word = read_u32(data, soff + 4)
        next_imm = next_word & 0xFFFF
        if next_imm == 0x2388:
            print(f"  0x{addr:08X}: lui $v0, 0x089E")
            print(f"  0x{addr+4:08X}: 0x{next_word:08X}  {disasm(next_word, addr+4)}")
            count += 1
    # Also check with other registers
    op = (word >> 26) & 0x3F
    rt = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    if op == 0x0F and imm == 0x089E and rt != 2:
        next_word = read_u32(data, soff + 4)
        next_imm = next_word & 0xFFFF
        if next_imm == 0x2388:
            print(f"  0x{addr:08X}: lui {rn(rt)}, 0x089E")
            print(f"  0x{addr+4:08X}: 0x{next_word:08X}  {disasm(next_word, addr+4)}")
            count += 1
print(f"  Found {count} references")

# 8. Check the player entity field 0x05AB value in the save state
# First find the player entity pointer
# Look at caller 0x088A54B8: $s0 is the entity, let's find it via entity list
# Typically player entity is the first in a list accessible from global data
# Let's check common entity list locations
print("\n=== Checking entity pigment via known structures ===")
# From the callers, $a0 is loaded from 0x08A3345C (or $s1+0x345C where $s1=0x08A30000 area)
# This is likely the "game data context" pointer
# Let's see what's at various offsets from this pointer
if ctx_val != 0:
    print(f"  Context ptr = 0x{ctx_val:08X}")
    # The equipment data for the player might be at ctx_val + some offset
    # Let's check some entity-like structures
    # Try reading 0x05AB from various base addresses
    # Player entity base is often at a predictable location
    # Let's search near the global pointer area
    for test_base_addr in [0x089C7508, 0x08A30000, 0x08AB0000]:
        soff = psp_to_state(test_base_addr)
        if soff + 4 <= len(data):
            ptr = read_u32(data, soff)
            print(f"  [0x{test_base_addr:08X}] = 0x{ptr:08X}")
