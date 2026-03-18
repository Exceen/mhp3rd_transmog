#!/usr/bin/env python3
"""
Investigate the equipment box submenu construction to find what gates
the "Change Pigment" option. Focus on:
1. The full submenu builder function around 0x09CB6200
2. The function 0x09CB5440 called before each add_menu_option
3. Any conditional branches that skip adding certain options
4. How the game distinguishes high rank vs low rank armor
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

rnames = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
          's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']
def rn(r): return f"${rnames[r]}"

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
        if word == 0: return "nop"
        if funct == 0x00: return f"sll {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x02: return f"srl {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x03: return f"sra {rn(rd)}, {rn(rt)}, {sa}"
        if funct == 0x04: return f"sllv {rn(rd)}, {rn(rt)}, {rn(rs)}"
        if funct == 0x06: return f"srlv {rn(rd)}, {rn(rt)}, {rn(rs)}"
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x0A: return f"movz {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x0B: return f"movn {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x18: return f"mult {rn(rs)}, {rn(rt)}"
        if funct == 0x19: return f"multu {rn(rs)}, {rn(rt)}"
        if funct == 0x10: return f"mfhi {rn(rd)}"
        if funct == 0x12: return f"mflo {rn(rd)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x26: return f"xor {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x27: return f"nor {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"[special 0x{funct:02X}] {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
    elif op == 0x01:
        if rt == 0: return f"bltz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        if rt == 1: return f"bgez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
        return f"regimm rt={rt}"
    elif op == 0x02: return f"j 0x{target:08X}"
    elif op == 0x03: return f"jal 0x{target:08X}"
    elif op == 0x04: return f"beq {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x05: return f"bne {rn(rs)}, {rn(rt)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x06: return f"blez {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x07: return f"bgtz {rn(rs)}, 0x{(addr+4+simm*4)&0xFFFFFFFF:08X}"
    elif op == 0x09: return f"addiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0A: return f"slti {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0B: return f"sltiu {rn(rt)}, {rn(rs)}, {simm}"
    elif op == 0x0C: return f"andi {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0D: return f"ori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0E: return f"xori {rn(rt)}, {rn(rs)}, 0x{imm:04X}"
    elif op == 0x0F: return f"lui {rn(rt)}, 0x{imm:04X}"
    elif op == 0x20: return f"lb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x21: return f"lh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x23: return f"lw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x24: return f"lbu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x25: return f"lhu {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x28: return f"sb {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x29: return f"sh {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    elif op == 0x2B: return f"sw {rn(rt)}, 0x{imm:04X}({rn(rs)})"
    else: return f"[op=0x{op:02X}] {rn(rt)}, 0x{imm:04X}({rn(rs)})"

with open(PPST, 'rb') as f:
    raw = f.read()
data = zstandard.ZstdDecompressor().decompress(raw[HEADER_SIZE:], max_output_size=64*1024*1024)

def dump_range(start, end, label=""):
    if label:
        print(f"\n{'='*70}")
        print(f"=== {label}")
        print(f"{'='*70}")
    for addr in range(start, end, 4):
        soff = psp_to_state(addr)
        if soff + 4 > len(data): break
        word = read_u32(data, soff)
        d = disasm(word, addr)
        markers = ""
        if 'jal 0x0880E654' in d: markers = "  <-- add_menu_option"
        if 'jal 0x09CB5' in d: markers += "  <-- overlay_func"
        if 'jal 0x0886AE7C' in d: markers += "  <-- EBOOT_0886AE7C"
        if 'beq' in d or 'bne' in d or 'blez' in d or 'bgtz' in d or 'bltz' in d or 'bgez' in d:
            markers += "  <-- BRANCH"
        print(f"  0x{addr:08X}: 0x{word:08X}  {d}{markers}")

# 1. Find the full function that builds the equipment box submenu
# Search backwards from 0x09CB6180 for function prologue
print("=== Finding submenu builder function start ===")
func_start = None
for addr in range(0x09CB6180, 0x09CB5800, -4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    simm = (word & 0xFFFF) if (word & 0xFFFF) < 0x8000 else (word & 0xFFFF) - 0x10000
    if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
        func_start = addr
        print(f"Function starts at 0x{func_start:08X} (stack = {-simm})")
        break

if func_start:
    # Dump the ENTIRE function including all menu option adds
    dump_range(func_start, func_start + 0x400,
               f"Submenu builder at 0x{func_start:08X}")

# 2. Dump the function 0x09CB5440 to understand what it does
print("\n\n=== Function 0x09CB5440 ===")
# Check if this function exists at this address
soff = psp_to_state(0x09CB5440)
if soff + 4 <= len(data):
    word = read_u32(data, soff)
    print(f"  First word at 0x09CB5440: 0x{word:08X} = {disasm(word, 0x09CB5440)}")
    # Check if it's a function prologue
    dump_range(0x09CB5440, 0x09CB5540, "Function 0x09CB5440")

# 3. Let's also look for the EBOOT function add_menu_option (0x0880E654)
# to understand its signature
dump_range(0x0880E654, 0x0880E700, "EBOOT add_menu_option 0x0880E654")

# 4. Look at the armor data table byte +4 (flag byte) more carefully
# to understand if there's a rank indicator
print("\n\n=== Armor data flag analysis ===")
print("Checking flag byte (+4) and pigment byte (+19) for patterns")
# HEAD table
tables = {
    'HEAD':  (0x089825AC, 256),
    'CHEST': (0x08980144, 233),
    'ARMS':  (0x0897DFFC, 213),
    'WAIST': (0x08984DAC, 214),
    'LEGS':  (0x08986F1C, 220),
}
for tname, (base, count) in tables.items():
    print(f"\n  {tname} (base=0x{base:08X}, {count} entries):")
    pigment_entries = []
    no_pigment_entries = []
    for i in range(count):
        entry_addr = base + i * 40
        soff = psp_to_state(entry_addr)
        if soff + 40 > len(data): break
        model_m = struct.unpack_from('<h', data, soff)[0]
        model_f = struct.unpack_from('<h', data, soff + 2)[0]
        flag = data[soff + 4]
        pigment = data[soff + 19]
        # Also check bytes 5-7 for potential rank info
        b5 = data[soff + 5]
        b6 = data[soff + 6]
        b7 = data[soff + 7]
        rarity = data[soff + 18]  # byte 18 might be rarity
        if pigment > 0:
            pigment_entries.append((i, model_m, model_f, flag, pigment, b5, b6, b7, rarity))
        else:
            no_pigment_entries.append((i, model_m, model_f, flag, pigment, b5, b6, b7, rarity))

    print(f"    Pigment=1: {len(pigment_entries)} entries, Pigment=0: {len(no_pigment_entries)} entries")
    if pigment_entries:
        # Show first few with pigment
        print(f"    First 5 with pigment:")
        for e in pigment_entries[:5]:
            print(f"      eid={e[0]}: model=({e[1]},{e[2]}), flag=0x{e[3]:02X}, pigment={e[4]}, b5=0x{e[5]:02X}, b6=0x{e[6]:02X}, b7=0x{e[7]:02X}, rarity={e[8]}")
    if no_pigment_entries:
        # Show first few without pigment
        print(f"    First 5 without pigment:")
        for e in no_pigment_entries[:5]:
            print(f"      eid={e[0]}: model=({e[1]},{e[2]}), flag=0x{e[3]:02X}, pigment={e[4]}, b5=0x{e[5]:02X}, b6=0x{e[6]:02X}, b7=0x{e[7]:02X}, rarity={e[8]}")

    # Check: is pigment correlated with EID ranges?
    if pigment_entries:
        min_eid = min(e[0] for e in pigment_entries)
        max_eid = max(e[0] for e in pigment_entries)
        print(f"    Pigment EID range: {min_eid}-{max_eid}")
    if no_pigment_entries:
        min_eid = min(e[0] for e in no_pigment_entries)
        max_eid = max(e[0] for e in no_pigment_entries)
        print(f"    No-pigment EID range: {min_eid}-{max_eid}")

# 5. Dump a few full 40-byte entries to check if there's a rank byte
print("\n\n=== Full hex dump of select armor entries (HEAD) ===")
base = 0x089825AC
for i in [0, 1, 10, 50, 100, 200, 255]:
    if i >= 256: continue
    entry_addr = base + i * 40
    soff = psp_to_state(entry_addr)
    pigment = data[soff + 19]
    hexdata = data[soff:soff+40]
    hexstr = ' '.join(f'{b:02X}' for b in hexdata)
    print(f"  HEAD[{i:3d}] pig={pigment}: {hexstr}")

# 6. Check what the overlay pigment display function reads from the 72-byte structure
# Specifically byte +19 AND bytes +6/+7 (the "are they different?" check)
# This might tell us: +6 = low rank model, +7 = high rank model?
# Or: +6 = current color, +7 = default color?
print("\n\n=== Overlay pigment gate analysis ===")
print("From dump_pigment_sites.py, the gate checks:")
print("  1. byte +19 of 72-byte entry (pigment flag from armor data)")
print("  2. byte +6 != byte +7 of 72-byte entry")
print("Let's check what bytes +6 and +7 map to in the armor data table")
print()

# Look at how the 72-byte overlay structure is populated
# The overlay reads entries from base + 40 + index*72
# Fields likely come from the armor data table
# Let's search for where the overlay populates these structures
print("=== Searching overlay for code that populates 72-byte structures ===")
# Search for stores with offset patterns matching 72-byte entries
for addr in range(0x09CB5000, 0x09CB7400, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    d = disasm(word, addr)
    # Look for sb/sh/sw with small offsets that suggest structure population
    if ('sb ' in d or 'sh ' in d or 'sw ' in d) and ('+6' in d or '+7' in d or '0x0006' in d or '0x0007' in d or '0x0013' in d):
        print(f"  0x{addr:08X}: {d}")

# 7. Actually, let's look at what function populates the equipment box items
# It should call the equipment lookup and copy data into the 72-byte structures
# Search for references to the 72 constant (entry size)
print("\n\n=== Search for literal 72 (0x48) in overlay code near equipment box ===")
for addr in range(0x09CB4000, 0x09CB8000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    if op == 0x09 and simm == 72:  # addiu with 72
        d = disasm(word, addr)
        print(f"  0x{addr:08X}: {d}")
    if op == 0x09 and simm == 40:  # addiu with 40 (armor entry size)
        d = disasm(word, addr)
        print(f"  0x{addr:08X}: {d}  (40 = armor entry size)")
