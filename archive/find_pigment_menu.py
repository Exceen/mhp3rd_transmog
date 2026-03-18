#!/usr/bin/env python3
"""
Find the game progress flag that controls whether "Change Pigment" appears
in the equipment box menu.

Strategy:
1. Find the equipment box menu construction code in the overlay
2. Look for conditional checks that gate menu options
3. Trace back to the game progress flag
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

def read_u8(data, off):
    return data[off]

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
        if funct == 0x08: return f"jr {rn(rs)}"
        if funct == 0x09: return f"jalr {rn(rd)}, {rn(rs)}"
        if funct == 0x21: return f"addu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x23: return f"subu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x24: return f"and {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x25: return f"or {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2A: return f"slt {rn(rd)}, {rn(rs)}, {rn(rt)}"
        if funct == 0x2B: return f"sltu {rn(rd)}, {rn(rs)}, {rn(rt)}"
        return f"[special 0x{funct:02X}] {rn(rd)},{rn(rs)},{rn(rt)} sa={sa}"
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
print(f"Decompressed: {len(data)} bytes\n")

# The equipment box overlay function at 0x09CB73A0 handles pigment display.
# But the MENU that shows "Change Pigment" option is built elsewhere.
# Let's search for functions that call the pigment display function.

# First, let's find callers of the overlay function 0x09CB73A0
print("=== Searching for callers of overlay function 0x09CB73A0 ===")
target_jal = (0x03 << 26) | (0x09CB73A0 >> 2)
print(f"  Looking for jal word: 0x{target_jal:08X}")
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  Found caller at 0x{addr:08X}")
        # Dump context
        for a in range(addr - 16, addr + 20, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == addr else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")

# Also search EBOOT for callers
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  Found EBOOT caller at 0x{addr:08X}")

# The pigment unlock in MHP3rd is likely tied to village quest progress.
# In MHP3rd, pigment is unlocked by a specific NPC/event.
# The save data typically contains feature unlock flags.
#
# Let's search for EBOOT code that checks a flag and builds menu options.
# The equipment box menu likely uses a function to add options like:
# "Equip", "Remove", "Pigment", "Details"
#
# A common pattern: the code checks a flag byte, and if set, adds the pigment option.

# Let's look for the EBOOT function that the overlay calls for pigment check.
# The overlay might call an EBOOT function like "is_pigment_unlocked()"
# Search for common "feature unlock" patterns:
# - Loading from a save data pointer + offset
# - Comparing against quest completion counts

# Let's search for functions called near the pigment code in the overlay
# that might be unlock checks
print("\n=== Overlay code near 0x09CB7000-0x09CB7400 (before pigment function) ===")
print("Looking for potential menu construction or pigment unlock checks...")

# Search overlay for calls to EBOOT functions near the pigment code
for addr in range(0x09CB6000, 0x09CB73A0, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    op = (word >> 26) & 0x3F
    if op == 0x03:  # jal
        target = (word & 0x03FFFFFF) << 2
        # Check if target is in EBOOT range
        if 0x08804000 <= target < 0x08920000:
            print(f"  0x{addr:08X}: jal 0x{target:08X} (EBOOT)")

# Let's look for the specific pigment unlock check.
# In MH games, save data often has a "features unlocked" bitmask.
# Let's search for EBOOT functions that return a boolean and are called
# near menu construction code.

# The overlay function at 0x09CB73A0 takes $a0 (some context) and $s5 (index).
# Before it checks the pigment flag from the data structure, it might check
# a global unlock first. But looking at the disassembly, the first thing it does
# is load data and check byte +19. There's no global unlock check at the start.

# So maybe the global unlock is checked BEFORE this function is called.
# The caller decides whether to call this function at all.

# Let's look at what address the overlay stores for the menu option handling.
# Search for references to 0x09CB73A0 (as a function pointer in a table)
func_addr_bytes = struct.pack('<I', 0x09CB73A0)
print(f"\n=== Searching for function pointer 0x09CB73A0 in overlay data ===")
for offset in range(psp_to_state(0x09C57C80), psp_to_state(0x09F00000), 4):
    if offset + 4 > len(data): break
    if data[offset:offset+4] == func_addr_bytes:
        psp_addr = offset - STATE_OFFSET_BASE + PSP_BASE
        print(f"  Found at 0x{psp_addr:08X} (state offset 0x{offset:08X})")

# Let's try a different approach: search for where the save data / player data
# stores the pigment unlock flag.
# Known: global_ptr at 0x089C7508 is 0 (not in quest)
# The save data might be at a fixed location.

# Search for EBOOT functions that are short (return 0 or 1) and reference
# save data area. These might be "is_feature_unlocked" functions.

# Actually, let's look at the EBOOT function at 0x088690EC more carefully.
# It's called from overlay code and returns the pigment flag. But maybe
# there's a wrapper that checks both the per-armor flag AND a global unlock.

# Let's find callers of 0x08869054 (the function containing 0x088690EC)
print("\n=== Callers of function 0x08869054 ===")
target_jal = (0x03 << 26) | (0x08869054 >> 2)
for addr in range(0x08804000, 0x08920000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  0x{addr:08X}: jal 0x08869054")
        for a in range(addr - 8, addr + 16, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}")

# Also check overlay callers
for addr in range(0x09C57C80, 0x09E00000, 4):
    soff = psp_to_state(addr)
    if soff + 4 > len(data): break
    word = read_u32(data, soff)
    if word == target_jal:
        print(f"  Overlay: 0x{addr:08X}: jal 0x08869054")
        for a in range(addr - 20, addr + 24, 4):
            s = psp_to_state(a)
            w = read_u32(data, s)
            marker = " <--" if a == addr else ""
            print(f"    0x{a:08X}: 0x{w:08X}  {disasm(w, a)}{marker}")

# Let's also look at the function 0x088691FC which starts right after
# the pigment query function. It has the same type-checking pattern
# as get_pigment_flag. This might be the wrapper.
print("\n=== Function at 0x088691FC (has type checking like get_pigment_flag) ===")
for addr in range(0x088691FC, 0x088692C0, 4):
    soff = psp_to_state(addr)
    word = read_u32(data, soff)
    print(f"  0x{addr:08X}: 0x{word:08X}  {disasm(word, addr)}")

# Search for save data pointer patterns
# Look for lw from known data areas that might hold player progress
print("\n=== Search for save_data or player_progress pointers ===")
# Check what's at 0x08AB area (seen in some callers)
for test in [0x08ABCE80, 0x08A3345C]:
    soff = psp_to_state(test)
    if soff + 4 <= len(data):
        val = read_u32(data, soff)
        print(f"  [0x{test:08X}] = 0x{val:08X}")
