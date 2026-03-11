#!/usr/bin/env python3
"""Find player list rendering addresses in MHP3rd."""

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

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def decode_addiu(instr):
    """Decode addiu rt, rs, imm. Returns (rt, rs, imm) or None."""
    if (instr >> 26) == 0x09:  # addiu opcode
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            imm -= 0x10000
        return (rt, rs, imm)
    return None

def decode_ori(instr):
    """Decode ori rt, rs, imm."""
    if (instr >> 26) == 0x0D:
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        return (rt, rs, imm)
    return None

def decode_lui(instr):
    """Decode lui rt, imm."""
    if (instr >> 26) == 0x0F:
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        return (rt, imm)
    return None

REG_NAMES = {0:'$zero',1:'$at',2:'$v0',3:'$v1',4:'$a0',5:'$a1',6:'$a2',7:'$a3',
             8:'$t0',9:'$t1',10:'$t2',11:'$t3',12:'$t4',13:'$t5',14:'$t6',15:'$t7',
             16:'$s0',17:'$s1',18:'$s2',19:'$s3',20:'$s4',21:'$s5',22:'$s6',23:'$s7',
             24:'$t8',25:'$t9',28:'$gp',29:'$sp',30:'$fp',31:'$ra'}

print("Decompressing save state...")
data = decompress_ppst(PPST_FILE)

# ============================================================
# In MHFU, player list rendering:
#   0x08841A08: addiu $s4, $zero, 0x2D (Y=45)
#   0x08841A24: addiu $a2, $zero, 0xFFAD (X=-83)
#
# Strategy 1: Search for similar patterns — addiu to $s4 with small positive values
# and addiu to $a2 with negative values, close together
# ============================================================

print("\n=== STRATEGY 1: MHFU-like player list pattern ===")
print("Searching for addiu $s4, $zero, <30-80> near addiu $a2, $zero, <negative>")

# Search both eboot and overlay
ranges = [
    ("eboot", 0x08800000, 0x08960000),
    ("overlay", 0x09C57C80, 0x09DC0000),
]

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)

    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        d = decode_addiu(instr)
        if d and d[0] == 20 and d[1] == 0 and 20 <= d[2] <= 80:  # addiu $s4, $zero, 20-80
            psp = off - MEM_OFFSET + PSP_BASE
            # Check nearby for negative X value in a2
            for k in range(-20, 20):
                noff = off + k * 4
                if start_off <= noff < end_off:
                    ni = read_u32(data, noff)
                    nd = decode_addiu(ni)
                    if nd and nd[0] == 6 and nd[1] == 0 and nd[2] < 0:  # addiu $a2, $zero, negative
                        npsp = noff - MEM_OFFSET + PSP_BASE
                        cw1 = psp - 0x08800000
                        cw2 = npsp - 0x08800000
                        print(f"  [{region_name}] 0x{psp:08X} (CW 0x20{cw1:07X}): addiu $s4, $zero, {d[2]}")
                        print(f"     nearby: 0x{npsp:08X} (CW 0x20{cw2:07X}): addiu $a2, $zero, {nd[2]}")

# ============================================================
# Strategy 2: Search for text rendering function calls
# The print function is at 0x088EAA64 (from kurogami's repos)
# Look for JAL 0x088EAA64 and check what X/Y values are set before it
# ============================================================
print("\n=== STRATEGY 2: Calls to print function 0x088EAA64 ===")
# JAL target: 0x088EAA64 -> (addr >> 2) = 0x0223A999
# JAL encoding: 0x0C000000 | (target >> 2) = 0x0C23A999... wait
# JAL target = (instr & 0x03FFFFFF) << 2
# For 0x088EAA64: target >> 2 = 0x0223A999
# JAL = 0x0C000000 | 0x0223A999 = 0x0E23A999... hmm
# Actually JAL opcode is 000011, so top 6 bits = 0x0C
# 0x0C000000 | (0x088EAA64 >> 2) = 0x0C000000 | 0x0223AA99 = 0x0C23AA99

jal_target = 0x088EAA64
jal_instr = 0x0C000000 | (jal_target >> 2)
print(f"Looking for JAL 0x{jal_target:08X} = instruction 0x{jal_instr:08X}")

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)

    count = 0
    for off in range(start_off, end_off, 4):
        instr = read_u32(data, off)
        if instr == jal_instr:
            psp = off - MEM_OFFSET + PSP_BASE
            count += 1
            # Dump context around the call
            print(f"\n  [{region_name}] JAL at 0x{psp:08X}:")
            for k in range(-8, 4):
                coff = off + k * 4
                if start_off <= coff < end_off:
                    ci = read_u32(data, coff)
                    cpsp = coff - MEM_OFFSET + PSP_BASE
                    cw = cpsp - 0x08800000
                    # Try to decode
                    desc = ""
                    d = decode_addiu(ci)
                    if d:
                        desc = f"  addiu {REG_NAMES.get(d[0], f'${d[0]}')}, {REG_NAMES.get(d[1], f'${d[1]}')}, {d[2]}"
                    dl = decode_lui(ci)
                    if dl:
                        desc = f"  lui {REG_NAMES.get(dl[0], f'${dl[0]}')}, 0x{dl[1]:04X}"
                    if ci == jal_instr:
                        desc = f"  <<< JAL 0x{jal_target:08X}"
                    marker = " ***" if desc else ""
                    print(f"    0x{cpsp:08X} (CW 0x20{cw:07X}): 0x{ci:08X}{desc}{marker}")
    print(f"  Total JAL calls in {region_name}: {count}")

# ============================================================
# Strategy 3: Search for the string "Dragon" to find player data
# ============================================================
print("\n=== STRATEGY 3: Finding player name 'Dragon' in memory ===")
# Try ASCII, UTF-16LE, and Shift-JIS
search_patterns = [
    ("ASCII", b"Dragon"),
    ("UTF-16LE", "Dragon".encode('utf-16-le')),
]

for encoding, pattern in search_patterns:
    off = 0
    while off < len(data):
        idx = data.find(pattern, off)
        if idx == -1:
            break
        psp = idx - MEM_OFFSET + PSP_BASE
        if 0x08000000 <= psp <= 0x0A000000:
            # Dump surrounding bytes
            ctx = data[max(0,idx-32):idx+len(pattern)+32]
            print(f"  [{encoding}] Found at 0x{psp:08X} (offset 0x{idx:X})")
            # Print hex dump of nearby data
            for i in range(max(0,idx-16), min(len(data), idx+len(pattern)+16), 16):
                hexbytes = ' '.join(f'{data[j]:02X}' for j in range(i, min(i+16, len(data))))
                p = i - MEM_OFFSET + PSP_BASE
                print(f"    0x{p:08X}: {hexbytes}")
        off = idx + 1

# ============================================================
# Strategy 4: Search for rendering function that takes X/Y + string ptr
# Look for sequences: addiu/ori setting position, then load string ptr, then JAL
# In overlay code specifically
# ============================================================
print("\n=== STRATEGY 4: Text render calls in overlay with position args ===")
# Common text rendering pattern:
#   addiu $a0, $zero, <X>    ; or move from register
#   addiu $a1, $zero, <Y>    ; or move from register
#   lui $a2, <string_hi>     ; load string address
#   addiu $a2, $a2, <string_lo>
#   jal <render_func>

# Let me search for JAL to 0x088EAA64 in overlay and nearby addiu patterns
# But also check for other rendering functions
# kurogami uses 0x0E239BFC as a JAL in the HP display — let me check what that targets
# 0x0E239BFC -> target = (0x0E239BFC & 0x03FFFFFF) << 2 = 0x0239BFC << 2 = hmm
# Actually: JAL stores (addr >> 2) in lower 26 bits
# 0x0E239BFC: opcode = 0x0E >> 2 = 3 = JAL, target = (0x0E239BFC & 0x03FFFFFF) << 2
# = 0x0239BFC << 2 = 0x008E6FF0... that doesn't look right
# Let me recalculate: 0x0E239BFC & 0x03FFFFFF = 0x02239BFC, << 2 = 0x088E6FF0
# Hmm, that's in the eboot near the main hook point

# Let me also find JAL to the sceGeListEnQueue (0x08960CF8)
jal_ge = 0x0C000000 | (0x08960CF8 >> 2)
print(f"\nLooking for JAL sceGeListEnQueue = 0x{jal_ge:08X}")

for region_name, start, end in ranges:
    start_off = psp_to_offset(start)
    end_off = min(psp_to_offset(end), len(data) - 4)
    count = 0
    for off in range(start_off, end_off, 4):
        if read_u32(data, off) == jal_ge:
            count += 1
    print(f"  [{region_name}] JAL sceGeListEnQueue count: {count}")

print("\nDone!")
