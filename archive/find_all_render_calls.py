#!/usr/bin/env python3
"""Find ALL calls to sprite render functions in the overlay (0x09C57C80+).
Goal: identify which render calls draw the player list HP bars."""

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

# Known sprite render functions that accept X/Y offsets via $t0/$t1
RENDER_FUNCS = {
    0x0890112C: "sprite_render_112C($t0=X,$t1=Y)",
    0x08901000: "sprite_render_1000($t0=X,$t1=Y)",
    0x08901168: "sprite_render_1168",
    0x089012D8: "render_12D8",
    0x088FF8F0: "sprite_render_F8F0($t0=?,$t1=?)",
    0x08901C48: "bar_render_1C48($t0=type,$t1→$a2)",
    0x08900BF0: "bg_render_BF0($t1=X,$t2=Y)",
}

# Overlay range
OVL_START = 0x09C57C80
OVL_END = 0x09DA0000  # generous upper bound

# Known functions we've already analyzed
KNOWN_CALLERS = {
    0x09D6380C: "per-player names/icons/bg (PATCHED)",
    0x09D624D4: "per-player loop2 (tried, no effect)",
    0x09D6309C: "per-player loop3 (tried, no effect)",
    0x09D5E9C0: "common path 1 (tried, no effect)",
    0x09D5E8D0: "common path 2 (tried, no effect)",
    0x09D648AC: "own HP/stamina (tried, wrong bars)",
    0x09D6C498: "parent HUD renderer",
}

print("=== ALL RENDER CALLS IN OVERLAY ===")
print(f"Scanning {OVL_START:08X} - {OVL_END:08X}\n")

# Build JAL opcodes for each render function
jal_opcodes = {}
for target in RENDER_FUNCS:
    jal_opcodes[target] = (0x03 << 26) | (target >> 2)

# Scan overlay for all JAL to render functions
calls_by_func = {t: [] for t in RENDER_FUNCS}

for addr in range(OVL_START, OVL_END, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    op = instr >> 26
    if op != 0x03:  # not JAL
        continue
    target = (instr & 0x03FFFFFF) << 2
    if target in RENDER_FUNCS:
        calls_by_func[target].append(addr)

for target, addrs in sorted(calls_by_func.items()):
    if not addrs:
        continue
    print(f"\n--- {RENDER_FUNCS[target]} (0x{target:08X}) ---")
    print(f"    {len(addrs)} call sites:")
    for addr in addrs:
        cw = addr - 0x08800000
        # Try to identify which function this call is in
        # by scanning backwards for common function prologue patterns
        func_info = ""
        for known_addr, name in KNOWN_CALLERS.items():
            if known_addr <= addr <= known_addr + 0x800:
                func_info = f" IN {name}"
                break

        # Check the delay slot (addr+4) and instruction before
        ds_off = psp_to_offset(addr + 4)
        ds_instr = read_u32(data, ds_off)

        # Check what sets $t0 before the call (look back up to 8 instructions)
        t0_info = ""
        for k in range(1, 12):
            prev = addr - k * 4
            prev_off = psp_to_offset(prev)
            if prev_off < 0:
                break
            pi = read_u32(data, prev_off)
            pop = pi >> 26
            prt = (pi >> 16) & 0x1F
            prd = (pi >> 11) & 0x1F
            pfunc = pi & 0x3F

            # addiu $t0, ... or addu $t0,$zero,$zero or ori $t0,...
            if pop == 0x09 and prt == 8:  # addiu $t0
                prs = (pi >> 21) & 0x1F
                imm = pi & 0xFFFF
                simm = imm if imm < 0x8000 else imm - 0x10000
                REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
                t0_info = f" $t0=addiu {REGS[prs]},{simm} @-{k}"
                break
            elif pop == 0 and pfunc == 0x21 and prd == 8:  # addu $t0,...
                prs = (pi >> 21) & 0x1F
                REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
                t0_info = f" $t0=addu {REGS[prs]},{REGS[(pi>>16)&0x1F]} @-{k}"
                break
            elif pop == 0x0D and prt == 8:  # ori $t0
                imm = pi & 0xFFFF
                t0_info = f" $t0=ori 0x{imm:04X} @-{k}"
                break
            # Also check if $t0 set in delay slot
            if k == 1 and pop == 0:
                pass  # delay slot, check separately
            # Break if we hit a branch or jal (different basic block)
            if pop in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
                break
            if pop == 0x01:
                break

        print(f"    0x{addr:08X} (CW 0x{cw:07X}){func_info}{t0_info}")

# Now let's specifically look at the parent function 0x09D6C498 to trace ALL its calls
print("\n\n=== 0x09D6C498 CALL TREE ===")
print("All JAL instructions in 0x09D6C498-0x09D6CC00:")
for addr in range(0x09D6C498, 0x09D6CC00, 4):
    off = psp_to_offset(addr)
    if off + 4 > len(data):
        break
    instr = read_u32(data, off)
    op = instr >> 26
    if op == 0x03:
        target = (instr & 0x03FFFFFF) << 2
        cw = addr - 0x08800000
        name = ""
        if target in RENDER_FUNCS:
            name = f" [{RENDER_FUNCS[target]}]"
        elif target in KNOWN_CALLERS:
            name = f" [{KNOWN_CALLERS[target]}]"
        elif 0x09C50000 <= target <= 0x09DA0000:
            name = f" [OVL]"
        elif 0x08800000 <= target <= 0x08A00000:
            name = f" [EBOOT]"
        print(f"  0x{addr:08X} (CW 0x{cw:07X}): jal 0x{target:08X}{name}")
    elif instr >> 26 == 0 and (instr & 0x3F) == 0x08:  # jr $ra
        rs = (instr >> 21) & 0x1F
        REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
                '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
                '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
                '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
        print(f"  0x{addr:08X}: jr {REGS[rs]} [END]")
        break

print("\nDone!")
