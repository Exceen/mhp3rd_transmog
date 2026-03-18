#!/usr/bin/env python3
"""
Find ALL frame-timing related mechanisms in MHP3rd (ULJM-05800) save state.
Analyzes decompressed PSP memory for sceDisplay*, sceKernelDelay*, timing functions,
frame counters, and the full context around known framebuf calls.
"""

import struct
import zstandard as zstd

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48  # offset in decompressed data where PSP 0x08000000 starts
PSP_BASE = 0x08000000
CWCHEAT_BASE = 0x08800000

# Executable code range (approximate)
CODE_START = 0x08800000
CODE_END = 0x09000000  # search wider than 0x08900000

def psp_to_offset(addr):
    """PSP address to offset in decompressed data."""
    return addr - PSP_BASE + MEM_OFFSET

def offset_to_psp(off):
    """Offset in decompressed data to PSP address."""
    return off - MEM_OFFSET + PSP_BASE

def cwcheat_offset(addr):
    """PSP address to CWCheat offset."""
    return addr - CWCHEAT_BASE

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def decode_mips_instr(instr, addr):
    """Basic MIPS instruction decoder for common instructions."""
    op = (instr >> 26) & 0x3F
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    shamt = (instr >> 6) & 0x1F
    funct = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target = (instr & 0x03FFFFFF) << 2 | (addr & 0xF0000000)

    regs = ['zero','at','v0','v1','a0','a1','a2','a3',
            't0','t1','t2','t3','t4','t5','t6','t7',
            's0','s1','s2','s3','s4','s5','s6','s7',
            't8','t9','k0','k1','gp','sp','fp','ra']

    if instr == 0:
        return "nop"

    if op == 0:  # R-type
        if funct == 0x08: return f"jr ${regs[rs]}"
        if funct == 0x09: return f"jalr ${regs[rd]}, ${regs[rs]}"
        if funct == 0x21: return f"addu ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x23: return f"subu ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x25: return f"or ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x24: return f"and ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x2A: return f"slt ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x2B: return f"sltu ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x00: return f"sll ${regs[rd]}, ${regs[rt]}, {shamt}"
        if funct == 0x02: return f"srl ${regs[rd]}, ${regs[rt]}, {shamt}"
        if funct == 0x03: return f"sra ${regs[rd]}, ${regs[rt]}, {shamt}"
        if funct == 0x04: return f"sllv ${regs[rd]}, ${regs[rt]}, ${regs[rs]}"
        if funct == 0x06: return f"srlv ${regs[rd]}, ${regs[rt]}, ${regs[rs]}"
        if funct == 0x18: return f"mult ${regs[rs]}, ${regs[rt]}"
        if funct == 0x1A: return f"div ${regs[rs]}, ${regs[rt]}"
        if funct == 0x10: return f"mfhi ${regs[rd]}"
        if funct == 0x12: return f"mflo ${regs[rd]}"
        return f"R-type op=0 funct=0x{funct:02X} rs={regs[rs]} rt={regs[rt]} rd={regs[rd]}"

    if op == 0x02: return f"j 0x{target:08X}"
    if op == 0x03: return f"jal 0x{target:08X}"
    if op == 0x04:
        btarget = addr + 4 + (simm << 2)
        return f"beq ${regs[rs]}, ${regs[rt]}, 0x{btarget:08X}"
    if op == 0x05:
        btarget = addr + 4 + (simm << 2)
        return f"bne ${regs[rs]}, ${regs[rt]}, 0x{btarget:08X}"
    if op == 0x06:
        btarget = addr + 4 + (simm << 2)
        return f"blez ${regs[rs]}, 0x{btarget:08X}"
    if op == 0x07:
        btarget = addr + 4 + (simm << 2)
        return f"bgtz ${regs[rs]}, 0x{btarget:08X}"
    if op == 0x01:
        btarget = addr + 4 + (simm << 2)
        if rt == 0: return f"bltz ${regs[rs]}, 0x{btarget:08X}"
        if rt == 1: return f"bgez ${regs[rs]}, 0x{btarget:08X}"
        if rt == 0x11: return f"bgezal ${regs[rs]}, 0x{btarget:08X}"
        return f"REGIMM rt={rt} ${regs[rs]}, 0x{btarget:08X}"

    if op == 0x08: return f"addi ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x09: return f"addiu ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x0A: return f"slti ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x0B: return f"sltiu ${regs[rt]}, ${regs[rs]}, {imm}"
    if op == 0x0C: return f"andi ${regs[rt]}, ${regs[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori ${regs[rt]}, ${regs[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui ${regs[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x21: return f"lh ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x23: return f"lw ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x24: return f"lbu ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x25: return f"lhu ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x28: return f"sb ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x29: return f"sh ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x2B: return f"sw ${regs[rt]}, {simm}(${regs[rs]})"

    return f"??? op=0x{op:02X} raw=0x{instr:08X}"

def disassemble_range(data, psp_start, count):
    """Disassemble `count` instructions starting at psp_start."""
    lines = []
    for i in range(count):
        addr = psp_start + i * 4
        off = psp_to_offset(addr)
        if off < 0 or off + 4 > len(data):
            lines.append(f"  0x{addr:08X}: (out of bounds)")
            continue
        instr = read_u32(data, off)
        decoded = decode_mips_instr(instr, addr)
        cw = cwcheat_offset(addr)
        cw_str = f"CW:0x{cw:07X}" if cw >= 0 else ""
        lines.append(f"  0x{addr:08X} [{cw_str:>14s}]: {instr:08X}  {decoded}")
    return lines

def find_jal_callers(data, target_addr, search_start, search_end):
    """Find all JAL instructions targeting target_addr in the given range."""
    # JAL encoding: opcode=3 (bits 31:26), target = (addr >> 2) & 0x03FFFFFF
    target_field = (target_addr >> 2) & 0x03FFFFFF
    jal_instr = (0x03 << 26) | target_field

    callers = []
    start_off = psp_to_offset(search_start)
    end_off = psp_to_offset(search_end)

    for off in range(start_off, min(end_off, len(data) - 3), 4):
        instr = read_u32(data, off)
        if instr == jal_instr:
            caller_addr = offset_to_psp(off)
            callers.append(caller_addr)
    return callers

def find_string(data, s):
    """Find all occurrences of a string in data, return offsets."""
    encoded = s.encode('ascii')
    results = []
    start = 0
    while True:
        idx = data.find(encoded, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results

def find_nid_stub(data, nid, search_start=0x08800000, search_end=0x09800000):
    """
    PSP stubs for imported functions have the NID in the .rodata.sceNid section.
    The stub itself is typically:
        j <addr>   or   jr $ra (unresolved)
    We search for the NID bytes and try to find the corresponding stub.

    Alternatively, search for the standard PSP stub pattern:
    The import stub is 2 instructions: j target; nop
    The NID table is separate. Let's search for the NID value directly.
    """
    nid_bytes = struct.pack('<I', nid)
    results = []
    start_off = psp_to_offset(search_start)
    end_off = min(psp_to_offset(search_end), len(data) - 3)

    pos = start_off
    while pos < end_off:
        idx = data.find(nid_bytes, pos, end_off)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        results.append(psp_addr)
        pos = idx + 4
    return results

def main():
    print(f"Loading save state: {SAVE_STATE}")
    with open(SAVE_STATE, 'rb') as f:
        raw = f.read()

    compressed = raw[HEADER_SIZE:]
    dctx = zstd.ZstdDecompressor()
    data = dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)
    print(f"Decompressed size: {len(data)} bytes (0x{len(data):X})")

    # Maximum PSP address available
    max_psp = offset_to_psp(len(data))
    print(f"Max PSP address in dump: 0x{max_psp:08X}")

    # Adjust search range
    search_start = 0x08800000
    search_end = min(0x09800000, max_psp)

    print("\n" + "="*80)
    print("1. sceDisplaySetFrameBuf CALLERS (JAL to 0x08960D30)")
    print("="*80)

    stub_addr = 0x08960D30
    # First verify what's at the stub
    print(f"\n  Stub at 0x{stub_addr:08X}:")
    for line in disassemble_range(data, stub_addr, 4):
        print(line)

    callers = find_jal_callers(data, stub_addr, search_start, search_end)
    print(f"\n  Found {len(callers)} JAL callers:")
    for c in callers:
        cw = cwcheat_offset(c)
        print(f"    0x{c:08X}  (CW offset: 0x{cw:07X})")

    print("\n" + "="*80)
    print("2. sceKernelDelayThread CALLS")
    print("="*80)

    # Search for the string "sceKernelDelayThread"
    delay_str_offsets = find_string(data, "sceKernelDelayThread")
    print(f"\n  String 'sceKernelDelayThread' found at {len(delay_str_offsets)} locations:")
    for off in delay_str_offsets:
        psp_addr = offset_to_psp(off)
        print(f"    offset 0x{off:X} -> PSP 0x{psp_addr:08X}")

    # Also search for sceKernelDelayThreadCB
    delay_cb_offsets = find_string(data, "sceKernelDelayThreadCB")
    print(f"\n  String 'sceKernelDelayThreadCB' found at {len(delay_cb_offsets)} locations:")
    for off in delay_cb_offsets:
        psp_addr = offset_to_psp(off)
        print(f"    offset 0x{off:X} -> PSP 0x{psp_addr:08X}")

    # Known NIDs for common functions
    # sceKernelDelayThread NID = 0xCEADEB47
    # sceKernelDelayThreadCB NID = 0x68DA9E36
    print("\n  Searching for sceKernelDelayThread NID 0xCEADEB47...")
    nid_locs = find_nid_stub(data, 0xCEADEB47)
    print(f"  NID found at: {['0x%08X' % a for a in nid_locs]}")

    print("\n  Searching for sceKernelDelayThreadCB NID 0x68DA9E36...")
    nid_locs2 = find_nid_stub(data, 0x68DA9E36)
    print(f"  NID found at: {['0x%08X' % a for a in nid_locs2]}")

    # Now let's find the actual stub addresses by looking at the import tables
    # PSP import stubs are typically in a section near 0x0895xxxx-0x0896xxxx
    # Each stub is: j <target>; nop (or jr $ra; nop if unresolved)
    # Let's scan for J instructions pointing into kernel space (0x08000000-0x0880xxxx or 0x08800000+)
    # Actually, PPSSPP replaces stubs with J instructions to HLE implementations.
    # The stub at 0x08960D30 is known. Let's look at the stub table region.

    print("\n  Examining import stub region around 0x08960D00-0x08961000:")
    # Find J instructions in the stub region to identify imported functions
    stub_region_start = 0x08960C00
    stub_region_end = 0x08962000

    stubs = {}
    for addr in range(stub_region_start, stub_region_end, 8):
        off = psp_to_offset(addr)
        if off + 8 > len(data):
            break
        instr = read_u32(data, off)
        instr2 = read_u32(data, off + 4)
        op = (instr >> 26) & 0x3F
        if op == 2:  # J instruction
            target = ((instr & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
            stubs[addr] = target

    print(f"  Found {len(stubs)} J-instruction stubs in region:")
    for stub_addr_found, target in sorted(stubs.items()):
        cw = cwcheat_offset(stub_addr_found)
        print(f"    Stub 0x{stub_addr_found:08X} (CW:0x{cw:07X}) -> J 0x{target:08X}")

    # For each stub, find its callers and see which ones are called often
    print("\n  Finding callers for each stub (delay/timing related):")

    # Let's also look for string references to identify which stub is which
    # Search for function name strings near the NID table
    timing_strings = [
        "sceKernelDelayThread", "sceDisplayWaitVblank", "sceDisplayWaitVblankStart",
        "sceDisplayWaitVblankCB", "sceDisplayWaitVblankStartCB",
        "sceRtcGetCurrentTick", "sceKernelGetSystemTimeWide", "sceKernelGetSystemTimeLow",
        "sceKernelUSec2SysClock", "sceDisplayGetVcount",
        "sceDisplayGetFrameBuf"
    ]

    print("\n  Searching for timing-related function name strings:")
    for s in timing_strings:
        offsets = find_string(data, s + "\x00")  # null-terminated
        if not offsets:
            offsets = find_string(data, s)
        if offsets:
            for off in offsets:
                psp_addr = offset_to_psp(off)
                print(f"    '{s}' at PSP 0x{psp_addr:08X}")

    # Now let's find ALL stubs and their callers
    # Focus on stubs that might be delay/vblank related
    # Let's try to find stubs by NID matching
    known_nids = {
        0xCEADEB47: "sceKernelDelayThread",
        0x68DA9E36: "sceKernelDelayThreadCB",
        0x984C27E7: "sceDisplayWaitVblankStart",
        0x46F186C3: "sceDisplayWaitVblankStartCB",
        0x36CDFADE: "sceDisplayWaitVblank",
        0x8EB9EC49: "sceDisplayWaitVblankCB",
        0xEEDA2E54: "sceDisplayGetFrameBuf",
        0x289D82FE: "sceDisplaySetFrameBuf",
        0x9ED47A42: "sceDisplaySetMode",
        0xDBA6C4C4: "sceDisplayGetMode",
        0x773DD3A3: "sceRtcGetCurrentTick",
        0x82BC5777: "sceKernelGetSystemTimeWide",
        0x369ED59D: "sceKernelGetSystemTimeLow",
        0x40F1469C: "sceDisplayGetVcount",
    }

    print("\n  Searching for known NIDs in memory:")
    nid_to_stub = {}
    for nid, name in known_nids.items():
        locs = find_nid_stub(data, nid)
        if locs:
            print(f"    {name} (NID 0x{nid:08X}): found at {['0x%08X' % a for a in locs]}")

    # Better approach: scan the import table structure
    # PSP modules have a structured import table. Let's look for the sceDisplay library string
    # and work from there to find the NID table and stub table.

    print("\n  Looking for library name strings to find import tables:")
    for libname in ["sceDisplay", "ThreadManForUser", "sceRtc"]:
        offsets = find_string(data, libname + "\x00")
        if offsets:
            for off in offsets:
                psp_addr = offset_to_psp(off)
                print(f"    '{libname}' at PSP 0x{psp_addr:08X}")

    # Let's use a more direct approach: for each known stub in the stub region,
    # count its callers and list them
    print("\n" + "="*80)
    print("2b. ALL STUB CALLERS (stubs in 0x08960C00-0x08962000)")
    print("="*80)

    for stub_addr_found in sorted(stubs.keys()):
        callers = find_jal_callers(data, stub_addr_found, search_start, search_end)
        if callers:
            target = stubs[stub_addr_found]
            print(f"\n  Stub 0x{stub_addr_found:08X} -> J 0x{target:08X}  ({len(callers)} callers)")
            for c in callers:
                cw = cwcheat_offset(c)
                print(f"    Caller: 0x{c:08X}  (CW:0x{cw:07X})")

    # Also scan a wider range for stubs (some games have them elsewhere)
    print("\n  Scanning wider stub range 0x08960000-0x08970000...")
    wider_stubs = {}
    for addr in range(0x08960000, min(0x08970000, search_end), 8):
        off = psp_to_offset(addr)
        if off + 8 > len(data):
            break
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        if op == 2:  # J instruction
            target = ((instr & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
            # Check if next instruction is NOP (common for stubs)
            instr2 = read_u32(data, off + 4)
            if instr2 == 0:
                wider_stubs[addr] = target

    # Find callers for wider stubs not already found
    new_stubs = {k: v for k, v in wider_stubs.items() if k not in stubs}
    if new_stubs:
        print(f"  Found {len(new_stubs)} additional stubs:")
        for stub_addr_found in sorted(new_stubs.keys()):
            callers = find_jal_callers(data, stub_addr_found, search_start, search_end)
            if callers:
                target = new_stubs[stub_addr_found]
                print(f"\n  Stub 0x{stub_addr_found:08X} -> J 0x{target:08X}  ({len(callers)} callers)")
                for c in callers:
                    cw = cwcheat_offset(c)
                    print(f"    Caller: 0x{c:08X}  (CW:0x{cw:07X})")

    print("\n" + "="*80)
    print("3. CONTEXT AROUND sceDisplaySetFrameBuf CALL (0x08822490)")
    print("="*80)

    # The JAL to sceDisplaySetFrameBuf was at 0x08822490 (or nearby)
    # Let's find the exact caller first
    framebuf_callers = find_jal_callers(data, 0x08960D30, search_start, search_end)

    for caller in framebuf_callers:
        print(f"\n  --- Context around caller at 0x{caller:08X} ---")
        # 50 instructions before, the call itself, and 50 after
        start_addr = caller - 50 * 4
        print("\n  [50 instructions BEFORE the call]")
        for line in disassemble_range(data, start_addr, 50):
            print(line)
        print("\n  [THE CALL and 50 instructions AFTER]")
        for line in disassemble_range(data, caller, 51):
            print(line)

    print("\n" + "="*80)
    print("4. SEARCHING FOR FRAME COUNTER / VBLANK COUNT PATTERNS")
    print("="*80)

    # Look for slti with small values (1, 2, 3) which could be frame counter checks
    # slti: opcode = 0x0A, encoding: 0x28XXYYYY where XX includes rs,rt and YYYY is immediate
    # slti $rt, $rs, imm -> 001010 rs(5) rt(5) imm(16)

    print("\n  Searching for 'slti $reg, $reg, 2' (30fps frame counter check):")
    code_start_off = psp_to_offset(CODE_START)
    code_end_off = min(psp_to_offset(CODE_END), len(data) - 3)

    for off in range(code_start_off, code_end_off, 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        imm = instr & 0xFFFF
        if op == 0x0A and imm in (2, 3):  # slti with imm=2 or 3
            addr = offset_to_psp(off)
            cw = cwcheat_offset(addr)
            decoded = decode_mips_instr(instr, addr)
            print(f"    0x{addr:08X} (CW:0x{cw:07X}): {instr:08X}  {decoded}")

    # Also look for addiu $reg, $reg, 1 followed by slti or bne patterns (counter increment + check)
    print("\n  Searching for 'addiu $reg, $reg, 1' (counter increment) near slti/bne:")
    for off in range(code_start_off, code_end_off, 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        simm = imm if imm < 0x8000 else imm - 0x10000

        # addiu $rt, $rs, 1 where rt == rs (counter++)
        if op == 0x09 and simm == 1 and rs == rt and rs != 0 and rs != 29:  # not $zero, not $sp
            # Check next few instructions for a compare/branch
            for delta in range(1, 5):
                next_off = off + delta * 4
                if next_off + 4 > len(data):
                    break
                next_instr = read_u32(data, next_off)
                next_op = (next_instr >> 26) & 0x3F
                next_imm = next_instr & 0xFFFF
                next_simm = next_imm if next_imm < 0x8000 else next_imm - 0x10000
                # slti with small values
                if next_op == 0x0A and 1 <= next_simm <= 5:
                    addr = offset_to_psp(off)
                    cw = cwcheat_offset(addr)
                    print(f"\n    Counter increment at 0x{addr:08X} (CW:0x{cw:07X}):")
                    for line in disassemble_range(data, addr - 4, 10):
                        print(line)
                    break

    print("\n" + "="*80)
    print("5. MHFU-STYLE SPEED CONTROL: HALFWORD VALUE CONTROLLING FRAME COUNT")
    print("="*80)

    # In MHFU, a halfword at 0x08A5DD18 with value 1 controls speed
    # Look for lh/lhu instructions loading a value that's compared to small constants
    # Also search for the specific value pattern in data sections

    # Search for halfwords with value 1 or 2 in likely data regions that are referenced
    # by lh/lhu instructions from code

    # Let's look for a specific pattern: load halfword, check against small constant
    print("\n  Searching for lh/lhu + slti/beq patterns with small constants (frame skip control):")
    found_patterns = []
    for off in range(code_start_off, code_end_off, 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F

        # lh (0x21) or lhu (0x25)
        if op in (0x21, 0x25):
            rt = (instr >> 16) & 0x1F
            # Check next few instructions for comparison with small value
            for delta in range(1, 6):
                next_off = off + delta * 4
                if next_off + 4 > len(data):
                    break
                next_instr = read_u32(data, next_off)
                next_op = (next_instr >> 26) & 0x3F
                next_rs = (next_instr >> 21) & 0x1F
                next_imm = next_instr & 0xFFFF
                next_simm = next_imm if next_imm < 0x8000 else next_imm - 0x10000

                # slti using the loaded register, with small immediate
                if next_op == 0x0A and next_rs == rt and 1 <= next_simm <= 4:
                    addr = offset_to_psp(off)
                    cw = cwcheat_offset(addr)
                    found_patterns.append((addr, cw))
                    break

    print(f"  Found {len(found_patterns)} potential frame-skip patterns:")
    for addr, cw in found_patterns[:30]:  # limit output
        print(f"\n    Pattern at 0x{addr:08X} (CW:0x{cw:07X}):")
        for line in disassemble_range(data, addr - 4, 12):
            print(line)
    if len(found_patterns) > 30:
        print(f"\n    ... and {len(found_patterns) - 30} more")

    print("\n" + "="*80)
    print("6. SEARCH FOR sceDisplayGetVcount AND VBLANK COUNTER READS")
    print("="*80)

    # sceDisplayGetVcount returns the vblank counter
    # Look for its stub and callers
    # NID: 0x40F1469C

    # Let's search all stubs more carefully
    # Also look for JALR calls (indirect calls through registers)
    print("\n  Searching for JALR $ra, $reg (indirect function calls) in frame-related code:")
    # We'll focus on the area around the framebuf caller

    print("\n" + "="*80)
    print("7. SEARCHING FOR COMMON SPEED HACK TARGETS")
    print("="*80)

    # Pattern 1: A word/halfword storing frame wait count (1=60fps, 2=30fps)
    # that gets loaded and used as a loop counter for vblank waits

    # Pattern 2: Timer-based frame limiter using GetSystemTime
    # Pattern 3: sceDisplaySetFrameBuf sync parameter (already tried)

    # Let's look for loops that call stubs (especially small tight loops)
    print("\n  Looking for tight loops around stub calls (potential vblank wait loops):")
    for stub_addr_found in sorted(stubs.keys()):
        callers = find_jal_callers(data, stub_addr_found, search_start, search_end)
        for c in callers:
            # Check if there's a branch back to before the call within ~20 instructions
            for delta in range(1, 20):
                check_off = psp_to_offset(c + delta * 4)
                if check_off + 4 > len(data):
                    break
                check_instr = read_u32(data, check_off)
                check_op = (check_instr >> 26) & 0x3F
                if check_op in (0x04, 0x05, 0x06, 0x07, 0x01):  # branch instructions
                    check_imm = check_instr & 0xFFFF
                    check_simm = check_imm if check_imm < 0x8000 else check_imm - 0x10000
                    branch_target = (c + delta * 4) + 4 + (check_simm << 2)
                    # Does it branch back to before or at the call?
                    if branch_target <= c and branch_target >= c - 40:
                        check_addr = offset_to_psp(check_off)
                        print(f"\n    Loop around stub call at 0x{c:08X} -> stub 0x{stub_addr_found:08X}:")
                        loop_start = branch_target - 4
                        for line in disassemble_range(data, loop_start, (check_addr - loop_start) // 4 + 4):
                            print(line)
                        break

    # Pattern: Look for values of 16667 (microseconds = 1/60th second) or 33333 (1/30th)
    # These are common sceKernelDelayThread arguments
    print("\n  Searching for delay constants (16667us=60fps, 33333us=30fps):")
    for val, desc in [(16667, "1/60s"), (33333, "1/30s"), (16666, "~1/60s"), (33334, "~1/30s")]:
        # Look for lui + ori or addiu loading this value
        # 16667 = 0x411B, fits in 16-bit immediate
        # 33333 = 0x8235, fits in 16-bit (signed: -32203)

        # Search for the value as a 32-bit word in data section
        val_bytes = struct.pack('<I', val)
        pos = 0
        while True:
            idx = data.find(val_bytes, pos)
            if idx == -1:
                break
            psp_addr = offset_to_psp(idx)
            if 0x08800000 <= psp_addr < search_end:
                cw = cwcheat_offset(psp_addr)
                print(f"    Value {val} ({desc}) at PSP 0x{psp_addr:08X} (CW:0x{cw:07X})")
            pos = idx + 4

        # Also look for li (ori $rt, $zero, val) or addiu $rt, $zero, val
        if val < 0x10000:
            # ori $rt, $zero, val: 001101 00000 rt(5) val(16) = 0x34XX????
            # addiu $rt, $zero, val: 001001 00000 rt(5) val(16) = 0x24XX????
            for off in range(code_start_off, code_end_off, 4):
                instr = read_u32(data, off)
                op = (instr >> 26) & 0x3F
                rs = (instr >> 21) & 0x1F
                imm = instr & 0xFFFF
                if rs == 0 and imm == val:
                    if op == 0x0D:  # ori
                        addr = offset_to_psp(off)
                        cw = cwcheat_offset(addr)
                        decoded = decode_mips_instr(instr, addr)
                        print(f"    ori loading {val} ({desc}) at 0x{addr:08X} (CW:0x{cw:07X}): {decoded}")
                    elif op == 0x09:  # addiu
                        addr = offset_to_psp(off)
                        cw = cwcheat_offset(addr)
                        decoded = decode_mips_instr(instr, addr)
                        print(f"    addiu loading {val} ({desc}) at 0x{addr:08X} (CW:0x{cw:07X}): {decoded}")

    print("\n" + "="*80)
    print("8. BROADER SEARCH: ALL JAL TARGETS IN STUB REGION")
    print("="*80)

    # Find ALL JAL instructions in code that target the stub region (0x08960000-0x08970000)
    print("\n  All JAL instructions targeting 0x08960000-0x08970000:")
    jal_targets = {}
    for off in range(code_start_off, code_end_off, 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        if op == 3:  # JAL
            target = ((instr & 0x03FFFFFF) << 2) | (offset_to_psp(off) & 0xF0000000)
            if 0x08960000 <= target < 0x08970000:
                if target not in jal_targets:
                    jal_targets[target] = []
                jal_targets[target].append(offset_to_psp(off))

    for target in sorted(jal_targets.keys()):
        callers = jal_targets[target]
        # Check what's at the stub
        stub_off = psp_to_offset(target)
        if stub_off + 4 <= len(data):
            stub_instr = read_u32(data, stub_off)
            stub_decoded = decode_mips_instr(stub_instr, target)
        else:
            stub_decoded = "(out of range)"
        print(f"\n  Target 0x{target:08X} [{stub_decoded}] - {len(callers)} callers:")
        for c in callers[:10]:
            cw = cwcheat_offset(c)
            print(f"    0x{c:08X} (CW:0x{cw:07X})")
        if len(callers) > 10:
            print(f"    ... and {len(callers) - 10} more")

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print("""
Key things to try for speed hack:
1. If sceKernelDelayThread is found: NOP the call or reduce the delay value
2. If vblank wait loop found: Reduce loop count or NOP the wait
3. If frame counter compared to 2: Change comparison to 1
4. If timer-based limiter: Modify the target tick count
5. Data-based approach: Find the halfword/word that controls frame timing
""")

if __name__ == "__main__":
    main()
