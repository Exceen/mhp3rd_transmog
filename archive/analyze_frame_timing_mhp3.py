#!/usr/bin/env python3
"""
Deep analysis of the most promising frame timing locations found in MHP3rd.
Focus on:
1. The counter+16666us pattern at 0x088E6900
2. The 16666us load at 0x08866080
3. The 33333 data table at 0x0898497C
4. The NID-based stub identification for sceKernelDelayThread etc.
5. Identify which stubs in the stub region correspond to timing functions
"""

import struct
import zstandard as zstd

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_BASE = 0x08000000
CWCHEAT_BASE = 0x08800000

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def offset_to_psp(off):
    return off - MEM_OFFSET + PSP_BASE

def cwcheat_offset(addr):
    return addr - CWCHEAT_BASE

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def decode_mips_instr(instr, addr):
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

    if instr == 0: return "nop"
    if op == 0:
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
        if funct == 0x0A: return f"movz ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x0B: return f"movn ${regs[rd]}, ${regs[rs]}, ${regs[rt]}"
        if funct == 0x18: return f"mult ${regs[rs]}, ${regs[rt]}"
        if funct == 0x1A: return f"div ${regs[rs]}, ${regs[rt]}"
        if funct == 0x10: return f"mfhi ${regs[rd]}"
        if funct == 0x12: return f"mflo ${regs[rd]}"
        return f"R-type funct=0x{funct:02X} rs={regs[rs]} rt={regs[rt]} rd={regs[rd]}"
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
        if rt == 0x10: return f"bltzal ${regs[rs]}, 0x{btarget:08X}"
        if rt == 0x11: return f"bgezal ${regs[rs]}, 0x{btarget:08X}"
        return f"REGIMM rt={rt} ${regs[rs]}, 0x{btarget:08X}"
    if op == 0x08: return f"addi ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x09: return f"addiu ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x0A: return f"slti ${regs[rt]}, ${regs[rs]}, {simm}"
    if op == 0x0B: return f"sltiu ${regs[rt]}, ${regs[rs]}, {imm}"
    if op == 0x0C: return f"andi ${regs[rt]}, ${regs[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori ${regs[rt]}, ${regs[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori ${regs[rt]}, ${regs[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui ${regs[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x21: return f"lh ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x23: return f"lw ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x24: return f"lbu ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x25: return f"lhu ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x28: return f"sb ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x29: return f"sh ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x2B: return f"sw ${regs[rt]}, {simm}(${regs[rs]})"
    if op == 0x1F:
        # ALLEGREX special instructions (ext, ins, seb, seh, etc.)
        special3_funct = funct
        if special3_funct == 0x20:
            # SEB/SEH/BITREV/WSBH etc based on shamt
            if shamt == 0x10: return f"seb ${regs[rd]}, ${regs[rt]}"
            if shamt == 0x18: return f"seh ${regs[rd]}, ${regs[rt]}"
            return f"BSHFL shamt=0x{shamt:02X} rd={regs[rd]} rt={regs[rt]}"
        if special3_funct == 0x00:
            # EXT
            lsb = shamt
            msbd = rd
            return f"ext ${regs[rt]}, ${regs[rs]}, {lsb}, {msbd+1}"
        if special3_funct == 0x04:
            # INS
            lsb = shamt
            msb = rd
            return f"ins ${regs[rt]}, ${regs[rs]}, {lsb}, {msb-lsb+1}"
        return f"SPECIAL3 funct=0x{funct:02X} raw=0x{instr:08X}"
    return f"??? op=0x{op:02X} raw=0x{instr:08X}"

def disasm(data, psp_start, count):
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

def find_jal_callers(data, target_addr, search_start=0x08800000, search_end=0x09600000):
    target_field = (target_addr >> 2) & 0x03FFFFFF
    jal_instr = (0x03 << 26) | target_field
    callers = []
    start_off = psp_to_offset(search_start)
    end_off = min(psp_to_offset(search_end), len(data) - 3)
    for off in range(start_off, end_off, 4):
        if read_u32(data, off) == jal_instr:
            callers.append(offset_to_psp(off))
    return callers

def main():
    print("Loading save state...")
    with open(SAVE_STATE, 'rb') as f:
        raw = f.read()
    compressed = raw[HEADER_SIZE:]
    dctx = zstd.ZstdDecompressor()
    data = dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)
    print(f"Decompressed: {len(data)} bytes\n")

    # ==========================================
    # 1. IDENTIFY TIMING STUBS VIA NID TABLE
    # ==========================================
    print("="*80)
    print("1. IDENTIFYING IMPORT STUBS VIA NID TABLE")
    print("="*80)

    # The PSP import table structure:
    # Each import entry has: name_ptr, flags, entry_size, num_vars, num_funcs, nid_ptr, stub_ptr
    # The NID table and stub table are parallel arrays.
    # We found NIDs at these locations:
    #   sceKernelDelayThread (0xCEADEB47) at 0x089619D0
    #   sceKernelDelayThreadCB (0x68DA9E36) at 0x08961A40
    #   sceDisplaySetFrameBuf (0x289D82FE) at 0x08961AD8
    #   sceKernelGetSystemTimeWide (0x82BC5777) at 0x08961A58
    #   sceKernelGetSystemTimeLow (0x369ED59D) at 0x08961A10

    # Let's look at the NID table regions and map each NID to its stub
    # PSP import stubs are at fixed addresses, 8 bytes each (J target; NOP)
    # The NID table is a separate array. We need to find the import table header
    # that links them.

    # Let's examine the region around the sceDisplay NID table
    # sceDisplaySetFrameBuf NID at 0x08961AD8
    # The known stub for sceDisplaySetFrameBuf is 0x08960D30

    # Let's look at the import structure. The library import header for sceDisplay
    # was found at PSP 0x08961748. Let's read the import header structure.

    # Actually, let's take a more direct approach: scan the NID tables and
    # match them to the stub tables based on the import table structure.

    # PSP SceLibraryStubTable structure (PSP format):
    # +0: name (ptr to library name string)
    # +4: version (2 bytes)
    # +6: attribute (2 bytes)
    # +8: entry_size (1 byte, usually 5 = 5 words = 20 bytes for the struct)
    # +9: num_vars (1 byte)
    # +10: num_funcs (2 bytes)
    # +12: nid_table_ptr (pointer to array of NIDs)
    # +16: stub_table_ptr (pointer to array of stubs)

    # Let's scan for import table entries
    # The library name 'sceDisplay' is at 0x08961748
    # 'ThreadManForUser' is at 0x089616F4

    # Let's search for import headers that reference these strings
    print("\n  Looking for import headers referencing known library strings...")

    import_headers = []
    search_start_off = psp_to_offset(0x08960000)
    search_end_off = psp_to_offset(0x08962000)

    known_lib_addrs = {
        0x08961748: "sceDisplay",
        0x089616F4: "ThreadManForUser",
        0x089617B0: "sceRtc",
    }

    for off in range(search_start_off, search_end_off, 4):
        val = read_u32(data, off)
        if val in known_lib_addrs:
            psp_addr = offset_to_psp(off)
            lib_name = known_lib_addrs[val]
            print(f"\n  Import header for '{lib_name}' at PSP 0x{psp_addr:08X}:")

            # Read the import header structure
            # Try both 5-word and 6-word formats
            for i in range(6):
                word = read_u32(data, off + i * 4)
                print(f"    +{i*4:2d}: 0x{word:08X}")

            # Assuming standard format: name at +0
            # +4: version/attr
            # +8: entry_size | num_vars | num_funcs
            meta = read_u32(data, off + 8)
            entry_size = (meta >> 0) & 0xFF
            num_vars = (meta >> 8) & 0xFF
            num_funcs = (meta >> 16) & 0xFFFF

            # Actually the PSP format has:
            # +8: 1 byte entry_len (in 32-bit words), 1 byte num_vars, 2 bytes num_funcs
            # But it could also be different. Let's try reading it correctly.
            byte8 = data[off + 8]
            byte9 = data[off + 9]
            half10 = read_u16(data, off + 10)

            print(f"    entry_size={byte8} num_vars={byte9} num_funcs={half10}")

            nid_table_ptr = read_u32(data, off + 12)
            stub_table_ptr = read_u32(data, off + 16)
            print(f"    nid_table=0x{nid_table_ptr:08X} stub_table=0x{stub_table_ptr:08X}")

            if 0x08800000 <= nid_table_ptr < 0x09700000 and 0x08800000 <= stub_table_ptr < 0x09700000:
                print(f"\n    Function stubs:")
                for j in range(half10):
                    nid_off = psp_to_offset(nid_table_ptr + j * 4)
                    stub_off = psp_to_offset(stub_table_ptr + j * 8)
                    if nid_off + 4 <= len(data) and stub_off + 8 <= len(data):
                        nid = read_u32(data, nid_off)
                        stub_instr = read_u32(data, stub_off)
                        stub_addr = stub_table_ptr + j * 8

                        # Look up NID name
                        nid_name = {
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
                            0xDB821F47: "sceKernelGetSystemTime",
                            0x110DEC9A: "sceKernelUSec2SysClock",
                            0xC8CD158C: "sceKernelUSec2SysClockWide",
                            0xBA6B92E2: "sceKernelSysClock2USec",
                            0xE1619D7C: "sceKernelSysClock2USecWide",
                            0xD6DA4BA1: "sceKernelCreateSema",
                            0x28B6489C: "sceKernelDeleteSema",
                            0x3F53E640: "sceKernelSignalSema",
                            0x4E3A1105: "sceKernelWaitSema",
                            0x6D212BAC: "sceKernelWaitSemaCB",
                            0x58B1F937: "sceKernelPollSema",
                            0xBC6FEBC5: "sceKernelReferSemaStatus",
                            0x55C20A00: "sceKernelCreateEventFlag",
                            0xEF9E4C70: "sceKernelDeleteEventFlag",
                            0x1FB15A32: "sceKernelSetEventFlag",
                            0x812346E4: "sceKernelClearEventFlag",
                            0x402FCF22: "sceKernelWaitEventFlag",
                            0x328C546F: "sceKernelWaitEventFlagCB",
                            0x30FD48F0: "sceKernelPollEventFlag",
                            0xCD203292: "sceKernelCancelEventFlag",
                            0xA66B0120: "sceKernelReferEventFlagStatus",
                            0x57CF62DD: "sceKernelCreateThread",
                            0x9FA03CD3: "sceKernelDeleteThread",
                            0xF475845D: "sceKernelStartThread",
                            0xAA73C935: "sceKernelExitThread",
                            0x809CE29B: "sceKernelExitDeleteThread",
                            0x616403BA: "sceKernelTerminateThread",
                            0x383F7BCC: "sceKernelTerminateDeleteThread",
                            0x3AD58B8C: "sceKernelSuspendDispatchThread",
                            0x27E22EC2: "sceKernelResumeDispatchThread",
                            0x293B45B8: "sceKernelGetThreadId",
                            0x17C1684E: "sceKernelReferThreadStatus",
                            0x94AA61EE: "sceKernelGetThreadCurrentPriority",
                            0x71BC9871: "sceKernelChangeThreadPriority",
                            0x912354A7: "sceKernelRotateThreadReadyQueue",
                            0x9ACE131E: "sceKernelSleepThread",
                            0x82826F70: "sceKernelSleepThreadCB",
                            0xD59EAD2F: "sceKernelWakeupThread",
                            0xFCCFAD26: "sceKernelCancelWakeupThread",
                            0x278C0106: "sceKernelWaitThreadEnd",
                            0x840E8133: "sceKernelWaitThreadEndCB",
                            0xD13BDE95: "sceKernelCheckThreadStack",
                            0x94416130: "sceKernelGetThreadmanIdList",
                            0x64D4540E: "sceKernelReferThreadProfiler",
                            0x8218B4DD: "sceKernelReferGlobalProfiler",
                        }.get(nid, f"unknown_0x{nid:08X}")

                        decoded = decode_mips_instr(stub_instr, stub_addr)
                        cw = cwcheat_offset(stub_addr)
                        callers = find_jal_callers(data, stub_addr, 0x08800000, 0x09600000)
                        print(f"      [{j:2d}] NID=0x{nid:08X} -> {nid_name}")
                        print(f"           Stub at 0x{stub_addr:08X} (CW:0x{cw:07X}): {decoded}")
                        print(f"           {len(callers)} callers: {['0x%08X' % c for c in callers[:5]]}")

                        # Save timing-related stubs for detailed analysis
                        if lib_name == "sceDisplay" or nid_name in [
                            "sceKernelDelayThread", "sceKernelDelayThreadCB",
                            "sceKernelGetSystemTimeWide", "sceKernelGetSystemTimeLow",
                        ]:
                            import_headers.append((stub_addr, nid_name, callers))

    # ==========================================
    # 2. DEEP ANALYSIS OF THE 16666us FRAME TIMING FUNCTION
    # ==========================================
    print("\n" + "="*80)
    print("2. DEEP ANALYSIS: FRAME TIMING FUNCTION AT 0x088E68xx")
    print("="*80)

    # The counter at 0x088E6904 increments, compares to 2, and loads 16666
    # Let's disassemble the full function
    # Find function start (look for stack frame setup)
    print("\n  Full function around 0x088E6900 (frame timing with 16666us):")
    for line in disasm(data, 0x088E6800, 80):
        print(line)

    # ==========================================
    # 3. DEEP ANALYSIS OF 16666us AT 0x08866080
    # ==========================================
    print("\n" + "="*80)
    print("3. DEEP ANALYSIS: FUNCTION AT 0x08866080 (16666us)")
    print("="*80)
    for line in disasm(data, 0x08866020, 60):
        print(line)

    # ==========================================
    # 4. THE 33333 DATA TABLE AT 0x0898497C
    # ==========================================
    print("\n" + "="*80)
    print("4. THE 33333us DATA TABLE AT 0x0898497C")
    print("="*80)
    # These are evenly spaced 33333 values - likely a table of frame timing data
    print("\n  Data around 0x08984970:")
    for i in range(30):
        addr = 0x08984960 + i * 4
        off = psp_to_offset(addr)
        val = read_u32(data, off)
        cw = cwcheat_offset(addr)
        print(f"  0x{addr:08X} (CW:0x{cw:07X}): 0x{val:08X} ({val})")

    # Find what code references this table
    # Look for lui 0x0898 in code
    print("\n  Searching for code loading address 0x08984xxx (the 33333 table):")
    search_start_off = psp_to_offset(0x08800000)
    search_end_off = psp_to_offset(0x09600000)
    for off in range(search_start_off, min(search_end_off, len(data) - 3), 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        imm = instr & 0xFFFF
        if op == 0x0F and imm == 0x0898:  # lui $reg, 0x0898
            # Check next few instructions for addiu with offset near 0x4900-0x4D00
            for delta in range(1, 5):
                next_off = off + delta * 4
                if next_off + 4 > len(data):
                    break
                next_instr = read_u32(data, next_off)
                next_op = (next_instr >> 26) & 0x3F
                next_imm = next_instr & 0xFFFF
                next_simm = next_imm if next_imm < 0x8000 else next_imm - 0x10000
                if next_op == 0x09 and 0x4900 <= next_imm <= 0x4E00:  # addiu with table offset
                    addr = offset_to_psp(off)
                    cw = cwcheat_offset(addr)
                    print(f"\n    Reference at 0x{addr:08X} (CW:0x{cw:07X}):")
                    for line in disasm(data, addr - 8, 20):
                        print(line)
                    break

    # ==========================================
    # 5. THE 33333 CONSTANT AT 0x08A3AEA8 (IN DATA)
    # ==========================================
    print("\n" + "="*80)
    print("5. DATA VALUE 33333 AT 0x08A3AEA8")
    print("="*80)
    # This could be a single variable controlling frame timing
    addr = 0x08A3AEA8
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    cw = cwcheat_offset(addr)
    print(f"  0x{addr:08X} (CW:0x{cw:07X}): value = {val} (0x{val:08X})")

    # Check surrounding data
    print("\n  Context (16 words around it):")
    for i in range(-8, 8):
        a = addr + i * 4
        o = psp_to_offset(a)
        v = read_u32(data, o)
        c = cwcheat_offset(a)
        marker = " <---" if i == 0 else ""
        print(f"  0x{a:08X} (CW:0x{c:07X}): 0x{v:08X} ({v}){marker}")

    # Find code that references this address (lui 0x08A3 + addiu/lw with offset near 0xAEA8)
    print("\n  Code referencing 0x08A3AEA8:")
    for off in range(search_start_off, min(search_end_off, len(data) - 3), 4):
        instr = read_u32(data, off)
        op = (instr >> 26) & 0x3F
        imm = instr & 0xFFFF
        if op == 0x0F and imm == 0x08A4:  # lui $reg, 0x08A4 (since 0xAEA8 is negative offset from 0x08A4xxxx)
            for delta in range(1, 8):
                next_off = off + delta * 4
                if next_off + 4 > len(data):
                    break
                next_instr = read_u32(data, next_off)
                next_op = (next_instr >> 26) & 0x3F
                next_simm = (next_instr & 0xFFFF)
                if next_simm >= 0x8000:
                    next_simm -= 0x10000
                # 0x08A3AEA8 = 0x08A40000 + (-0x5158) = 0x08A40000 - 0x5158
                if next_op in (0x23, 0x25, 0x21) and next_simm == -0x5158:  # lw/lhu/lh with correct offset
                    addr_ref = offset_to_psp(off)
                    cw_ref = cwcheat_offset(addr_ref)
                    print(f"\n    Reference at 0x{addr_ref:08X} (CW:0x{cw_ref:07X}):")
                    for line in disasm(data, addr_ref - 4, 20):
                        print(line)
                    break

    # ==========================================
    # 6. 16666 CONSTANT AT 0x08A33E44
    # ==========================================
    print("\n" + "="*80)
    print("6. DATA VALUE 16666 AT 0x08A33E44")
    print("="*80)
    addr = 0x08A33E44
    off = psp_to_offset(addr)
    val = read_u32(data, off)
    cw = cwcheat_offset(addr)
    print(f"  0x{addr:08X} (CW:0x{cw:07X}): value = {val} (0x{val:08X})")

    print("\n  Context (16 words around it):")
    for i in range(-8, 8):
        a = addr + i * 4
        o = psp_to_offset(a)
        v = read_u32(data, o)
        c = cwcheat_offset(a)
        marker = " <---" if i == 0 else ""
        print(f"  0x{a:08X} (CW:0x{c:07X}): 0x{v:08X} ({v}){marker}")

    # ==========================================
    # 7. CALLERS OF TIMING-RELATED STUBS (with context)
    # ==========================================
    print("\n" + "="*80)
    print("7. DETAILED CALLERS OF TIMING STUBS")
    print("="*80)

    for stub_addr, name, callers in import_headers:
        if not callers:
            continue
        print(f"\n  --- {name} (stub 0x{stub_addr:08X}) ---")
        for c in callers:
            cw = cwcheat_offset(c)
            print(f"\n    Caller at 0x{c:08X} (CW:0x{cw:07X}):")
            for line in disasm(data, c - 20, 15):
                print(line)

    # ==========================================
    # 8. SUMMARY
    # ==========================================
    print("\n" + "="*80)
    print("8. SPEED HACK CANDIDATES SUMMARY")
    print("="*80)
    print("""
MOST PROMISING TARGETS:

A) Frame counter at 0x088E6904 with 16666us:
   - Increments counter, compares to 2 (30fps check)
   - Loads 16666us (1/60 second) as return value
   - MOVZ selects between 16666 and the counter result
   -> Try: NOP the counter check, or change slti immediate from 2 to 1

B) The 33333us (1/30s) data table at 0x0898497C:
   - Many entries of 33333 (evenly spaced every 0x28 = 40 bytes)
   - This looks like a frame timing configuration table
   -> Try: Change all 33333 values to 16667 for 60fps

C) The single 33333 value at 0x08A3AEA8:
   - Could be a global frame timing variable
   -> Try: Change to 16667

D) sceKernelDelayThread callers:
   - If the delay value is 33333, NOP the call or halve the value

E) sceDisplaySetFrameBuf function at 0x08822464:
   - The $a3 (sync=1) at 0x0882247C was already tried
   - Look at the surrounding logic for vblank count control
""")

if __name__ == "__main__":
    main()
