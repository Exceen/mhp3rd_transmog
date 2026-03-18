#!/usr/bin/env python3
"""
Deep Frame Timing Analysis for MHP3rd (ULJM05800)
===================================================
Previous attempts to create a speed hack by patching sync=1->0 at 0x0882247C
had NO EFFECT. This script takes a fundamentally different approach:

1. VBLANK callback registration (sceDisplay NIDs, subintr handlers)
2. Thread-based frame sync (WaitEventFlag, WaitSema, etc.)
3. MHFU reference: what does the WORKING speed cheat at 0x080590BC actually patch?
4. Game speed multiplier search (float constants in data)
5. HD version 60fps cheat pattern matching
6. Full sceDisplay import table analysis
7. Main loop timing via system clock reads
"""

import struct
import zstandard
import sys

# ============================================================
# Configuration
# ============================================================
MHP3_SAVE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
MHFU_SAVE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05500_1.01_0.ppst"

HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_RAM_BASE = 0x08000000
CW_BASE = 0x08800000

# MIPS register names
REGS = ['zero','at','v0','v1','a0','a1','a2','a3',
        't0','t1','t2','t3','t4','t5','t6','t7',
        's0','s1','s2','s3','s4','s5','s6','s7',
        't8','t9','k0','k1','gp','sp','fp','ra']

# Known PSP syscall NIDs
KNOWN_NIDS = {
    # sceDisplay
    0x289D82FE: "sceDisplaySetFrameBuf",
    0x0E20F177: "sceDisplaySetMode",
    0x984C27E7: "sceDisplayWaitVblankStart",
    0x46F186C3: "sceDisplayWaitVblankStartCB",
    0x36CDFADE: "sceDisplayWaitVblank",
    0x8EB9EC49: "sceDisplayRegisterVblankStartCallback",
    0x21038913: "sceDisplayGetVcount",
    0xEEDA2E54: "sceDisplayGetFrameBuf",
    0xDBA6C4C4: "sceDisplayGetMode",
    0xB4F378FA: "sceDisplayIsForeground",
    0x7ED59BC4: "sceDisplaySetHoldMode",
    0xDEA197D4: "sceDisplayGetCurrentHcount",
    0x40F1469C: "sceDisplayWaitVblankStartMulti",
    0x77ED8B3A: "sceDisplayWaitVblankStartMultiCB",
    # sceCtrl
    0x6A2774F3: "sceCtrlSetSamplingCycle",
    0x1F4011E6: "sceCtrlSetSamplingMode",
    0x3A622550: "sceCtrlPeekBufferPositive",
    0xC152080A: "sceCtrlPeekBufferNegative",
    0x1F803938: "sceCtrlReadBufferPositive",
    0x60B81F86: "sceCtrlReadBufferNegative",
    # sceKernel threading
    0x402FCF22: "sceKernelWaitEventFlag",
    0x328C546F: "sceKernelWaitEventFlagCB",
    0x812346E4: "sceKernelClearEventFlag",
    0x1FB15A32: "sceKernelSetEventFlag",
    0x55C20A00: "sceKernelCreateEventFlag",
    0xEF9E4C70: "sceKernelDeleteEventFlag",
    0x3AD58B8C: "sceKernelWaitSema",
    0x6D212BAC: "sceKernelWaitSemaCB",
    0x3F53E640: "sceKernelSignalSema",
    0xD6DA4BA1: "sceKernelCreateSema",
    0x28B6489C: "sceKernelDeleteSema",
    0x74829B76: "sceKernelReceiveMsgPipe",
    0xFBFA697D: "sceKernelReceiveMsgPipeCB",
    0x876DBFAD: "sceKernelSendMsgPipe",
    0x7C0DC2A0: "sceKernelSendMsgPipeCB",
    0xDF52098F: "sceKernelTryReceiveMsgPipe",
    # sceKernel timing
    0xB2C25152: "sceKernelGetSystemTimeLow",
    0xDB738F35: "sceKernelGetSystemTime",
    0x369ED59D: "sceKernelGetSystemTimeWide",
    0xCEAB09BB: "sceKernelDelayThread",
    0x68DA9E36: "sceKernelDelayThreadCB",
    0x110DEC9A: "sceKernelUSec2SysClock",
    0xC8CD158C: "sceKernelUSec2SysClockWide",
    0xBA6B92E2: "sceKernelSysClock2USec",
    0xE1619D7C: "sceKernelSysClock2USecWide",
    # sceKernel interrupt
    0xCA04A2B9: "sceKernelRegisterSubIntrHandler",
    0xD61E6961: "sceKernelReleaseSubIntrHandler",
    0xFB8E22EC: "sceKernelEnableSubIntr",
    0x8A389411: "sceKernelDisableSubIntr",
    # sceRtc
    0x3F7AD767: "sceRtcGetCurrentTick",
    0x029CA3B3: "sceRtcGetAccumulativeTime",
    0x011F03C1: "sceRtcGetCurrentClock",
    0x4CFA57B0: "sceRtcGetCurrentClockLocalTime",
    0x7ED29E40: "sceRtcSetTick",
    0x6FF40ACC: "sceRtcGetTick",
    0xC41C2853: "sceRtcGetTickResolution",
    # sceGe
    0xAB49E76A: "sceGeListEnQueue",
    0x1C0D95A6: "sceGeListEnQueueHead",
    0x05DB22CE: "sceGeListSync",
    0xB287BD61: "sceGeDrawSync",
    0xA4FC06A4: "sceGeSetCallback",
    0x0BF608FB: "sceGeUnsetCallback",
    # power
    0x0AFD0D8B: "scePowerTick",
    0x04B7766E: "scePowerRegisterCallback",
    0xEFD3C963: "scePowerGetCpuClockFrequency",
    0x737486F2: "scePowerSetClockFrequency",
    0x469989AD: "scePowerSetCpuClockFrequency",
    0xB8D7B3FB: "scePowerSetBusClockFrequency",
    # thread mgmt
    0x446D8DE6: "sceKernelCreateThread",
    0xF475845D: "sceKernelStartThread",
    0xAA73C935: "sceKernelExitThread",
    0x616403BA: "sceKernelTerminateThread",
    0x809CE29B: "sceKernelExitDeleteThread",
    0x9ACE131E: "sceKernelSleepThread",
    0x82826F70: "sceKernelSleepThreadCB",
    0xD59EAD2F: "sceKernelWakeupThread",
    0x9944F31F: "sceKernelSuspendThread",
    0x75156E8F: "sceKernelResumeThread",
    0xCEADEB47: "sceKernelDelayThread",  # alternate
}

# ============================================================
# Utility functions
# ============================================================

def decompress_save_state(path):
    with open(path, "rb") as f:
        f.seek(HEADER_SIZE)
        compressed = f.read()
    dctx = zstandard.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)

def psp_to_offset(psp_addr):
    return (psp_addr - PSP_RAM_BASE) + MEM_OFFSET

def offset_to_psp(off):
    return (off - MEM_OFFSET) + PSP_RAM_BASE

def read8(data, psp_addr):
    off = psp_to_offset(psp_addr)
    if 0 <= off < len(data):
        return data[off]
    return None

def read16(data, psp_addr):
    off = psp_to_offset(psp_addr)
    if 0 <= off < len(data) - 1:
        return struct.unpack_from("<H", data, off)[0]
    return None

def read32(data, psp_addr):
    off = psp_to_offset(psp_addr)
    if 0 <= off < len(data) - 3:
        return struct.unpack_from("<I", data, off)[0]
    return None

def cw_offset(psp_addr):
    return psp_addr - CW_BASE

def cw_addr_str(psp_addr):
    return f"0x{cw_offset(psp_addr):07X}"

def cw_line_32(psp_addr, value):
    return f"_L 0x2{cw_offset(psp_addr):07X} 0x{value:08X}"

def cw_line_16(psp_addr, value):
    return f"_L 0x1{cw_offset(psp_addr):07X} 0x0000{value:04X}"

def decode_mips(word, addr):
    """Decode a MIPS instruction to human-readable form."""
    if word == 0:
        return "nop"
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    sa = (word >> 6) & 0x1F
    func = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    target26 = word & 0x03FFFFFF

    if op == 0:  # SPECIAL
        if func == 0x00:
            if word == 0: return "nop"
            return f"sll ${REGS[rd]}, ${REGS[rt]}, {sa}"
        if func == 0x02: return f"srl ${REGS[rd]}, ${REGS[rt]}, {sa}"
        if func == 0x03: return f"sra ${REGS[rd]}, ${REGS[rt]}, {sa}"
        if func == 0x04: return f"sllv ${REGS[rd]}, ${REGS[rt]}, ${REGS[rs]}"
        if func == 0x06: return f"srlv ${REGS[rd]}, ${REGS[rt]}, ${REGS[rs]}"
        if func == 0x07: return f"srav ${REGS[rd]}, ${REGS[rt]}, ${REGS[rs]}"
        if func == 0x08: return f"jr ${REGS[rs]}"
        if func == 0x09: return f"jalr ${REGS[rd]}, ${REGS[rs]}" if rd != 31 else f"jalr ${REGS[rs]}"
        if func == 0x0A: return f"movz ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x0B: return f"movn ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x0C: return "syscall"
        if func == 0x10: return f"mfhi ${REGS[rd]}"
        if func == 0x12: return f"mflo ${REGS[rd]}"
        if func == 0x18: return f"mult ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x19: return f"multu ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x1A: return f"div ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x1B: return f"divu ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x20: return f"add ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x21: return f"addu ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x22: return f"sub ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x23: return f"subu ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x24: return f"and ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x25: return f"or ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x26: return f"xor ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x27: return f"nor ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x2A: return f"slt ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x2B: return f"sltu ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        return f"special_0x{func:02X} ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"

    if op == 1:  # REGIMM
        if rt == 0x00:
            t = addr + 4 + (simm << 2)
            return f"bltz ${REGS[rs]}, 0x{t:08X}"
        if rt == 0x01:
            t = addr + 4 + (simm << 2)
            return f"bgez ${REGS[rs]}, 0x{t:08X}"
        if rt == 0x11:
            t = addr + 4 + (simm << 2)
            return f"bgezal ${REGS[rs]}, 0x{t:08X}"
        return f"regimm_0x{rt:02X} ${REGS[rs]}, 0x{imm:04X}"

    if op == 2:
        t = (target26 << 2) | (addr & 0xF0000000)
        return f"j 0x{t:08X}"
    if op == 3:
        t = (target26 << 2) | (addr & 0xF0000000)
        return f"jal 0x{t:08X}"
    if op == 4:
        t = addr + 4 + (simm << 2)
        return f"beq ${REGS[rs]}, ${REGS[rt]}, 0x{t:08X}"
    if op == 5:
        t = addr + 4 + (simm << 2)
        return f"bne ${REGS[rs]}, ${REGS[rt]}, 0x{t:08X}"
    if op == 6:
        t = addr + 4 + (simm << 2)
        return f"blez ${REGS[rs]}, 0x{t:08X}"
    if op == 7:
        t = addr + 4 + (simm << 2)
        return f"bgtz ${REGS[rs]}, 0x{t:08X}"
    if op == 8:
        return f"addi ${REGS[rt]}, ${REGS[rs]}, {simm}"
    if op == 9:
        return f"addiu ${REGS[rt]}, ${REGS[rs]}, {simm}"
    if op == 0xA:
        return f"slti ${REGS[rt]}, ${REGS[rs]}, {simm}"
    if op == 0xB:
        return f"sltiu ${REGS[rt]}, ${REGS[rs]}, {simm}"
    if op == 0xC:
        return f"andi ${REGS[rt]}, ${REGS[rs]}, 0x{imm:04X}"
    if op == 0xD:
        return f"ori ${REGS[rt]}, ${REGS[rs]}, 0x{imm:04X}"
    if op == 0xE:
        return f"xori ${REGS[rt]}, ${REGS[rs]}, 0x{imm:04X}"
    if op == 0xF:
        return f"lui ${REGS[rt]}, 0x{imm:04X}"

    # Load/store
    ls_names = {0x20:"lb",0x21:"lh",0x22:"lwl",0x23:"lw",0x24:"lbu",0x25:"lhu",0x26:"lwr",
                0x28:"sb",0x29:"sh",0x2A:"swl",0x2B:"sw",0x2E:"swr"}
    if op in ls_names:
        return f"{ls_names[op]} ${REGS[rt]}, {simm}(${REGS[rs]})"

    # FPU (COP1)
    if op == 0x11:
        fmt = rs
        if fmt == 0x10:  # .S (single)
            if func == 0x00: return f"add.s $f{rd}, $f{(word>>11)&0x1F}, $f{rt}"
            if func == 0x01: return f"sub.s $f{rd}, $f{(word>>11)&0x1F}, $f{rt}"
            if func == 0x02: return f"mul.s $f{rd}, $f{(word>>11)&0x1F}, $f{rt}"
            if func == 0x03: return f"div.s $f{rd}, $f{(word>>11)&0x1F}, $f{rt}"
            if func == 0x06: return f"mov.s $f{rd}, $f{(word>>11)&0x1F}"
            if func == 0x04: return f"sqrt.s $f{rd}, $f{(word>>11)&0x1F}"
            if func == 0x05: return f"abs.s $f{rd}, $f{(word>>11)&0x1F}"
            if func == 0x07: return f"neg.s $f{rd}, $f{(word>>11)&0x1F}"
            if func == 0x0D: return f"trunc.w.s $f{rd}, $f{(word>>11)&0x1F}"
            if func == 0x24: return f"cvt.w.s $f{rd}, $f{(word>>11)&0x1F}"
            if func >= 0x30:
                cond_names = {0x30:"c.f.s",0x31:"c.un.s",0x32:"c.eq.s",0x33:"c.ueq.s",
                              0x34:"c.olt.s",0x35:"c.ult.s",0x36:"c.ole.s",0x37:"c.ule.s",
                              0x38:"c.sf.s",0x39:"c.ngle.s",0x3A:"c.seq.s",0x3B:"c.ngl.s",
                              0x3C:"c.lt.s",0x3D:"c.nge.s",0x3E:"c.le.s",0x3F:"c.ngt.s"}
                fd = (word >> 6) & 0x1F
                fs = (word >> 11) & 0x1F
                cn = cond_names.get(func, f"c.?{func:02X}.s")
                return f"{cn} $f{fs}, $f{rt}"
            return f"cop1.s func=0x{func:02X}"
        if fmt == 0x14:  # .W
            if func == 0x20: return f"cvt.s.w $f{rd}, $f{(word>>11)&0x1F}"
            return f"cop1.w func=0x{func:02X}"
        if fmt == 0x00:  # mfc1
            return f"mfc1 ${REGS[rt]}, $f{rd}"
        if fmt == 0x04:  # mtc1
            return f"mtc1 ${REGS[rt]}, $f{rd}"
        if fmt == 0x08:  # BC1
            if rt == 0: return f"bc1f 0x{addr + 4 + (simm << 2):08X}"
            if rt == 1: return f"bc1t 0x{addr + 4 + (simm << 2):08X}"
            return f"bc1?{rt}"
        return f"cop1 fmt={fmt} 0x{word:08X}"

    # LWC1 / SWC1
    if op == 0x31:
        return f"lwc1 $f{rt}, {simm}(${REGS[rs]})"
    if op == 0x39:
        return f"swc1 $f{rt}, {simm}(${REGS[rs]})"

    # VFPU (COP2) - just show raw
    if op == 0x12:
        return f"cop2 0x{word:08X}"
    if op == 0x32:
        return f"lwc2 (vfpu) 0x{word:08X}"
    if op == 0x3A:
        return f"swc2 (vfpu) 0x{word:08X}"

    # SPECIAL2
    if op == 0x1C:
        if func == 0x02: return f"mul ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x20: return f"clz ${REGS[rd]}, ${REGS[rs]}"
        if func == 0x24: return f"msub ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x00: return f"madd ${REGS[rs]}, ${REGS[rt]}"
        return f"special2 func=0x{func:02X}"

    # SPECIAL3
    if op == 0x1F:
        if func == 0x20:  # ext / ins via SEB/SEH
            size = rd + 1
            pos = sa
            return f"ext ${REGS[rt]}, ${REGS[rs]}, {pos}, {size}"
        if func == 0x04:
            size = rd - sa + 1
            return f"ins ${REGS[rt]}, ${REGS[rs]}, {sa}, {size}"
        if sa == 0x10 and func == 0x20: return f"seb ${REGS[rd]}, ${REGS[rt]}"
        if sa == 0x18 and func == 0x20: return f"seh ${REGS[rd]}, ${REGS[rt]}"
        return f"special3 0x{word:08X}"

    return f"??? 0x{word:08X}"


def disasm_range(data, start_addr, count):
    """Disassemble 'count' instructions starting at start_addr. Returns list of (addr, word, text)."""
    result = []
    for i in range(count):
        addr = start_addr + i * 4
        w = read32(data, addr)
        if w is None:
            result.append((addr, 0, "<out of range>"))
        else:
            result.append((addr, w, decode_mips(w, addr)))
    return result

def print_disasm(data, start_addr, count, prefix="    "):
    for addr, w, text in disasm_range(data, start_addr, count):
        print(f"{prefix}0x{addr:08X}: 0x{w:08X}  {text}")

def find_bytes(data, pattern, start_psp=0x08800000, end_psp=0x09FFFFFF, max_results=50):
    """Find all occurrences of a byte pattern in PSP memory range."""
    results = []
    start_off = psp_to_offset(start_psp)
    end_off = psp_to_offset(end_psp)
    if start_off < 0: start_off = 0
    if end_off > len(data): end_off = len(data)

    off = start_off
    while len(results) < max_results:
        idx = data.find(pattern, off, end_off)
        if idx == -1:
            break
        results.append(offset_to_psp(idx))
        off = idx + 1
    return results

def find_word(data, word, start_psp=0x08800000, end_psp=0x09FFFFFF, max_results=50):
    return find_bytes(data, struct.pack("<I", word), start_psp, end_psp, max_results)

def find_jal_to(data, target, start_psp=0x08804000, end_psp=0x08FFFFFF):
    """Find all JAL instructions targeting a given address."""
    # JAL encoding: opcode=3, target26 = (target >> 2) & 0x03FFFFFF
    target26 = (target >> 2) & 0x03FFFFFF
    jal_word = (3 << 26) | target26
    return find_word(data, jal_word, start_psp, end_psp)

def find_stub_for_syscall(data, start_psp=0x08900000, end_psp=0x09700000):
    """Find all syscall stubs: jr $ra / syscall X patterns.
    PSP stubs are: jr $ra; syscall N (where jr $ra = 0x03E00008)"""
    results = []
    jr_ra = 0x03E00008
    start_off = psp_to_offset(start_psp)
    end_off = psp_to_offset(end_psp)

    for off in range(start_off, min(end_off, len(data) - 7), 4):
        w0 = struct.unpack_from("<I", data, off)[0]
        if w0 == jr_ra:
            w1 = struct.unpack_from("<I", data, off + 4)[0]
            if (w1 >> 26) == 0 and (w1 & 0x3F) == 0x0C:  # syscall
                syscall_num = (w1 >> 6) & 0xFFFFF
                psp_addr = offset_to_psp(off)
                results.append((psp_addr, syscall_num))
    return results

def find_all_stubs_in_import_tables(data):
    """Find PSP import stub tables. Each imported library has a structure with
    NID table and stub table. The stubs are jr $ra + syscall.
    We scan for all jr $ra / syscall pairs and group them."""
    return find_stub_for_syscall(data)

def is_branch(word):
    """Check if instruction is a branch/jump."""
    op = (word >> 26) & 0x3F
    if op in (2, 3):  # j, jal
        return True
    if op in (4, 5, 6, 7):  # beq, bne, blez, bgtz
        return True
    if op == 1:  # REGIMM (bltz, bgez, etc.)
        return True
    if op == 0:
        func = word & 0x3F
        if func in (8, 9):  # jr, jalr
            return True
    return False


# ============================================================
# Analysis functions
# ============================================================

def analyze_vblank_callbacks(data):
    """Section 1: VBLANK callback registration"""
    print("=" * 80)
    print("SECTION 1: VBLANK CALLBACK REGISTRATION")
    print("=" * 80)

    # Search for sceDisplayRegisterVblankStartCallback NID 0x8EB9EC49
    nid_bytes = struct.pack("<I", 0x8EB9EC49)
    locs = find_bytes(data, nid_bytes, 0x08800000, 0x09700000)
    print(f"\n  NID 0x8EB9EC49 (sceDisplayRegisterVblankStartCallback) found at: {len(locs)} locations")
    for loc in locs:
        print(f"    0x{loc:08X}")
        # Check surrounding context - this is likely in a NID table
        print(f"    Context (8 words):")
        for i in range(-4, 4):
            a = loc + i * 4
            v = read32(data, a)
            nid_name = KNOWN_NIDS.get(v, "")
            marker = " <-- this NID" if i == 0 else ""
            if nid_name:
                print(f"      0x{a:08X}: 0x{v:08X}  [{nid_name}]{marker}")
            else:
                print(f"      0x{a:08X}: 0x{v:08X}{marker}")

    # Search for sceKernelRegisterSubIntrHandler NID 0xCA04A2B9
    nid_bytes2 = struct.pack("<I", 0xCA04A2B9)
    locs2 = find_bytes(data, nid_bytes2, 0x08800000, 0x09700000)
    print(f"\n  NID 0xCA04A2B9 (sceKernelRegisterSubIntrHandler) found at: {len(locs2)} locations")
    for loc in locs2:
        print(f"    0x{loc:08X}")

    # Find the actual stubs
    stubs = find_stub_for_syscall(data)
    print(f"\n  Total syscall stubs found: {len(stubs)}")

    # For each stub, check if it's called with VBLANK-related args
    # sceKernelRegisterSubIntrHandler(PSP_VBLANK_INT=30, subintr, handler, arg)
    # Look for calls where $a0 = 30 (0x1E)
    # addiu $a0, $zero, 30 = 0x2404001E
    print(f"\n  Searching for 'addiu $a0, $zero, 30' (0x2404001E) near JAL instructions...")
    load_a0_30 = find_word(data, 0x2404001E, 0x08804000, 0x08960000)
    for loc in load_a0_30:
        print(f"\n    Found at 0x{loc:08X}:")
        print_disasm(data, loc - 16, 12)

    # Also check for li $a0, 30 via ori
    # ori $a0, $zero, 0x001E = 0x3404001E
    load_a0_30b = find_word(data, 0x3404001E, 0x08804000, 0x08960000)
    if load_a0_30b:
        print(f"\n  Also found 'ori $a0, $zero, 0x1E' at:")
        for loc in load_a0_30b:
            print(f"    0x{loc:08X}")
            print_disasm(data, loc - 8, 8)


def analyze_thread_sync(data):
    """Section 2: Thread-based frame synchronization"""
    print("\n" + "=" * 80)
    print("SECTION 2: THREAD-BASED FRAME SYNCHRONIZATION")
    print("=" * 80)

    # Key NIDs to find
    sync_nids = {
        0x402FCF22: "sceKernelWaitEventFlag",
        0x328C546F: "sceKernelWaitEventFlagCB",
        0x3AD58B8C: "sceKernelWaitSema",
        0x6D212BAC: "sceKernelWaitSemaCB",
        0x74829B76: "sceKernelReceiveMsgPipe",
        0x1FB15A32: "sceKernelSetEventFlag",
        0x3F53E640: "sceKernelSignalSema",
        0x984C27E7: "sceDisplayWaitVblankStart",
        0x46F186C3: "sceDisplayWaitVblankStartCB",
        0x36CDFADE: "sceDisplayWaitVblank",
    }

    for nid, name in sync_nids.items():
        nid_bytes = struct.pack("<I", nid)
        locs = find_bytes(data, nid_bytes, 0x08800000, 0x09700000)
        if locs:
            print(f"\n  {name} (NID 0x{nid:08X}): found in NID tables at {len(locs)} location(s)")
            for loc in locs:
                print(f"    NID table entry: 0x{loc:08X}")
        else:
            print(f"\n  {name} (NID 0x{nid:08X}): NOT imported")

    # Now find all stubs and try to match them to known syscalls
    # The PSP import table structure: for each library:
    #   - A list of NIDs (4 bytes each)
    #   - A corresponding list of stubs (8 bytes each: jr $ra; syscall N)
    # We can scan for stub blocks and correlate

    # Better approach: find NID table entries and corresponding stubs
    # NID table and stub table are paired - each NID at position i corresponds to stub at position i
    # The import header at some address contains pointers to both tables

    # Let's find all stubs and just look for who calls them
    stubs = find_stub_for_syscall(data, 0x08960000, 0x09700000)
    print(f"\n  --- Tracing callers of synchronization-related stubs ---")

    # Group stubs by proximity (import tables have stubs in blocks of 8 bytes)
    # We need to match stubs to NIDs. Let's try the correlation approach:
    # For each NID we found, figure out which stub corresponds to it.

    # PSP import structure (simplified):
    # At some location there's a table of NIDs and a table of stubs.
    # The stubs are at addresses like 0x0896XXXX, and NIDs are nearby.
    # Let's look for patterns: blocks of consecutive stubs

    stub_dict = {}  # addr -> syscall_num
    for addr, scnum in stubs:
        stub_dict[addr] = scnum

    # Find all NID table entries for our sync functions
    # Then try to find the corresponding stub
    print(f"\n  --- Mapping NIDs to stubs ---")
    nid_to_stub = {}

    for nid, name in sync_nids.items():
        nid_bytes = struct.pack("<I", nid)
        locs = find_bytes(data, nid_bytes, 0x08800000, 0x09700000)
        for nid_loc in locs:
            # The NID table is an array. We need to find which index this NID is at.
            # Then the stub table has the same index.
            # PSP import headers contain: nid_table_ptr, stub_table_ptr, num_funcs
            # The stubs are 8 bytes each (jr $ra + syscall)

            # Heuristic: find the start of the NID block (consecutive valid NIDs)
            # Then count our offset to get index
            # Then look for a stub block at a similar index offset

            # Simpler: check the import module table structure
            # Each import entry is 0x2C bytes with:
            #   +0x00: name_ptr
            #   +0x08: attr
            #   +0x0C: entry_size (usually 5)
            #   +0x0D: var_count
            #   +0x0E: func_count (u16)
            #   +0x10: nid_table_ptr
            #   +0x14: stub_table_ptr

            # For now, let's just record the NID location
            # and search for the stub that corresponds to it
            pass

    # Alternative approach: scan stub area, find consecutive stubs, then
    # look for their NID tables nearby
    print(f"\n  --- Finding stub blocks and their NID tables ---")

    # Group stubs into blocks (consecutive stubs 8 bytes apart)
    sorted_stubs = sorted(stubs, key=lambda x: x[0])
    blocks = []
    current_block = []
    for addr, scnum in sorted_stubs:
        if current_block and addr != current_block[-1][0] + 8:
            blocks.append(current_block)
            current_block = []
        current_block.append((addr, scnum))
    if current_block:
        blocks.append(current_block)

    print(f"  Found {len(blocks)} stub blocks")

    # For each block, the NID table should be at a location where
    # the import header points to both
    # Let's try to find NID tables by searching for the stub block address
    # in memory (the import header contains a pointer to the stub table)
    stub_to_name = {}
    for block in blocks:
        block_start = block[0][0]
        block_size = len(block)

        # Search for pointer to this stub block
        ptr_locs = find_word(data, block_start, 0x08800000, 0x09700000)
        for ptr_loc in ptr_locs:
            # This might be the stub_table_ptr in an import header
            # The nid_table_ptr would be at ptr_loc - 4
            nid_table_ptr = read32(data, ptr_loc - 4)
            if nid_table_ptr and 0x08800000 <= nid_table_ptr < 0x09700000:
                # Read NIDs from the NID table
                for i, (stub_addr, scnum) in enumerate(block):
                    nid = read32(data, nid_table_ptr + i * 4)
                    if nid is not None:
                        name = KNOWN_NIDS.get(nid, f"unknown_0x{nid:08X}")
                        stub_to_name[stub_addr] = (name, nid, scnum)

    # Print all identified stubs
    print(f"\n  Identified {len(stub_to_name)} stubs:")
    for addr in sorted(stub_to_name.keys()):
        name, nid, scnum = stub_to_name[addr]
        print(f"    0x{addr:08X}: syscall 0x{scnum:05X} = {name} (NID 0x{nid:08X})")

    # Now find callers of the key synchronization stubs
    key_funcs = [
        "sceKernelWaitEventFlag", "sceKernelWaitEventFlagCB",
        "sceKernelWaitSema", "sceKernelWaitSemaCB",
        "sceKernelReceiveMsgPipe",
        "sceDisplayWaitVblankStart", "sceDisplayWaitVblankStartCB",
        "sceDisplayWaitVblank",
        "sceDisplaySetFrameBuf",
        "sceKernelGetSystemTimeLow", "sceKernelGetSystemTimeWide",
        "sceRtcGetCurrentTick",
        "sceKernelDelayThread", "sceKernelDelayThreadCB",
        "sceKernelSetEventFlag", "sceKernelSignalSema",
        "sceKernelSleepThread", "sceKernelSleepThreadCB",
        "sceGeDrawSync", "sceGeListSync",
    ]

    for func_name in key_funcs:
        # Find stub address for this function
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            if callers:
                print(f"\n  *** {func_name} @ 0x{stub_addr:08X} - {len(callers)} caller(s):")
                for caller in callers:
                    print(f"\n      Caller at 0x{caller:08X} (CW: {cw_addr_str(caller)}):")
                    # Show context - back up to find function start (look for addiu $sp, $sp, -N)
                    print_disasm(data, caller - 24, 16, prefix="        ")

    return stub_to_name


def analyze_mhfu_reference(data_mhp3):
    """Section 3: MHFU speed cheat reference"""
    print("\n" + "=" * 80)
    print("SECTION 3: MHFU SPEED CHEAT REFERENCE (0x080590BC)")
    print("=" * 80)

    try:
        data_mhfu = decompress_save_state(MHFU_SAVE)
        print(f"\n  MHFU save state loaded, size: {len(data_mhfu)} bytes")

        # The working MHFU speed cheat patches 0x080590BC
        # Read what's at that address in the unpatched state
        addr = 0x080590BC
        w = read32(data_mhfu, addr)
        print(f"\n  Instruction at 0x{addr:08X}: 0x{w:08X}")
        print(f"  Decoded: {decode_mips(w, addr)}")

        # Show surrounding context
        print(f"\n  Context around 0x{addr:08X}:")
        print_disasm(data_mhfu, addr - 40, 24)

        # Check if it's a JAL - if so, what does it call?
        op = (w >> 26) & 0x3F
        if op == 3:  # JAL
            target = ((w & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
            print(f"\n  JAL target: 0x{target:08X}")
            print(f"  Code at target:")
            print_disasm(data_mhfu, target, 16)

            # Check if target is a syscall stub
            t0 = read32(data_mhfu, target)
            t1 = read32(data_mhfu, target + 4)
            if t0 == 0x03E00008 and t1 is not None and ((t1 >> 26) == 0 and (t1 & 0x3F) == 0x0C):
                scnum = (t1 >> 6) & 0xFFFFF
                print(f"  -> This is a syscall stub! syscall 0x{scnum:05X}")

        # Also check the broader function this is in
        # Go back to find function prologue
        print(f"\n  Searching for function prologue before 0x{addr:08X}...")
        for back in range(4, 200, 4):
            w_back = read32(data_mhfu, addr - back)
            if w_back is not None:
                decoded = decode_mips(w_back, addr - back)
                if "addiu $sp, $sp, -" in decoded:
                    func_start = addr - back
                    print(f"  Function likely starts at 0x{func_start:08X}")
                    print(f"  Full function disassembly:")
                    print_disasm(data_mhfu, func_start, 60)
                    break

        # Now search for the SAME pattern in MHP3rd
        print(f"\n  --- Searching for equivalent pattern in MHP3rd ---")

        # What is the instruction? Let's analyze what the speed cheat replaces it WITH
        # Common speed cheats replace a JAL with NOP, or replace a branch condition
        # If it's a jal to sceDisplayWaitVblankStart or sceKernelDelayThread, we need
        # to find the equivalent in MHP3rd

        # Let's look for the function pattern in MHP3rd
        # Get a signature from the MHFU function
        if op == 3:  # If it was a JAL
            target = ((w & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
            t0 = read32(data_mhfu, target)
            t1 = read32(data_mhfu, target + 4)
            if t0 == 0x03E00008:
                # The cheat NOPs a call to a syscall stub
                # Let's figure out which syscall by looking at the NID
                scnum = (t1 >> 6) & 0xFFFFF
                # Search for the same syscall number in MHP3rd stubs
                print(f"  MHFU call targets syscall 0x{scnum:05X}")
                print(f"  Searching for same syscall in MHP3rd stubs...")

                mhp3_stubs = find_stub_for_syscall(data_mhp3, 0x08960000, 0x09700000)
                for s_addr, s_num in mhp3_stubs:
                    if s_num == scnum:
                        print(f"    Found MHP3rd stub with same syscall at 0x{s_addr:08X}")
                        callers = find_jal_to(data_mhp3, s_addr)
                        print(f"    Callers in MHP3rd: {len(callers)}")
                        for c in callers:
                            print(f"\n      0x{c:08X} (CW: {cw_addr_str(c)}):")
                            print_disasm(data_mhp3, c - 20, 14)

        # Also try to find the MHFU instruction bytes literally in MHP3rd
        # (unlikely to work due to different addresses, but check the surrounding pattern)
        # Instead, search for the instruction before and after 0x080590BC
        prev_w = read32(data_mhfu, addr - 4)
        next_w = read32(data_mhfu, addr + 4)
        print(f"\n  MHFU instructions around the patch point:")
        print(f"    0x{addr-4:08X}: 0x{prev_w:08X}  {decode_mips(prev_w, addr-4)}")
        print(f"    0x{addr:08X}: 0x{w:08X}  {decode_mips(w, addr)}  <-- PATCHED BY SPEED CHEAT")
        print(f"    0x{addr+4:08X}: 0x{next_w:08X}  {decode_mips(next_w, addr+4)}")

    except Exception as e:
        print(f"\n  ERROR loading MHFU save state: {e}")
        import traceback
        traceback.print_exc()


def analyze_float_constants(data):
    """Section 4: Game speed multiplier / float constants"""
    print("\n" + "=" * 80)
    print("SECTION 4: GAME SPEED MULTIPLIER (FLOAT CONSTANTS)")
    print("=" * 80)

    float_targets = {
        0x42700000: "60.0f (FPS)",
        0x41F00000: "30.0f (half FPS)",
        0x3F800000: "1.0f (multiplier)",
        0x3C888889: "1/60.0f (frame time ~0.01667)",
        0x3D088889: "1/30.0f (frame time ~0.03333)",
        0x3DCCCCCD: "0.1f",
        0x3E4CCCCD: "0.2f",
        0x3F000000: "0.5f",
        0x40000000: "2.0f",
        0x40800000: "4.0f",
        0x41200000: "10.0f",
        0x41C80000: "25.0f",
        0x41F80000: "31.0f",
        0x42000000: "32.0f",
        0x42480000: "50.0f",
        0x42C80000: "100.0f",
        0x447A0000: "1000.0f",
        0x3C8EFA35: "1/57.0f",
        0x3CA3D70A: "0.02f (50Hz frame time)",
        0x3C75C28F: "0.015f",
        0x411FFFFF: "~10.0f (9.999...)",
    }

    # Focus on data sections (not code area which has many coincidental matches)
    # Data areas in MHP3rd: 0x08960000+ and 0x09000000+
    data_ranges = [
        (0x08930000, 0x08960000, "read-only data near code"),
        (0x08960000, 0x09000000, "static data"),
        (0x09000000, 0x09A00000, "heap/dynamic data"),
    ]

    # Also search code area for LUI + ORI patterns loading these floats
    print("\n  --- Float constants in data sections ---")
    for fval, fname in sorted(float_targets.items()):
        all_locs = []
        for range_start, range_end, range_name in data_ranges:
            locs = find_word(data, fval, range_start, range_end)
            for loc in locs:
                all_locs.append((loc, range_name))
        if all_locs and len(all_locs) <= 30:
            print(f"\n  0x{fval:08X} ({fname}): {len(all_locs)} hit(s)")
            for loc, rname in all_locs[:15]:
                print(f"    0x{loc:08X} [{rname}] (CW: {cw_addr_str(loc)})")
                # Check who loads from this address (LUI + LWC1 or LW pattern)
                # Search for lui $XX, (loc>>16)
                lui_hi = loc >> 16
                # The low part
                lo = loc & 0xFFFF

    # Special: search for frame time constants being loaded via LUI+ORI/ADDIU into FPU
    # Pattern: lui $at, HI16 / lwc1 $fN, LO16($at) or mtc1 / lui+ori
    print("\n  --- Searching for code loading frame-time floats (1/30, 1/60) ---")
    for fval, fname in [(0x3C888889, "1/60.0f"), (0x3D088889, "1/30.0f"),
                        (0x42700000, "60.0f"), (0x41F00000, "30.0f")]:
        hi16 = (fval >> 16) & 0xFFFF
        lo16 = fval & 0xFFFF

        # LUI $at, hi16 = 0x3C010000 | hi16
        lui_word = 0x3C010000 | hi16
        lui_locs = find_word(data, lui_word, 0x08804000, 0x08960000)

        # Also check LUI to other regs (t0-t7, v0-v1)
        for reg_idx in [1, 2, 3, 8, 9, 10, 11]:  # at, v0, v1, t0-t3
            lui_w = (0xF << 28) | (reg_idx << 16) | hi16  # lui $reg, hi16
            l = find_word(data, lui_w, 0x08804000, 0x08960000)
            lui_locs.extend(l)

        if lui_locs:
            print(f"\n  LUI loading hi16 of {fname} (0x{hi16:04X}):")
            for loc in lui_locs[:10]:
                # Check next few instructions for ORI/ADDIU with lo16
                print(f"    0x{loc:08X}:")
                print_disasm(data, loc, 4, prefix="      ")

    # Search for integer frame timing: 16667 (microseconds per frame at 60fps)
    # and 33333 (at 30fps)
    print("\n  --- Integer frame time constants ---")
    int_targets = {
        16667: "16667us (1/60s)",
        16666: "16666us (1/60s alt)",
        33333: "33333us (1/30s)",
        33334: "33334us (1/30s alt)",
        16683: "16683us (slightly slow)",
        16700: "16700us (rounded)",
    }
    for ival, iname in int_targets.items():
        # As addiu immediate (fits in 16 bits)
        if ival < 0x8000:
            # addiu $aN, $zero, ival or ori $aN, $zero, ival
            for reg in range(4, 8):  # a0-a3
                addiu_w = (9 << 26) | (reg << 16) | ival
                locs = find_word(data, addiu_w, 0x08804000, 0x08960000)
                for loc in locs:
                    print(f"    addiu ${REGS[reg]}, $zero, {ival} ({iname}) at 0x{loc:08X}")
                    print_disasm(data, loc - 8, 8, prefix="      ")

                ori_w = (0xD << 26) | (reg << 16) | ival
                locs = find_word(data, ori_w, 0x08804000, 0x08960000)
                for loc in locs:
                    print(f"    ori ${REGS[reg]}, $zero, {ival} ({iname}) at 0x{loc:08X}")
                    print_disasm(data, loc - 8, 8, prefix="      ")
        else:
            # Needs LUI+ORI
            hi = (ival >> 16) & 0xFFFF
            lo = ival & 0xFFFF
            # Search for the value as a 32-bit word in data
            locs = find_word(data, ival, 0x08930000, 0x09A00000, 10)
            for loc in locs:
                print(f"    {ival} ({iname}) as data at 0x{loc:08X} (CW: {cw_addr_str(loc)})")

            # Search in code: lui $XX, hi / ori $XX, $XX, lo
            if hi > 0:
                for reg in [1, 2, 3, 8, 9]:
                    lui_w = (0xF << 28) | (reg << 16) | hi
                    locs = find_word(data, lui_w, 0x08804000, 0x08960000)
                    for loc in locs:
                        # Check next instruction for ori with lo
                        next_w = read32(data, loc + 4)
                        if next_w is not None:
                            next_op = (next_w >> 26) & 0x3F
                            next_imm = next_w & 0xFFFF
                            if next_op == 0xD and next_imm == lo:
                                print(f"    LUI+ORI loading {ival} ({iname}) at 0x{loc:08X}")
                                print_disasm(data, loc - 4, 6, prefix="      ")


def analyze_hd_version_pattern(data):
    """Section 5: HD version 60fps cheat pattern matching"""
    print("\n" + "=" * 80)
    print("SECTION 5: HD VERSION 60FPS CHEAT PATTERN MATCHING")
    print("=" * 80)

    # HD version patches:
    # 1. At 0x088766B8: replaces instruction with jump to custom code
    #    The hook jumps back to 0x088766C0 and stores a1 at 0x3660(a2)
    # 2. NOPs 0x088A6AA0
    #
    # The key instruction is: sw $a1, 0x3660($a2) = 0xACC53660

    print("\n  Searching for 'sw $a1, 0x3660($a2)' (0xACC53660) in MHP3rd...")
    target_word = 0xACC53660
    locs = find_word(data, target_word, 0x08804000, 0x09000000)
    if locs:
        for loc in locs:
            print(f"\n    Found at 0x{loc:08X} (CW: {cw_addr_str(loc)}):")
            print_disasm(data, loc - 28, 20)
    else:
        print("    NOT FOUND")

    # Try variations with different offsets near 0x3660
    print("\n  Searching for 'sw $a1, 0x36XX($a2)' patterns...")
    for offset in range(0x3640, 0x3680, 4):
        sw_word = 0xAC450000 | (0x06 << 21) | offset  # sw $a1, offset($a2)
        # Actually: sw rt, imm(rs) = 0x2B << 26 | rs << 21 | rt << 16 | imm
        sw_word = (0x2B << 26) | (6 << 21) | (5 << 16) | offset  # sw $a1, offset($a2)
        locs = find_word(data, sw_word, 0x08804000, 0x09000000)
        if locs:
            for loc in locs:
                print(f"    sw $a1, 0x{offset:04X}($a2) at 0x{loc:08X}")
                print_disasm(data, loc - 12, 10, prefix="      ")

    # Search for the HD reference address 0x08B77B14 pattern
    # In MHP3rd the base address would differ, but the offset pattern might be similar
    # Look for any lw/sw with 0x7B14 offset
    print("\n  Searching for memory accesses with offset 0x7B14...")
    for op_code in [0x23, 0x2B]:  # lw, sw
        for rs in range(32):
            w = (op_code << 26) | (rs << 21) | 0x7B14
            # Need to also specify rt, so search more broadly
            pass

    # Better: search for the value 0x7B14 as an offset in any lw/sw
    # lw $XX, 0x7B14($YY) where low 16 bits = 0x7B14
    for psp_addr_off in range(psp_to_offset(0x08804000), psp_to_offset(0x08960000), 4):
        if psp_addr_off + 3 >= len(data):
            break
        w = struct.unpack_from("<I", data, psp_addr_off)[0]
        imm = w & 0xFFFF
        op = (w >> 26) & 0x3F
        if imm == 0x7B14 and op in (0x23, 0x2B, 0x21, 0x25):  # lw, sw, lh, lhu
            a = offset_to_psp(psp_addr_off)
            print(f"    Instruction with offset 0x7B14 at 0x{a:08X}: {decode_mips(w, a)}")

    # The HD version's key pattern: a frame counter comparison
    # The 60fps patch changes a comparison so the game processes 2 logic frames per render frame
    # Look for frame counter patterns: addiu $reg, $reg, 1 followed by comparison
    # This is very common, so let's narrow down

    # Search for the specific pattern: the HD patch changes what happens after
    # sw $a1, 0x3660($a2) — a1 is likely a frame counter being stored
    # Let's search for stores to large struct offsets (0x3000-0x4000 range)
    # that involve a counter increment

    print("\n  Searching for frame counter increment patterns (addiu $v0/$v1, $v0/$v1, 1 near struct stores)...")
    # addiu $v0, $v0, 1 = 0x24420001
    # addiu $v1, $v1, 1 = 0x24630001
    for inc_word, reg_name in [(0x24420001, "v0"), (0x24630001, "v1"),
                                (0x24A50001, "a1"), (0x24840001, "a0")]:
        locs = find_word(data, inc_word, 0x08804000, 0x08960000)
        for loc in locs:
            # Check nearby for sw with large offset (struct field)
            found_sw = False
            for delta in range(-20, 24, 4):
                nearby = read32(data, loc + delta)
                if nearby is None:
                    continue
                op_nearby = (nearby >> 26) & 0x3F
                if op_nearby == 0x2B:  # sw
                    imm_nearby = nearby & 0xFFFF
                    if imm_nearby >= 0x1000:  # large struct offset
                        found_sw = True
                        break
            if found_sw:
                print(f"\n    addiu ${reg_name}, ${reg_name}, 1 at 0x{loc:08X} near large-offset store:")
                print_disasm(data, loc - 16, 12, prefix="      ")


def analyze_sceDisplay_imports(data, stub_to_name):
    """Section 6: Full sceDisplay import analysis"""
    print("\n" + "=" * 80)
    print("SECTION 6: FULL sceDisplay IMPORT ANALYSIS")
    print("=" * 80)

    # Filter stubs that are sceDisplay functions
    display_stubs = {addr: info for addr, info in stub_to_name.items()
                     if info[0].startswith("sceDisplay")}

    if display_stubs:
        print(f"\n  sceDisplay imports found: {len(display_stubs)}")
        for addr in sorted(display_stubs.keys()):
            name, nid, scnum = display_stubs[addr]
            print(f"    0x{addr:08X}: {name} (NID 0x{nid:08X}, syscall 0x{scnum:05X})")

            # Find all callers
            callers = find_jal_to(data, addr)
            print(f"      {len(callers)} caller(s):")
            for c in callers:
                print(f"        0x{c:08X} (CW offset: {cw_addr_str(c)})")
    else:
        print("\n  No sceDisplay stubs identified via NID matching.")
        print("  Attempting direct NID search in memory...")

        # Search for ALL known sceDisplay NIDs
        display_nids = {k: v for k, v in KNOWN_NIDS.items() if v.startswith("sceDisplay")}
        for nid, name in display_nids.items():
            locs = find_bytes(data, struct.pack("<I", nid), 0x08800000, 0x09700000)
            if locs:
                print(f"    {name} (0x{nid:08X}) NID found at: {[f'0x{l:08X}' for l in locs]}")


def analyze_main_loop_timing(data, stub_to_name):
    """Section 7: Main loop timing via system clock"""
    print("\n" + "=" * 80)
    print("SECTION 7: MAIN LOOP TIMING (SYSTEM CLOCK)")
    print("=" * 80)

    timing_funcs = [
        "sceKernelGetSystemTimeLow",
        "sceKernelGetSystemTimeWide",
        "sceKernelGetSystemTime",
        "sceRtcGetCurrentTick",
        "sceKernelDelayThread",
        "sceKernelDelayThreadCB",
    ]

    for func_name in timing_funcs:
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        if not stub_addrs:
            continue

        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            if callers:
                print(f"\n  {func_name} @ 0x{stub_addr:08X} - {len(callers)} caller(s):")
                for caller in callers:
                    print(f"\n    Caller at 0x{caller:08X} (CW: {cw_addr_str(caller)}):")
                    # Show generous context to find the timing loop
                    print_disasm(data, caller - 32, 24, prefix="      ")

                    # Check if this is inside a timing loop
                    # Look for backward branch (branch target < current address)
                    for i in range(24):
                        a = caller - 32 + i * 4
                        w = read32(data, a)
                        if w is None:
                            continue
                        op = (w >> 26) & 0x3F
                        if op in (4, 5, 6, 7):  # beq, bne, blez, bgtz
                            simm = w & 0xFFFF
                            if simm >= 0x8000:
                                simm -= 0x10000
                            target = a + 4 + (simm << 2)
                            if target < a:  # backward branch = loop
                                print(f"      ^^ BACKWARD BRANCH at 0x{a:08X} -> 0x{target:08X} (possible timing loop!)")

    # Search for busy-wait pattern:
    # GetSystemTimeLow / subtract / compare / branch back
    print("\n  --- Searching for busy-wait timing loops ---")
    # Find all calls to GetSystemTimeLow
    gstl_addrs = [addr for addr, (name, _, _) in stub_to_name.items()
                  if name == "sceKernelGetSystemTimeLow"]
    for gstl_addr in gstl_addrs:
        callers = find_jal_to(data, gstl_addr)
        for caller in callers:
            # Check if there's a backward branch within 20 instructions after the call
            for i in range(1, 20):
                a = caller + i * 4
                w = read32(data, a)
                if w is None:
                    continue
                op = (w >> 26) & 0x3F
                if op in (4, 5, 6, 7, 1):
                    simm = w & 0xFFFF
                    if simm >= 0x8000:
                        simm -= 0x10000
                    target = a + 4 + (simm << 2)
                    if target <= caller:
                        print(f"\n    BUSY-WAIT LOOP detected!")
                        print(f"    GetSystemTimeLow call: 0x{caller:08X}")
                        print(f"    Branch back: 0x{a:08X} -> 0x{target:08X}")
                        # Find the enclosing function
                        func_start = caller
                        for back in range(4, 300, 4):
                            wb = read32(data, caller - back)
                            if wb is not None:
                                d = decode_mips(wb, caller - back)
                                if "addiu $sp, $sp, -" in d:
                                    func_start = caller - back
                                    break
                        print(f"    Function starts at ~0x{func_start:08X}")
                        print(f"    Full context:")
                        num_insn = (a - func_start) // 4 + 10
                        print_disasm(data, func_start, min(num_insn, 60), prefix="      ")
                        break

    # Also look for sceKernelDelayThread callers — the game might use
    # a fixed delay per frame instead of busy-waiting
    print("\n  --- sceKernelDelayThread analysis ---")
    delay_addrs = [addr for addr, (name, _, _) in stub_to_name.items()
                   if "DelayThread" in name]
    for delay_addr in delay_addrs:
        name = stub_to_name[delay_addr][0]
        callers = find_jal_to(data, delay_addr)
        if callers:
            print(f"\n  {name} @ 0x{delay_addr:08X} - {len(callers)} caller(s):")
            for caller in callers:
                print(f"\n    0x{caller:08X} (CW: {cw_addr_str(caller)}):")
                print_disasm(data, caller - 28, 18, prefix="      ")


def generate_suggestions(data, stub_to_name):
    """Generate CWCheat code suggestions based on findings"""
    print("\n" + "=" * 80)
    print("SECTION 8: CWCHEAT CODE SUGGESTIONS")
    print("=" * 80)

    suggestions = []

    # 1. NOP any sceDisplayWaitVblankStart calls
    for func_name in ["sceDisplayWaitVblankStart", "sceDisplayWaitVblankStartCB",
                       "sceDisplayWaitVblank"]:
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            for c in callers:
                suggestions.append((f"NOP {func_name} call",
                                   cw_line_32(c, 0x00000000),
                                   c))

    # 2. NOP sceKernelDelayThread calls (makes game not sleep)
    for func_name in ["sceKernelDelayThread", "sceKernelDelayThreadCB"]:
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            for c in callers:
                suggestions.append((f"NOP {func_name} call",
                                   cw_line_32(c, 0x00000000),
                                   c))

    # 3. sceDisplaySetFrameBuf sync=0
    for addr, (name, _, _) in stub_to_name.items():
        if name == "sceDisplaySetFrameBuf":
            callers = find_jal_to(data, addr)
            for c in callers:
                # Look backward for where $a3 is set (sync parameter)
                for back in range(4, 40, 4):
                    w = read32(data, c - back)
                    if w is not None:
                        d = decode_mips(w, c - back)
                        if "addiu $a3" in d and "1" in d:
                            suggestions.append((f"SetFrameBuf sync=0 (before call at 0x{c:08X})",
                                               cw_line_32(c - back, w & 0xFFFF0000),
                                               c - back))
                            break

    # 4. NOP sceGeDrawSync calls (skip GPU sync waiting)
    for func_name in ["sceGeDrawSync"]:
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            for c in callers:
                suggestions.append((f"NOP {func_name} call",
                                   cw_line_32(c, 0x00000000),
                                   c))

    # 5. NOP sceKernelWaitEventFlag / sceKernelWaitSema calls
    for func_name in ["sceKernelWaitEventFlag", "sceKernelWaitEventFlagCB",
                       "sceKernelWaitSema", "sceKernelWaitSemaCB",
                       "sceKernelSleepThread", "sceKernelSleepThreadCB"]:
        stub_addrs = [addr for addr, (name, _, _) in stub_to_name.items() if name == func_name]
        for stub_addr in stub_addrs:
            callers = find_jal_to(data, stub_addr)
            for c in callers:
                suggestions.append((f"NOP {func_name} call",
                                   cw_line_32(c, 0x00000000),
                                   c))

    if suggestions:
        print(f"\n  {len(suggestions)} potential cheat codes found:\n")
        for i, (desc, code, addr) in enumerate(suggestions):
            print(f"  [{i+1}] {desc}")
            print(f"      Address: 0x{addr:08X}")
            print(f"      CWCheat: {code}")
            print(f"      Context:")
            print_disasm(data, addr - 8, 6, prefix="        ")
            print()
    else:
        print("\n  No direct suggestions generated. See analysis above for manual investigation.")

    # Print combined cheat block for easy testing
    if suggestions:
        print("\n  === Combined CWCheat block (ALL suggestions) ===")
        print("  _S ULJM-05800")
        print("  _G Monster Hunter Portable 3rd")

        # Group by category
        categories = {}
        for desc, code, addr in suggestions:
            cat = desc.split(" ")[0:2]
            cat_key = " ".join(cat)
            if cat_key not in categories:
                categories[cat_key] = []
            categories[cat_key].append((desc, code, addr))

        for cat, items in categories.items():
            print(f"  _C0 Speed Hack - {cat}")
            for desc, code, addr in items:
                print(f"  {code}")
            print()


def main():
    print("Deep Frame Timing Analysis for MHP3rd (ULJM05800)")
    print("=" * 80)

    print("\nDecompressing MHP3rd save state...")
    data = decompress_save_state(MHP3_SAVE)
    print(f"  Decompressed size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # Section 1: VBLANK callbacks
    analyze_vblank_callbacks(data)

    # Section 2: Thread sync (also returns stub mapping for later use)
    stub_to_name = analyze_thread_sync(data)

    # Section 3: MHFU reference
    analyze_mhfu_reference(data)

    # Section 4: Float constants
    analyze_float_constants(data)

    # Section 5: HD version pattern
    analyze_hd_version_pattern(data)

    # Section 6: Full sceDisplay imports
    analyze_sceDisplay_imports(data, stub_to_name)

    # Section 7: Main loop timing
    analyze_main_loop_timing(data, stub_to_name)

    # Section 8: Suggestions
    generate_suggestions(data, stub_to_name)

    # Section 9: DEFINITIVE FINDING - Frame counter pattern match with MHFU
    analyze_frame_counter_definitive(data)

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


def analyze_frame_counter_definitive(data):
    """Section 9: DEFINITIVE frame counter analysis based on MHFU comparison.

    KEY INSIGHT: The MHFU speed cheat address 0x080590BC was MISINTERPRETED.
    It is NOT a raw PSP address (0x080590BC is below EBOOT at 0x08804000).
    It is a CWCheat address: _L 0x200590BC -> PSP address 0x088590BC.

    At 0x088590BC in MHFU:
        lw $a0, -8936($v1)    # Load frame counter
        addiu $a0, $a0, 1     # INCREMENT <-- THIS IS WHAT THE CHEAT NOPS
        sw $a0, -8936($v1)    # Store counter
        slti $v1, $a0, 2      # Compare against 2
        bnel ...               # Skip if counter < 2

    The MHFU cheat NOPs the increment so the counter never reaches the threshold,
    which causes the frame-skip logic to always trigger -> 2x speed.

    In MHP3rd, the EQUIVALENT function is at 0x088E68D4:
        lw $v1, 5528($s0)         # Load frame counter
        addiu $v0, $zero, 16666   # Load delay value (16666us = ~1/60s)
        addiu $v1, $v1, 1         # INCREMENT counter
        sw $v1, 5528($s0)         # Store counter
        slti $a0, $v1, 2          # Compare against 2
        movz $v0, $zero, $a0      # If counter >= 2: return 0 (no delay)
                                   # If counter < 2: return 16666 (delay)

    The function returns a delay value in $v0. The caller uses this to decide
    how long to wait. When $v0 = 0, no waiting occurs.
    """
    print("\n" + "=" * 80)
    print("SECTION 9: DEFINITIVE FINDING - FRAME COUNTER (MHFU-EQUIVALENT)")
    print("=" * 80)

    print("\n  === MHFU Speed Cheat Decoded ===")
    print("  The MHFU speed cheat patches CWCheat address 0x200590BC")
    print("  This is PSP address 0x088590BC (NOT 0x080590BC)")
    print("  The original instruction: addiu $a0, $a0, 1 (frame counter increment)")
    print("  The cheat NOPs it -> counter never reaches 2 -> frame skip always triggers")

    print("\n  === MHP3rd Equivalent Function at 0x088E68D4 ===")
    print_disasm(data, 0x088E68D4, 20)

    print("\n  === Analysis ===")
    print("  0x088E68FC: lw $v1, 5528($s0)        - Load frame counter from struct+0x1598")
    print("  0x088E6900: addiu $v0, $zero, 16666   - Set default return = 16666us delay")
    print("  0x088E6904: addiu $v1, $v1, 1         - Increment frame counter")
    print("  0x088E6908: sw $v1, 5528($s0)         - Store incremented counter")
    print("  0x088E690C: slti $a0, $v1, 2          - a0 = (counter < 2) ? 1 : 0")
    print("  0x088E6910: movz $v0, $zero, $a0      - If a0==0 (counter>=2): v0 = 0")
    print("  Return: v0 = 16666 if counter < 2 (wait), v0 = 0 if counter >= 2 (skip)")
    print()
    print("  Counter reset at 0x088E68BC: sw $zero, 5528($s0)")
    print("  The counter cycles: 0->1 (return 16666), 1->2 (return 0), reset to 0")
    print("  This means: game processes logic every OTHER frame = 30fps logic at 60fps vsync")

    # Verify the instruction bytes
    w_inc = read32(data, 0x088E6904)
    w_slti = read32(data, 0x088E690C)
    w_movz = read32(data, 0x088E6910)
    w_delay = read32(data, 0x088E6900)

    print(f"\n  Verification:")
    print(f"    0x088E6900: 0x{w_delay:08X} (expected 0x2402411A = addiu $v0, $zero, 16666)")
    print(f"    0x088E6904: 0x{w_inc:08X} (expected 0x24630001 = addiu $v1, $v1, 1)")
    print(f"    0x088E690C: 0x{w_slti:08X} (expected 0x28640002 = slti $a0, $v1, 2)")
    print(f"    0x088E6910: 0x{w_movz:08X} (expected 0x0004100A = movz $v0, $zero, $a0)")

    all_ok = (w_inc == 0x24630001 and w_slti == 0x28640002 and
              w_movz == 0x0004100A and w_delay == 0x2402411A)
    print(f"    All match: {'YES' if all_ok else 'NO'}")

    print("\n  " + "=" * 60)
    print("  RECOMMENDED CWCHEAT CODES FOR SPEED HACK")
    print("  " + "=" * 60)

    print("\n  Option A: Force return value to 0 (always skip delay)")
    print("  Replace movz with unconditional: addu $v0, $zero, $zero")
    print(f"  _L 0x{cw_offset(0x088E6910):07X} 0x00001021")
    print(f"  CWCheat: _L 0x20{cw_offset(0x088E6910):06X} 0x00001021")

    print("\n  Option B: Force comparison result (a0 always = 0)")
    print("  Replace slti with: addiu $a0, $zero, 0")
    print(f"  CWCheat: _L 0x20{cw_offset(0x088E690C):06X} 0x24040000")

    print("\n  Option C: NOP the delay constant load (v0 inherits jal return = unpredictable)")
    print("  WARNING: This is what was tried before at 0x088E6900 and may not work reliably")
    print(f"  CWCheat: _L 0x20{cw_offset(0x088E6900):06X} 0x00000000")

    print("\n  Option D: MHFU-style - NOP the counter increment")
    print("  Counter stays at 0, slti gives a0=1, movz does NOT fire, v0=16666 returned")
    print("  WARNING: This makes it SLOWER (always returns delay value)!")
    print(f"  CWCheat: _L 0x20{cw_offset(0x088E6904):06X} 0x00000000")
    print("  DO NOT USE - the MHP3rd logic is INVERTED compared to MHFU!")

    print("\n  Option E: Change threshold from 2 to 1 (process logic every frame)")
    print("  slti $a0, $v1, 1 instead of slti $a0, $v1, 2")
    print(f"  CWCheat: _L 0x20{cw_offset(0x088E690C):06X} 0x28640001")
    print("  This makes counter reach threshold every frame -> always return 0")

    print("\n  " + "-" * 60)
    print("  RECOMMENDED: Use Option A or Option E")
    print()
    print("  For copy-paste into ULJM05800.ini:")
    print()
    print("  _S ULJM-05800")
    print("  _G Monster Hunter Portable 3rd")
    print("  _C0 Speed Hack (2x) - Force Skip Frame Delay")
    print(f"  _L 0x20{cw_offset(0x088E6910):06X} 0x00001021")
    print()
    print("  Alternative (change frame skip threshold):")
    print("  _C0 Speed Hack (2x) - Every-Frame Logic")
    print(f"  _L 0x20{cw_offset(0x088E690C):06X} 0x28640001")
    print()
    print("  NOTE: This function is called via function pointer (jalr),")
    print("  not via direct JAL, which is why static caller tracing didn't find callers.")
    print("  The function pointer is likely stored in a vtable or callback struct.")
    print()
    print("  For even more speed (3x, 4x), combine with SetFrameBuf sync=0:")
    print("  _C0 Speed Hack (Max) - Skip Delay + No VSync")
    print(f"  _L 0x20{cw_offset(0x088E6910):06X} 0x00001021")
    print(f"  _L 0x2002247C 0x24070000")
    print()


if __name__ == "__main__":
    main()
