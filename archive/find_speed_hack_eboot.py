#!/usr/bin/env python3
"""
Find speed hack addresses for MHP3rd (ULJM05800) from save state memory.

The EBOOT.BIN is encrypted (~PSP format), so we extract the decrypted code
from a PPSSPP save state instead.

Strategy:
1. Decompress the save state to get the full PSP memory image.
2. Determine the EBOOT's load address and code boundaries from the ELF
   program headers (which PPSSPP places in memory at the load address).
3. Search for the frame timing constant 16666 (0x411A) and the frame
   counter check (slti with immediate 2) within the EBOOT code region.
4. Cross-reference nearby patterns to find the actual frame timing function.
5. Also search for sceDisplaySetFrameBuf calls with sync=1 parameter.
6. Calculate correct CWCheat offsets for all findings.
7. Output ready-to-use CWCheat codes.
"""

import struct
import sys

try:
    import zstd
    def decompress_zstd(data):
        return zstd.decompress(data)
except ImportError:
    import zstandard
    def decompress_zstd(data):
        dctx = zstandard.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=256 * 1024 * 1024)

# ─── Configuration ───────────────────────────────────────────────────────────

SAVE_STATES = [
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_6.ppst",
    "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst",
]
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_BASE = 0x08000000
CWCHEAT_BASE = 0x08800000

# EBOOT typically loads at 0x08804000 for PSP games
# The ~PSP header showed seg1 addr = 0x08804000
EBOOT_LOAD_ADDR = 0x08804000
# Rough end of EBOOT code (before data/BSS). We'll refine this.
EBOOT_CODE_END = 0x08A00000

# Known stub addresses from previous analysis
STUB_sceDisplaySetFrameBuf = 0x08960D30
STUB_sceKernelDelayThread = None  # Will find dynamically
STUB_sceKernelGetSystemTimeLow = None

# ─── MIPS helpers ────────────────────────────────────────────────────────────

REG = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
       '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
       '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
       '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(w, addr):
    """Minimal MIPS disassembler."""
    op = (w >> 26) & 0x3F
    rs = (w >> 21) & 0x1F
    rt = (w >> 16) & 0x1F
    rd = (w >> 11) & 0x1F
    shamt = (w >> 6) & 0x1F
    funct = w & 0x3F
    imm = w & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    if w == 0: return "nop"
    if op == 0:
        names = {0x08:"jr", 0x09:"jalr", 0x21:"addu", 0x23:"subu", 0x25:"or",
                 0x24:"and", 0x26:"xor", 0x27:"nor", 0x2A:"slt", 0x2B:"sltu",
                 0x0A:"movz", 0x0B:"movn", 0x00:"sll", 0x02:"srl", 0x03:"sra",
                 0x18:"mult", 0x19:"multu", 0x1A:"div", 0x10:"mfhi", 0x12:"mflo"}
        if funct == 0x08: return f"jr {REG[rs]}"
        if funct == 0x09: return f"jalr {REG[rd]}, {REG[rs]}"
        if funct in (0x00, 0x02, 0x03):
            return f"{names[funct]} {REG[rd]}, {REG[rt]}, {shamt}"
        if funct in (0x18, 0x19, 0x1A):
            return f"{names[funct]} {REG[rs]}, {REG[rt]}"
        if funct in (0x10, 0x12):
            return f"{names[funct]} {REG[rd]}"
        if funct in names:
            return f"{names[funct]} {REG[rd]}, {REG[rs]}, {REG[rt]}"
        return f"R:0x{funct:02X} {REG[rd]},{REG[rs]},{REG[rt]}"
    if op == 0x02:
        t = ((addr + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
        return f"j 0x{t:08X}"
    if op == 0x03:
        t = ((addr + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
        return f"jal 0x{t:08X}"
    btarget = addr + 4 + (simm << 2)
    if op == 0x04: return f"beq {REG[rs]}, {REG[rt]}, 0x{btarget:08X}"
    if op == 0x05: return f"bne {REG[rs]}, {REG[rt]}, 0x{btarget:08X}"
    if op == 0x06: return f"blez {REG[rs]}, 0x{btarget:08X}"
    if op == 0x07: return f"bgtz {REG[rs]}, 0x{btarget:08X}"
    if op == 0x01:
        bnames = {0:"bltz", 1:"bgez", 0x10:"bltzal", 0x11:"bgezal"}
        return f"{bnames.get(rt,'regimm')} {REG[rs]}, 0x{btarget:08X}"
    if op == 0x09: return f"addiu {REG[rt]}, {REG[rs]}, {simm}"
    if op == 0x0A: return f"slti {REG[rt]}, {REG[rs]}, {simm}"
    if op == 0x0B: return f"sltiu {REG[rt]}, {REG[rs]}, {simm}"
    if op == 0x0C: return f"andi {REG[rt]}, {REG[rs]}, 0x{imm:04X}"
    if op == 0x0D: return f"ori {REG[rt]}, {REG[rs]}, 0x{imm:04X}"
    if op == 0x0E: return f"xori {REG[rt]}, {REG[rs]}, 0x{imm:04X}"
    if op == 0x0F: return f"lui {REG[rt]}, 0x{imm:04X}"
    if op == 0x20: return f"lb {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x21: return f"lh {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x23: return f"lw {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x24: return f"lbu {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x25: return f"lhu {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x28: return f"sb {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x29: return f"sh {REG[rt]}, {simm}({REG[rs]})"
    if op == 0x2B: return f"sw {REG[rt]}, {simm}({REG[rs]})"
    return f"??? op=0x{op:02X} raw=0x{w:08X}"

def psp_off(addr):
    """PSP address to file offset in decompressed save state."""
    return (addr - PSP_BASE) + MEM_OFFSET

def read32(data, addr):
    off = psp_off(addr)
    if 0 <= off <= len(data) - 4:
        return struct.unpack_from("<I", data, off)[0]
    return None

def cw_offset(addr):
    return addr - CWCHEAT_BASE

def disasm_range(data, start_addr, count, highlight=None):
    """Disassemble a range, return list of formatted lines."""
    lines = []
    for i in range(count):
        a = start_addr + i * 4
        w = read32(data, a)
        if w is None:
            lines.append(f"  0x{a:08X}: (out of bounds)")
            continue
        cw = cw_offset(a)
        marker = " >>>" if highlight and a in highlight else "    "
        lines.append(f"{marker} 0x{a:08X} [CW:0x{cw:07X}]: {w:08X}  {disasm(w, a)}")
    return lines

def find_jal_to(data, target, start=0x08800000, end=0x09800000):
    """Find all JAL instructions targeting a given address."""
    field = (target >> 2) & 0x03FFFFFF
    jal = (0x03 << 26) | field
    results = []
    for a in range(start, end, 4):
        w = read32(data, a)
        if w == jal:
            results.append(a)
    return results

def find_function_start(data, addr):
    """Walk backwards from addr to find the function prologue (addiu $sp, $sp, -N)."""
    for a in range(addr, addr - 0x400, -4):
        w = read32(data, a)
        if w is None:
            break
        # addiu $sp, $sp, -N  (op=0x09, rs=29, rt=29, negative imm)
        if (w & 0xFFFF0000) == 0x27BD0000:
            simm = w & 0xFFFF
            if simm >= 0x8000:  # negative immediate
                return a
    return None


# ─── Main analysis ───────────────────────────────────────────────────────────

def main():
    # Load save state
    save_state = None
    for path in SAVE_STATES:
        try:
            with open(path, "rb") as f:
                raw = f.read()
            save_state = path
            break
        except FileNotFoundError:
            continue

    if save_state is None:
        print("ERROR: No save state found!")
        sys.exit(1)

    print(f"Using save state: {save_state}")
    print(f"Raw size: {len(raw)} bytes")

    data = decompress_zstd(raw[HEADER_SIZE:])
    print(f"Decompressed: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 1: Verify the ELF in memory
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 1: VERIFY EBOOT IN MEMORY")
    print("=" * 80)

    # Check if there's an ELF header at 0x08804000 or nearby
    for test_addr in [0x08804000, 0x08800000, 0x08800100, 0x08804100]:
        magic = read32(data, test_addr)
        if magic is not None:
            b = struct.pack("<I", magic)
            if b[:4] == b'\x7fELF':
                print(f"  ELF header found at 0x{test_addr:08X}!")
            else:
                # The EBOOT code might start directly without ELF header in memory
                d = disasm(magic, test_addr)
                print(f"  0x{test_addr:08X}: {magic:08X}  {d}")

    # The ~PSP header told us load addr = 0x08804000, entry = 0x088214C8
    entry = 0x088214C8
    print(f"\n  Entry point from ~PSP header: 0x{entry:08X}")
    w = read32(data, entry)
    if w is not None:
        print(f"  Instruction at entry: {w:08X}  {disasm(w, entry)}")

    # Find approximate code end by scanning for large zero regions
    print("\n  Scanning for EBOOT code boundaries...")
    code_start = 0x08804000
    code_end = code_start
    zero_run = 0
    for a in range(code_start, 0x09800000, 4):
        w = read32(data, a)
        if w == 0:
            zero_run += 1
            if zero_run > 64:  # 256 bytes of zeros = likely past code
                code_end = a - zero_run * 4
                break
        else:
            if zero_run < 64:
                code_end = a
            zero_run = 0
    if code_end == code_start:
        code_end = 0x09700000
    print(f"  EBOOT code region: 0x{code_start:08X} - 0x{code_end:08X}")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 2: Find the frame timing constant 16666 (0x411A)
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 2: SEARCH FOR FRAME TIMING CONSTANT 16666us (0x411A)")
    print("=" * 80)

    # Search for: addiu $reg, $zero, 0x411A  (li $reg, 16666)
    # Encoding: 0x2400411A | (rt << 16)   where rs=0 ($zero)
    # Also: addiu $reg, $reg, 0x411A (less likely but possible)
    # Also: ori $reg, $zero, 0x411A

    matches_16666 = []
    for a in range(0x08800000, 0x09800000, 4):
        w = read32(data, a)
        if w is None:
            continue
        imm = w & 0xFFFF
        op = (w >> 26) & 0x3F
        rs = (w >> 21) & 0x1F

        if imm == 0x411A:
            if op == 0x09:  # addiu
                matches_16666.append((a, w, "addiu"))
            elif op == 0x0D:  # ori
                matches_16666.append((a, w, "ori"))

    print(f"  Found {len(matches_16666)} instruction(s) loading 16666")
    for addr, w, kind in matches_16666:
        region = "STATIC" if addr < 0x09000000 else "DYNAMIC"
        cw = cw_offset(addr)
        rt = (w >> 16) & 0x1F
        rs_val = (w >> 21) & 0x1F
        print(f"\n  [{region}] 0x{addr:08X} [CW:0x{cw:07X}]: {w:08X}")
        print(f"    {kind} {REG[rt]}, {REG[rs_val]}, 16666")

        # Find function start
        func = find_function_start(data, addr)
        if func:
            print(f"    Function starts at: 0x{func:08X}")

        # Disassemble context
        print("    Context:")
        for line in disasm_range(data, addr - 32, 24, highlight={addr}):
            print(f"    {line}")
    print()

    # Also search for 16666 as a 32-bit data value
    print("  Also searching for 16666 as raw data word...")
    data_matches = []
    for a in range(0x08800000, 0x09800000, 4):
        w = read32(data, a)
        if w == 16666:
            data_matches.append(a)
    print(f"  Found {len(data_matches)} raw data matches")
    for addr in data_matches[:10]:
        cw = cw_offset(addr)
        region = "STATIC" if addr < 0x09000000 else "DYNAMIC"
        print(f"    [{region}] 0x{addr:08X} [CW:0x{cw:07X}] = 16666 (0x{16666:08X})")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 3: Find frame counter check (slti with imm=2)
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 3: SEARCH FOR FRAME COUNTER CHECK (slti $reg, $reg, 2)")
    print("=" * 80)

    matches_slti2 = []
    for a in range(0x08800000, 0x09800000, 4):
        w = read32(data, a)
        if w is None:
            continue
        # slti: op = 0x0A, imm = 2
        if (w & 0xFC000000) == 0x28000000 and (w & 0xFFFF) == 0x0002:
            matches_slti2.append((a, w))

    print(f"  Found {len(matches_slti2)} slti $x, $x, 2 instructions")
    for addr, w in matches_slti2:
        region = "STATIC" if addr < 0x09000000 else "DYNAMIC"
        cw = cw_offset(addr)
        rt = (w >> 16) & 0x1F
        rs_val = (w >> 21) & 0x1F
        print(f"\n  [{region}] 0x{addr:08X} [CW:0x{cw:07X}]: {w:08X}")
        print(f"    slti {REG[rt]}, {REG[rs_val]}, 2")
        print("    Context:")
        for line in disasm_range(data, addr - 20, 16, highlight={addr}):
            print(f"    {line}")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 4: Cross-reference — find 16666 and slti-2 near each other
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 4: CROSS-REFERENCE — 16666 + slti-2 WITHIN 128 BYTES")
    print("=" * 80)

    addrs_16666 = set(a for a, _, _ in matches_16666)
    addrs_slti2 = set(a for a, _ in matches_slti2)

    pairs = []
    for a16 in addrs_16666:
        for a_s in addrs_slti2:
            if abs(a16 - a_s) <= 128:
                pairs.append((a16, a_s))

    if pairs:
        print(f"  Found {len(pairs)} nearby pair(s)!")
        for a16, a_s in pairs:
            start = min(a16, a_s) - 32
            end = max(a16, a_s) + 32
            count = (end - start) // 4
            print(f"\n  16666 at 0x{a16:08X}, slti at 0x{a_s:08X}:")
            for line in disasm_range(data, start, count, highlight={a16, a_s}):
                print(f"  {line}")
    else:
        print("  No nearby pairs found.")
        print("  Expanding search to 512 bytes...")
        for a16 in addrs_16666:
            for a_s in addrs_slti2:
                if abs(a16 - a_s) <= 512:
                    pairs.append((a16, a_s))
        if pairs:
            print(f"  Found {len(pairs)} pair(s) within 512 bytes!")
            for a16, a_s in pairs:
                print(f"    16666 at 0x{a16:08X}, slti at 0x{a_s:08X}, distance={abs(a16-a_s)} bytes")
        else:
            print("  Still no pairs found within 512 bytes.")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 5: Find sceDisplaySetFrameBuf sync parameter
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 5: sceDisplaySetFrameBuf CALLS (sync=1 -> sync=0 for speed)")
    print("=" * 80)

    # Find import stubs by searching for NID 0x289D82FE
    nid_matches = []
    for a in range(0x08960000, 0x08970000, 4):
        w = read32(data, a)
        if w == 0x289D82FE:
            nid_matches.append(a)

    if nid_matches:
        print(f"  sceDisplaySetFrameBuf NID found at: {['0x%08X' % x for x in nid_matches]}")

    # Use known stub address
    stub = STUB_sceDisplaySetFrameBuf
    print(f"  Using stub address: 0x{stub:08X}")
    callers = find_jal_to(data, stub)
    print(f"  Found {len(callers)} JAL call sites")

    for caller in callers:
        cw = cw_offset(caller)
        print(f"\n  Call at 0x{caller:08X} [CW:0x{cw:07X}]:")
        # Look backwards for $a3 setup (sync parameter)
        # sceDisplaySetFrameBuf(void *topaddr, int bufferwidth, int pixelformat, int sync)
        # sync is $a3
        func = find_function_start(data, caller)
        start_look = max(caller - 64, func if func else caller - 64)
        print("    Context (looking for $a3 = sync parameter):")
        a3_setup = None
        for a in range(start_look, caller + 8, 4):
            w = read32(data, a)
            if w is None:
                continue
            d = disasm(w, a)
            # Check if this sets $a3
            op = (w >> 26) & 0x3F
            rt = (w >> 16) & 0x1F
            rd = (w >> 11) & 0x1F
            if op == 0x09 and rt == 7:  # addiu $a3, ...
                a3_setup = a
            elif op == 0 and rd == 7:   # R-type with rd=$a3
                a3_setup = a

        for line in disasm_range(data, start_look, (caller - start_look + 32) // 4, highlight={caller}):
            print(f"    {line}")

        if a3_setup:
            w_a3 = read32(data, a3_setup)
            cw_a3 = cw_offset(a3_setup)
            print(f"\n    $a3 (sync) set at 0x{a3_setup:08X} [CW:0x{cw_a3:07X}]: {w_a3:08X}")
            print(f"    To disable vsync: change to sync=0")
            # Generate the patch
            patched = (w_a3 & 0xFFFF0000) | 0x0000  # Set immediate to 0
            if (w_a3 >> 26) & 0x3F == 0x09:  # addiu
                patched = (w_a3 & 0xFFFF0000)  # addiu $a3, $x, 0
            print(f"    CWCheat: _L 0x2{cw_a3:07X} 0x{patched:08X}")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 6: Deep analysis of 0x088E6900 region (known frame timing func)
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 6: DEEP ANALYSIS OF FRAME TIMING FUNCTION (0x088E68xx region)")
    print("=" * 80)

    # From previous analysis, 0x088E6900 area has a counter+16666us pattern
    func_start = find_function_start(data, 0x088E6900)
    if func_start:
        print(f"  Function start: 0x{func_start:08X}")
        print("  Full disassembly:")
        for line in disasm_range(data, func_start, 80):
            print(f"  {line}")
    else:
        print("  Could not find function start, dumping area:")
        for line in disasm_range(data, 0x088E6800, 80):
            print(f"  {line}")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 7: Search for sceKernelDelayThread calls with timing args
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 7: sceKernelDelayThread IMPORT STUBS AND CALLS")
    print("=" * 80)

    # Find sceKernelDelayThread NID (0xCEADEB47) to get its stub
    delay_nid = 0xCEADEB47
    delaycb_nid = 0x68DA9E36
    for nid_val, nid_name in [(delay_nid, "sceKernelDelayThread"),
                               (delaycb_nid, "sceKernelDelayThreadCB")]:
        print(f"\n  Searching for {nid_name} NID (0x{nid_val:08X})...")
        for a in range(0x08960000, 0x08970000, 4):
            w = read32(data, a)
            if w == nid_val:
                print(f"    NID found at 0x{a:08X}")
                # The stub table is parallel to the NID table.
                # We need to find the import header to know the mapping.
                # From previous analysis, stubs are 8 bytes each (j target; nop)
                # Let's just search for all JAL instructions in the stub region
                # that jump to HLE addresses

    # Find stubs by looking at the known stub table region
    # Previous analysis showed stubs around 0x08960D00-0x08961000
    print("\n  Import stubs in 0x08960C00-0x08961400:")
    timing_stubs = {}
    for a in range(0x08960C00, 0x08961400, 8):
        w = read32(data, a)
        if w is None:
            continue
        op = (w >> 26) & 0x3F
        if op == 0x02:  # J instruction (jump to HLE handler)
            target = ((a + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            # Read the NID for this stub by finding which NID table entry maps here
            # For now, just identify the stubs and we'll manually check
            nop = read32(data, a + 4)
            if nop == 0:  # followed by NOP = likely a stub
                pass  # Will identify below

    # More targeted: find the import table headers
    # Search for sceKernelDelayThread by finding its stub through NID table
    # The NID table entry for sceKernelDelayThread at the known offset
    # Let's find all import lib headers
    print("\n  Scanning import table headers...")
    import_libs = {}
    for a in range(0x08960000, 0x08962000, 4):
        w = read32(data, a)
        if w is None:
            continue
        # Library name pointer — check if it points to a readable string
        if 0x08960000 <= w < 0x08970000:
            name_off = psp_off(w)
            if 0 <= name_off < len(data) - 4:
                # Try to read as string
                name = b""
                for i in range(64):
                    if name_off + i >= len(data):
                        break
                    b = data[name_off + i]
                    if b == 0:
                        break
                    if 32 <= b <= 126:
                        name += bytes([b])
                    else:
                        name = b""
                        break
                if len(name) > 3 and name.startswith(b"sce"):
                    name_str = name.decode("ascii")
                    # Read the import header
                    entry_size = data[psp_off(a) + 8] if psp_off(a) + 8 < len(data) else 0
                    num_vars = data[psp_off(a) + 9] if psp_off(a) + 9 < len(data) else 0
                    num_funcs = struct.unpack_from("<H", data, psp_off(a) + 10)[0] if psp_off(a) + 12 <= len(data) else 0
                    nid_ptr = read32(data, a + 12)
                    stub_ptr = read32(data, a + 16)

                    if name_str not in import_libs and num_funcs > 0 and num_funcs < 200:
                        import_libs[name_str] = (a, entry_size, num_vars, num_funcs, nid_ptr, stub_ptr)
                        print(f"    {name_str}: header=0x{a:08X}, funcs={num_funcs}, nid_tbl=0x{nid_ptr:08X}, stub_tbl=0x{stub_ptr:08X}")

    # Now resolve the timing-related stubs
    timing_funcs = {
        0xCEADEB47: "sceKernelDelayThread",
        0x68DA9E36: "sceKernelDelayThreadCB",
        0x82BC5777: "sceKernelGetSystemTimeWide",
        0x369ED59D: "sceKernelGetSystemTimeLow",
        0x289D82FE: "sceDisplaySetFrameBuf",
        0x984C27E7: "sceDisplayWaitVblankStart",
    }

    resolved_stubs = {}
    for lib_name, (hdr_addr, esz, nvars, nfuncs, nid_ptr, stub_ptr) in import_libs.items():
        if not (0x08800000 <= nid_ptr < 0x09800000 and 0x08800000 <= stub_ptr < 0x09800000):
            continue
        for i in range(nfuncs):
            nid = read32(data, nid_ptr + i * 4)
            stub_addr = stub_ptr + i * 8
            if nid in timing_funcs:
                resolved_stubs[timing_funcs[nid]] = stub_addr
                print(f"    RESOLVED: {timing_funcs[nid]} -> stub at 0x{stub_addr:08X}")

    # Find callers of sceKernelDelayThread
    for func_name in ["sceKernelDelayThread", "sceKernelDelayThreadCB"]:
        if func_name not in resolved_stubs:
            continue
        stub = resolved_stubs[func_name]
        callers = find_jal_to(data, stub)
        print(f"\n  {func_name} (stub 0x{stub:08X}): {len(callers)} callers")
        for caller in callers:
            cw = cw_offset(caller)
            print(f"\n    Caller at 0x{caller:08X} [CW:0x{cw:07X}]:")
            # Look for $a0 setup (delay in microseconds)
            for line in disasm_range(data, caller - 40, 20, highlight={caller}):
                print(f"    {line}")
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 8: Search for 33333 (0x8235) as data — MHP3 uses 30fps
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 8: SEARCH FOR 33333us (0x8235) — MHP3rd IS 30fps")
    print("=" * 80)

    # MHP3rd runs at 30fps, not 60fps! So the timing constant might be 33333us
    matches_33333 = []
    for a in range(0x08800000, 0x09800000, 4):
        w = read32(data, a)
        if w is None:
            continue
        imm = w & 0xFFFF
        op = (w >> 26) & 0x3F
        # 33333 = 0x8235, but as a signed 16-bit this is negative (-32203)
        # So it can't be loaded with a single addiu from $zero.
        # It would need lui+ori: lui $reg, 0x0000; ori $reg, $reg, 0x8235
        # or: ori $reg, $zero, 0x8235
        if imm == 0x8235 and op in (0x0D, 0x0E):  # ori, xori
            matches_33333.append((a, w, "ori/xori"))
        elif imm == 0x8235 and op == 0x09:  # addiu (would give -32203)
            matches_33333.append((a, w, "addiu(negative!)"))

    # Also search for 33333 as raw 32-bit data
    data_33333 = []
    for a in range(0x08800000, 0x09800000, 4):
        w = read32(data, a)
        if w == 33333:
            data_33333.append(a)

    print(f"  Instruction matches for 0x8235 imm: {len(matches_33333)}")
    for addr, w, kind in matches_33333:
        region = "STATIC" if addr < 0x09000000 else "DYNAMIC"
        cw = cw_offset(addr)
        print(f"    [{region}] 0x{addr:08X} [CW:0x{cw:07X}]: {w:08X}  {kind}")
        for line in disasm_range(data, addr - 16, 12, highlight={addr}):
            print(f"      {line}")

    print(f"\n  Raw data value 33333: {len(data_33333)} matches")
    for addr in data_33333[:20]:
        region = "STATIC" if addr < 0x09000000 else "DYNAMIC"
        cw = cw_offset(addr)
        print(f"    [{region}] 0x{addr:08X} [CW:0x{cw:07X}] = 33333")
        # Check if this is referenced by nearby code
        # Look for lui+lw pattern that could reference this address
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 9: Alternative — NOP the delay call entirely
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 9: GENERATE CWCHEAT CODES")
    print("=" * 80)

    codes = []

    # Code 1: Disable vsync on sceDisplaySetFrameBuf
    for caller in callers if 'callers' in dir() else []:
        pass  # Already handled in step 5

    # Regenerate sync=0 patches for all sceDisplaySetFrameBuf calls
    if STUB_sceDisplaySetFrameBuf:
        fb_callers = find_jal_to(data, STUB_sceDisplaySetFrameBuf)
        for caller in fb_callers:
            # Walk back to find $a3 setup
            for a in range(caller - 64, caller, 4):
                w = read32(data, a)
                if w is None:
                    continue
                op = (w >> 26) & 0x3F
                rt = (w >> 16) & 0x1F
                if op == 0x09 and rt == 7:  # addiu $a3
                    imm = w & 0xFFFF
                    if imm == 1:  # sync=1
                        cw = cw_offset(a)
                        patched = w & 0xFFFF0000  # sync=0
                        codes.append((
                            f"Disable vsync at 0x{a:08X} (sceDisplaySetFrameBuf sync=0)",
                            f"_L 0x2{cw:07X} 0x{patched:08X}",
                            a, w, patched
                        ))
                    break
                # Also check: or $a3, $zero, $reg  or  move $a3, $reg
                if op == 0 and ((w >> 11) & 0x1F) == 7:
                    funct = w & 0x3F
                    if funct == 0x25:  # or $a3, ...
                        # Harder to patch, note it
                        pass

    # Code 2: Patch frame timing — change 16666 to smaller values
    for addr, w, kind in matches_16666:
        if addr < 0x09000000:  # Only static addresses work with CWCheat
            cw = cw_offset(addr)
            rt = (w >> 16) & 0x1F
            rs_val = (w >> 21) & 0x1F
            # 2x speed: 16666 -> 8333 (0x208D)
            patched_2x = (w & 0xFFFF0000) | 0x208D
            # 3x speed: 16666 -> 5555 (0x15B3)
            patched_3x = (w & 0xFFFF0000) | 0x15B3
            # Max speed: 16666 -> 1 (nearly instant)
            patched_max = (w & 0xFFFF0000) | 0x0001
            codes.append((
                f"2x speed (16666->8333) at 0x{addr:08X}",
                f"_L 0x2{cw:07X} 0x{patched_2x:08X}",
                addr, w, patched_2x
            ))
            codes.append((
                f"3x speed (16666->5555) at 0x{addr:08X}",
                f"_L 0x2{cw:07X} 0x{patched_3x:08X}",
                addr, w, patched_3x
            ))
            codes.append((
                f"Max speed (16666->1) at 0x{addr:08X}",
                f"_L 0x2{cw:07X} 0x{patched_max:08X}",
                addr, w, patched_max
            ))

    # Code 3: Patch slti counter check — skip frames
    for addr, w in matches_slti2:
        if addr < 0x09000000:
            cw = cw_offset(addr)
            # Change "slti $x, $x, 2" to "slti $x, $x, 1" = always process
            patched = (w & 0xFFFF0000) | 0x0001
            codes.append((
                f"Frame skip: slti imm 2->1 at 0x{addr:08X}",
                f"_L 0x2{cw:07X} 0x{patched:08X}",
                addr, w, patched
            ))

    # Code 4: NOP sceKernelDelayThread calls
    for func_name in ["sceKernelDelayThread", "sceKernelDelayThreadCB"]:
        if func_name in resolved_stubs:
            stub = resolved_stubs[func_name]
            callers = find_jal_to(data, stub)
            for caller in callers:
                if caller < 0x09000000:
                    cw = cw_offset(caller)
                    codes.append((
                        f"NOP {func_name} call at 0x{caller:08X}",
                        f"_L 0x2{cw:07X} 0x00000000",
                        caller, read32(data, caller), 0
                    ))

    # Code 5: Patch 33333 data values (if 30fps timing)
    for addr in data_33333:
        if addr < 0x09000000:
            cw = cw_offset(addr)
            codes.append((
                f"2x speed (33333->16666 data) at 0x{addr:08X}",
                f"_L 0x2{cw:07X} 0x0000411A",
                addr, 33333, 0x0000411A
            ))

    print(f"\n  Generated {len(codes)} CWCheat code(s):\n")
    print("  _S ULJM-05800")
    print("  _G Monster Hunter Portable 3rd")
    print()

    # Group by category
    prev_cat = ""
    for desc, code, addr, orig, patched in codes:
        cat = desc.split("(")[0].strip() if "(" in desc else desc.split(" at ")[0].strip()
        if cat != prev_cat:
            print(f"  _C0 {cat}")
            prev_cat = cat
        print(f"  {code}")
        print(f"  // {desc}")
        print(f"  // Original: 0x{orig:08X} -> Patched: 0x{patched:08X}")
        print()

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 10: Verify addresses are in static EBOOT region
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("STEP 10: ADDRESS STABILITY CHECK")
    print("=" * 80)
    print("""
  CWCheat codes only work reliably for STATIC addresses (within the EBOOT
  code/data region, typically 0x08804000-0x0896xxxx).

  Addresses in the 0x09xxxxxx range are from dynamically loaded PRX modules
  and may shift between game boots. These CANNOT be used with CWCheat.

  For the EBOOT region: since the EBOOT is encrypted (~PSP format), PPSSPP
  decrypts it at load time and places it at the same base address every time.
  So addresses in 0x088xxxxx-0x0896xxxx should be stable.
""")

    for desc, code, addr, orig, patched in codes:
        if addr >= 0x09000000:
            print(f"  WARNING: 0x{addr:08X} is in dynamic region! {desc}")
        else:
            print(f"  OK:      0x{addr:08X} is in static region. {desc}")

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 11: Write ready-to-use cheat file
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("STEP 11: READY-TO-USE INI CONTENT")
    print("=" * 80)

    # Collect only static codes
    static_codes = [(d, c, a, o, p) for d, c, a, o, p in codes if a < 0x09000000]

    if static_codes:
        print("\n  Copy the following into your ULJM05800.ini:\n")
        print("  _S ULJM-05800")
        print("  _G Monster Hunter Portable 3rd")

        # Vsync disable
        vsync_codes = [c for d, c, a, o, p in static_codes if "vsync" in d.lower()]
        if vsync_codes:
            print("  _C0 Disable Vsync (Faster Rendering)")
            for c in vsync_codes:
                print(f"  {c}")

        # Speed 2x
        speed2_codes = [c for d, c, a, o, p in static_codes if "2x" in d]
        if speed2_codes:
            print("  _C0 2x Game Speed")
            for c in speed2_codes:
                print(f"  {c}")

        # Speed 3x
        speed3_codes = [c for d, c, a, o, p in static_codes if "3x" in d]
        if speed3_codes:
            print("  _C0 3x Game Speed")
            for c in speed3_codes:
                print(f"  {c}")

        # Max speed
        max_codes = [c for d, c, a, o, p in static_codes if "Max" in d]
        if max_codes:
            print("  _C0 Max Game Speed")
            for c in max_codes:
                print(f"  {c}")

        # Frame skip
        skip_codes = [c for d, c, a, o, p in static_codes if "skip" in d.lower()]
        if skip_codes:
            print("  _C0 Frame Skip (Counter Check)")
            for c in skip_codes:
                print(f"  {c}")

        # NOP delays
        nop_codes = [c for d, c, a, o, p in static_codes if "NOP" in d]
        if nop_codes:
            print("  _C0 Remove Delay Calls")
            for c in nop_codes:
                print(f"  {c}")
    else:
        print("\n  WARNING: No static-region codes found!")
        print("  All timing code may be in dynamically loaded PRX modules.")
        print("  This means CWCheat cannot patch them.")
        print("  Alternative: Use PPSSPP's built-in speed toggle (Tab key by default)")

    print()
    print("Done!")


if __name__ == "__main__":
    main()
