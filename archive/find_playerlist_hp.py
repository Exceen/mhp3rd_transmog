#!/usr/bin/env python3
"""Find what renders player list HP bars in MHP3rd.

Disassembles the player list name function 0x09D6380C and surrounding area,
plus the parent function 0x09D6C498, to find all jal/jalr targets that may
render HP bars."""

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

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_s16(data, off):
    return struct.unpack_from('<h', data, off)[0]

def psp_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

REGS = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3',
        '$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
        '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7',
        '$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']

def disasm(instr, addr):
    """Basic MIPS disassembler covering common instructions."""
    op = instr >> 26
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    rd = (instr >> 11) & 0x1F
    sa = (instr >> 6) & 0x1F
    func = instr & 0x3F
    imm = instr & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    if instr == 0:
        return "nop"

    # R-type (op == 0)
    if op == 0:
        if func == 0x08:
            return f"jr {REGS[rs]}"
        if func == 0x09:
            return f"jalr {REGS[rd]}, {REGS[rs]}"
        if func == 0x21:
            if rs == 0:
                return f"move {REGS[rd]}, {REGS[rt]}"
            return f"addu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x23:
            return f"subu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x00:
            return f"sll {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x02:
            return f"srl {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x03:
            return f"sra {REGS[rd]}, {REGS[rt]}, {sa}"
        if func == 0x04:
            return f"sllv {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
        if func == 0x06:
            return f"srlv {REGS[rd]}, {REGS[rt]}, {REGS[rs]}"
        if func == 0x24:
            return f"and {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x25:
            return f"or {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x26:
            return f"xor {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x27:
            return f"nor {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2A:
            return f"slt {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x2B:
            return f"sltu {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        if func == 0x18:
            return f"mult {REGS[rs]}, {REGS[rt]}"
        if func == 0x19:
            return f"multu {REGS[rs]}, {REGS[rt]}"
        if func == 0x10:
            return f"mfhi {REGS[rd]}"
        if func == 0x12:
            return f"mflo {REGS[rd]}"
        if func == 0x20:
            return f"add {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"R-type func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"

    # J-type
    if op == 2:
        target = (addr & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
        return f"j 0x{target:08X}"
    if op == 3:
        target = (addr & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
        return f"jal 0x{target:08X}"

    # I-type
    if op == 0x04:
        target = addr + 4 + (simm << 2)
        return f"beq {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x05:
        target = addr + 4 + (simm << 2)
        return f"bne {REGS[rs]}, {REGS[rt]}, 0x{target:08X}"
    if op == 0x06:
        target = addr + 4 + (simm << 2)
        return f"blez {REGS[rs]}, 0x{target:08X}"
    if op == 0x07:
        target = addr + 4 + (simm << 2)
        return f"bgtz {REGS[rs]}, 0x{target:08X}"
    if op == 0x01:
        target = addr + 4 + (simm << 2)
        if rt == 0:
            return f"bltz {REGS[rs]}, 0x{target:08X}"
        if rt == 1:
            return f"bgez {REGS[rs]}, 0x{target:08X}"
        if rt == 0x11:
            return f"bgezal {REGS[rs]}, 0x{target:08X}"
        return f"REGIMM rt={rt} {REGS[rs]}, 0x{target:08X}"

    if op == 0x09:
        if rs == 0:
            return f"li {REGS[rt]}, 0x{imm:04X}"
        return f"addiu {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x08:
        return f"addi {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0F:
        return f"lui {REGS[rt]}, 0x{imm:04X}"
    if op == 0x0C:
        return f"andi {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0D:
        return f"ori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0E:
        return f"xori {REGS[rt]}, {REGS[rs]}, 0x{imm:04X}"
    if op == 0x0A:
        return f"slti {REGS[rt]}, {REGS[rs]}, {simm}"
    if op == 0x0B:
        return f"sltiu {REGS[rt]}, {REGS[rs]}, {simm}"

    # Load/Store
    if op == 0x23:
        return f"lw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x2B:
        return f"sw {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x25:
        return f"lhu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x29:
        return f"sh {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x24:
        return f"lbu {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x28:
        return f"sb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x20:
        return f"lb {REGS[rt]}, {simm}({REGS[rs]})"
    if op == 0x21:
        return f"lh {REGS[rt]}, {simm}({REGS[rs]})"

    # FPU
    if op == 0x31:
        return f"lwc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x39:
        return f"swc1 $f{rt}, {simm}({REGS[rs]})"
    if op == 0x11:
        # COP1
        if rs == 0x10:  # S format
            if func == 0x00:
                return f"add.s $f{rd>>0&0x1f}, $f{(instr>>11)&0x1f}, $f{rt}"
            if func == 0x06:
                return f"mov.s $f{(instr>>6)&0x1f}, $f{(instr>>11)&0x1f}"
        if rs == 0x04:
            return f"mtc1 {REGS[rt]}, $f{rd}"
        if rs == 0x00:
            return f"mfc1 {REGS[rt]}, $f{rd}"
        return f"COP1 rs={rs} rt={rt} rd={rd} func=0x{func:02X}"

    # SPECIAL2 (op=0x1C) - multiply-add etc
    if op == 0x1C:
        if func == 0x02:
            return f"mul {REGS[rd]}, {REGS[rs]}, {REGS[rt]}"
        return f"SPECIAL2 func=0x{func:02X} {REGS[rd]},{REGS[rs]},{REGS[rt]}"

    return f"??? op=0x{op:02X} raw=0x{instr:08X}"


def disasm_range(data, start_addr, end_addr, label=None):
    """Disassemble a range of addresses and return lines + jal targets."""
    lines = []
    jal_targets = []
    jalr_locs = []

    if label:
        lines.append(f"\n{'='*70}")
        lines.append(f"  {label}")
        lines.append(f"  0x{start_addr:08X} - 0x{end_addr:08X}")
        lines.append(f"{'='*70}")

    addr = start_addr
    while addr < end_addr:
        off = psp_to_offset(addr)
        if off < 0 or off + 4 > len(data):
            lines.append(f"  0x{addr:08X}: <out of bounds>")
            addr += 4
            continue
        instr = read_u32(data, off)
        d = disasm(instr, addr)
        marker = ""

        op = instr >> 26
        func = instr & 0x3F

        if op == 3:  # jal
            target = (addr & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
            jal_targets.append((addr, target))
            marker = "  <--- JAL"
        elif op == 0 and func == 0x09:  # jalr
            rs = (instr >> 21) & 0x1F
            jalr_locs.append((addr, REGS[rs]))
            marker = "  <--- JALR"

        lines.append(f"  0x{addr:08X}: [{instr:08X}] {d}{marker}")
        addr += 4

    return lines, jal_targets, jalr_locs


def main():
    print("Loading and decompressing save state...")
    data = decompress_ppst(PPST_FILE)
    print(f"  Decompressed size: {len(data)} bytes (0x{len(data):X})")

    all_jal_targets = {}
    all_jalr_locs = []

    # ===== 1. Disassemble the player list name function 0x09D6380C =====
    print("\n" + "#"*70)
    print("# SECTION 1: Player list name function 0x09D6380C (~200 instrs)")
    print("#"*70)
    lines, jals, jalrs = disasm_range(data, 0x09D6380C, 0x09D6380C + 200*4,
                                       "Function 0x09D6380C (player list names/icons)")
    for l in lines:
        print(l)
    for addr, target in jals:
        all_jal_targets.setdefault(target, []).append(addr)
    all_jalr_locs.extend(jalrs)

    # ===== 2. Wider scan around 0x09D63800-0x09D64200 =====
    print("\n" + "#"*70)
    print("# SECTION 2: Wider area 0x09D63800 - 0x09D64200")
    print("#"*70)
    lines, jals, jalrs = disasm_range(data, 0x09D63800, 0x09D64200,
                                       "Wide scan 0x09D63800-0x09D64200")
    for l in lines:
        print(l)
    for addr, target in jals:
        all_jal_targets.setdefault(target, []).append(addr)
    all_jalr_locs.extend(jalrs)

    # ===== 3. Parent function 0x09D6C498 area =====
    print("\n" + "#"*70)
    print("# SECTION 3: Parent function 0x09D6C498 - 0x09D6CC00")
    print("#"*70)
    lines, jals, jalrs = disasm_range(data, 0x09D6C498, 0x09D6CC00,
                                       "Parent function 0x09D6C498 (rendering section)")
    for l in lines:
        print(l)
    for addr, target in jals:
        all_jal_targets.setdefault(target, []).append(addr)
    all_jalr_locs.extend(jalrs)

    # ===== 4. Summary: all JAL targets =====
    print("\n" + "#"*70)
    print("# SECTION 4: Summary of all JAL targets found")
    print("#"*70)
    print(f"\n  {'Target':>12s}  {'Type':>10s}  Called from")
    print(f"  {'-'*12}  {'-'*10}  {'-'*40}")
    for target in sorted(all_jal_targets.keys()):
        callers = all_jal_targets[target]
        if target < 0x09000000:
            ttype = "EBOOT"
        else:
            ttype = "OVERLAY"
        caller_strs = [f"0x{c:08X}" for c in sorted(callers)]
        # Deduplicate callers from overlapping sections
        caller_strs = sorted(set(caller_strs))
        print(f"  0x{target:08X}  {ttype:>10s}  {', '.join(caller_strs)}")

    print(f"\n  Total unique JAL targets: {len(all_jal_targets)}")

    # ===== 5. JALR locations =====
    if all_jalr_locs:
        # Deduplicate
        seen = set()
        unique_jalrs = []
        for addr, reg in all_jalr_locs:
            if addr not in seen:
                seen.add(addr)
                unique_jalrs.append((addr, reg))
        print(f"\n  JALR (indirect call) locations:")
        for addr, reg in sorted(unique_jalrs):
            print(f"    0x{addr:08X}: jalr {reg}")

    # ===== 6. Look for functions near the name function that might render bars =====
    print("\n" + "#"*70)
    print("# SECTION 5: Functions called from 0x09D6380C that might render bars")
    print("#"*70)
    print("\n  Checking each JAL target from the name function area for clues...")

    # Get jal targets specifically from the name function
    name_func_jals = {}
    addr = 0x09D6380C
    end = 0x09D6380C + 200*4
    while addr < end:
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        op = instr >> 26
        if op == 3:
            target = (addr & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
            name_func_jals.setdefault(target, []).append(addr)
        addr += 4

    for target in sorted(name_func_jals.keys()):
        callers = name_func_jals[target]
        ttype = "EBOOT" if target < 0x09000000 else "OVERLAY"
        print(f"\n  Target 0x{target:08X} ({ttype}), called from {[f'0x{c:08X}' for c in callers]}")
        # Disassemble first 30 instructions of each target
        t_off = psp_to_offset(target)
        if t_off < 0 or t_off + 120 > len(data):
            print(f"    <out of bounds>")
            continue
        print(f"    First 30 instructions:")
        for i in range(30):
            a = target + i*4
            o = psp_to_offset(a)
            ins = read_u32(data, o)
            d = disasm(ins, a)
            extra = ""
            if (ins >> 26) == 3:
                tgt = (a & 0xF0000000) | ((ins & 0x03FFFFFF) << 2)
                extra = f"  <-- calls 0x{tgt:08X}"
            print(f"      0x{a:08X}: [{ins:08X}] {d}{extra}")

    # ===== 7. Check what's right after the name rendering code =====
    print("\n" + "#"*70)
    print("# SECTION 6: Code after name function - look for bar rendering")
    print("#" * 70)
    # Look for jr $ra to find end of name function, then what follows
    addr = 0x09D6380C
    func_ends = []
    while addr < 0x09D64200:
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        # jr $ra
        if instr == 0x03E00008:
            func_ends.append(addr)
        addr += 4

    print(f"\n  jr $ra found at: {[f'0x{a:08X}' for a in func_ends]}")
    print(f"\n  These mark function boundaries. Functions in 0x09D63800-0x09D64200:")
    # Identify function starts by looking for addiu $sp, $sp, -N after jr $ra delay slots
    func_starts = []
    addr = 0x09D63800
    while addr < 0x09D64200:
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        # addiu $sp, $sp, -N  (op=9, rs=29, rt=29, simm<0)
        op = instr >> 26
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        simm = (instr & 0xFFFF)
        if simm >= 0x8000:
            simm -= 0x10000
        if op == 0x09 and rs == 29 and rt == 29 and simm < 0:
            # Check if prev instruction is nop or delay slot
            func_starts.append((addr, simm))
        addr += 4

    print(f"  Function prologues (addiu $sp, $sp, -N):")
    for a, frame in func_starts:
        print(f"    0x{a:08X}: frame size = {-frame}")

    # ===== 8. Scan parent function for context around each jal =====
    print("\n" + "#"*70)
    print("# SECTION 7: Parent function JAL calls with context (3 instr before/after)")
    print("#"*70)
    addr = 0x09D6C498
    while addr < 0x09D6CC00:
        off = psp_to_offset(addr)
        instr = read_u32(data, off)
        op = instr >> 26
        if op == 3:
            target = (addr & 0xF0000000) | ((instr & 0x03FFFFFF) << 2)
            ttype = "EBOOT" if target < 0x09000000 else "OVERLAY"
            print(f"\n  JAL 0x{target:08X} ({ttype}) at 0x{addr:08X}:")
            # Show 3 instructions before and 2 after (including delay slot)
            for delta in range(-12, 12, 4):
                a = addr + delta
                o = psp_to_offset(a)
                if o >= 0 and o + 4 <= len(data):
                    ins = read_u32(data, o)
                    d = disasm(ins, a)
                    ptr = " >>>" if delta == 0 else "    "
                    print(f"    {ptr} 0x{a:08X}: [{ins:08X}] {d}")
        addr += 4


if __name__ == "__main__":
    main()
