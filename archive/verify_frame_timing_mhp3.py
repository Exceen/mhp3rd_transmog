#!/usr/bin/env python3
"""Verify frame timing code in MHP3rd (ULJM05800) save state."""

import struct
import zstd

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
CWCHEAT_BASE = 0x08800000

# MIPS register names
REG_NAMES = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
]

def disasm_simple(word, addr):
    """Simple MIPS disassembler for common instructions."""
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    shamt = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000

    if word == 0:
        return "nop"

    if op == 0:  # R-type
        if funct == 0x21:
            return f"addu {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x2B:
            return f"sltu {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x2A:
            return f"slt {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x0A:
            return f"movz {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x0B:
            return f"movn {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x25:
            return f"or {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x08:
            return f"jr {REG_NAMES[rs]}"
        elif funct == 0x09:
            return f"jalr {REG_NAMES[rd]}, {REG_NAMES[rs]}"
        elif funct == 0x00:
            return f"sll {REG_NAMES[rd]}, {REG_NAMES[rt]}, {shamt}"
        elif funct == 0x02:
            return f"srl {REG_NAMES[rd]}, {REG_NAMES[rt]}, {shamt}"
        elif funct == 0x03:
            return f"sra {REG_NAMES[rd]}, {REG_NAMES[rt]}, {shamt}"
        elif funct == 0x23:
            return f"subu {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x24:
            return f"and {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x26:
            return f"xor {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x27:
            return f"nor {REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x18:
            return f"mult {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x19:
            return f"multu {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x1A:
            return f"div {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif funct == 0x10:
            return f"mfhi {REG_NAMES[rd]}"
        elif funct == 0x12:
            return f"mflo {REG_NAMES[rd]}"
        return f"R-type funct=0x{funct:02X} {REG_NAMES[rd]},{REG_NAMES[rs]},{REG_NAMES[rt]}"
    elif op == 0x09:
        return f"addiu {REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm} (0x{imm:04X})"
    elif op == 0x0A:
        return f"slti {REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm}"
    elif op == 0x0B:
        return f"sltiu {REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm}"
    elif op == 0x0C:
        return f"andi {REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm:04X}"
    elif op == 0x0D:
        return f"ori {REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm:04X}"
    elif op == 0x0F:
        return f"lui {REG_NAMES[rt]}, 0x{imm:04X}"
    elif op == 0x23:
        return f"lw {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x21:
        return f"lh {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x25:
        return f"lhu {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x20:
        return f"lb {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x24:
        return f"lbu {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x2B:
        return f"sw {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x29:
        return f"sh {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x28:
        return f"sb {REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
    elif op == 0x04:
        target = addr + 4 + (simm << 2)
        return f"beq {REG_NAMES[rs]}, {REG_NAMES[rt]}, 0x{target:08X}"
    elif op == 0x05:
        target = addr + 4 + (simm << 2)
        return f"bne {REG_NAMES[rs]}, {REG_NAMES[rt]}, 0x{target:08X}"
    elif op == 0x06:
        target = addr + 4 + (simm << 2)
        return f"blez {REG_NAMES[rs]}, 0x{target:08X}"
    elif op == 0x07:
        target = addr + 4 + (simm << 2)
        return f"bgtz {REG_NAMES[rs]}, 0x{target:08X}"
    elif op == 0x01:
        if rt == 0x01:
            target = addr + 4 + (simm << 2)
            return f"bgez {REG_NAMES[rs]}, 0x{target:08X}"
        elif rt == 0x00:
            target = addr + 4 + (simm << 2)
            return f"bltz {REG_NAMES[rs]}, 0x{target:08X}"
        elif rt == 0x11:
            target = addr + 4 + (simm << 2)
            return f"bgezal {REG_NAMES[rs]}, 0x{target:08X}"
    elif op == 0x02:
        target = ((addr + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return f"j 0x{target:08X}"
    elif op == 0x03:
        target = ((addr + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return f"jal 0x{target:08X}"
    elif op == 0x0E:
        return f"xori {REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm:04X}"

    return f"??? op=0x{op:02X} raw=0x{word:08X}"


def print_context(data, file_offset, psp_addr, n_before=5, n_after=5):
    """Print disassembly context around a match."""
    start_off = max(0, file_offset - n_before * 4)
    end_off = min(len(data), file_offset + 4 + n_after * 4)
    for off in range(start_off, end_off, 4):
        if off + 4 > len(data):
            break
        w = struct.unpack_from("<I", data, off)[0]
        pa = psp_addr + (off - file_offset)
        cw_off = pa - CWCHEAT_BASE
        marker = " >>>" if off == file_offset else "    "
        cw_str = f"CW=0x{cw_off:07X}" if pa >= CWCHEAT_BASE else f"            "
        print(f"  {marker} 0x{pa:08X} [{cw_str}]: 0x{w:08X}  {disasm_simple(w, pa)}")


def main():
    print(f"Reading save state: {SAVE_STATE}")
    with open(SAVE_STATE, "rb") as f:
        raw = f.read()

    print(f"Raw file size: {len(raw)} bytes")
    compressed = raw[HEADER_SIZE:]
    data = zstd.decompress(compressed)
    print(f"Decompressed size: {len(data)} bytes (0x{len(data):X})")

    # Memory starts at offset 0x48 = PSP 0x08000000
    MEM_OFFSET = 0x48
    mem = data[MEM_OFFSET:]
    print(f"Memory region: PSP 0x{PSP_BASE:08X} - 0x{PSP_BASE + len(mem):08X}")
    print()

    # =======================================================================
    # 1. Verify bytes at 0x088E690C
    # =======================================================================
    target_psp = 0x088E690C
    target_file = target_psp - PSP_BASE + MEM_OFFSET
    print("=" * 80)
    print(f"1. VERIFY BYTES AT 0x{target_psp:08X}")
    print("=" * 80)
    if target_file + 4 <= len(data):
        val = struct.unpack_from("<I", data, target_file)[0]
        print(f"   Value at 0x{target_psp:08X}: 0x{val:08X}")
        print(f"   Expected: 0x28640002 (slti $a0, $v1, 2)")
        if val == 0x28640002:
            print("   MATCH!")
        else:
            print(f"   MISMATCH! Actual: {disasm_simple(val, target_psp)}")
        print("\n   Context:")
        print_context(data, target_file, target_psp, 8, 8)
    else:
        print(f"   Address out of range!")
    print()

    # =======================================================================
    # 2. Search for 0x28640002 (slti $a0, $v1, 2)
    # =======================================================================
    print("=" * 80)
    print("2. SEARCH: slti $a0, $v1, 2 (0x28640002)")
    print("=" * 80)
    pattern = 0x28640002
    matches = []
    for off in range(MEM_OFFSET, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, off)[0]
        if val == pattern:
            psp_addr = PSP_BASE + (off - MEM_OFFSET)
            matches.append((off, psp_addr))
    print(f"   Found {len(matches)} matches")
    for off, pa in matches:
        region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
        cw_off = pa - CWCHEAT_BASE
        print(f"\n   --- 0x{pa:08X} (CW offset: 0x{cw_off:07X}) [{region}] ---")
        print_context(data, off, pa)
    print()

    # =======================================================================
    # 3. Search for slti variants: 0x286x0002 and 0x28xx0002
    # =======================================================================
    print("=" * 80)
    print("3. SEARCH: slti variants with immediate=2")
    print("=" * 80)

    # 0x28xx0002: slti $any, $any, 2
    matches_broad = []
    for off in range(MEM_OFFSET, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, off)[0]
        if (val & 0xFC000000) == 0x28000000 and (val & 0xFFFF) == 0x0002:
            psp_addr = PSP_BASE + (off - MEM_OFFSET)
            rs = (val >> 21) & 0x1F
            rt = (val >> 16) & 0x1F
            matches_broad.append((off, psp_addr, val, rs, rt))

    print(f"   Found {len(matches_broad)} matches for slti $any, $any, 2")
    for off, pa, val, rs, rt in matches_broad:
        region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
        cw_off = pa - CWCHEAT_BASE
        print(f"\n   --- 0x{pa:08X} (0x{val:08X}) slti {REG_NAMES[rt]}, {REG_NAMES[rs]}, 2 [{region}] ---")
        print_context(data, off, pa)
    print()

    # =======================================================================
    # 4. Search for 16666 (0x411A) in addiu instructions
    # =======================================================================
    print("=" * 80)
    print("4. SEARCH: addiu with 16666 (0x411A) - 1/60s in microseconds")
    print("=" * 80)
    matches_16666 = []
    for off in range(MEM_OFFSET, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, off)[0]
        # addiu = opcode 0x09, imm = 0x411A
        if (val & 0xFC000000) == 0x24000000 and (val & 0xFFFF) == 0x411A:
            psp_addr = PSP_BASE + (off - MEM_OFFSET)
            matches_16666.append((off, psp_addr, val))
        # Also check ori with 0x411A (might use lui+ori for larger values)
        if (val & 0xFC000000) == 0x34000000 and (val & 0xFFFF) == 0x411A:
            psp_addr = PSP_BASE + (off - MEM_OFFSET)
            matches_16666.append((off, psp_addr, val))
        # Also li (addiu $reg, $zero, 0x411A)
        # Already covered by addiu check above
    print(f"   Found {len(matches_16666)} matches")
    for off, pa, val in matches_16666:
        region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
        cw_off = pa - CWCHEAT_BASE
        print(f"\n   --- 0x{pa:08X} (0x{val:08X}) [{region}] CW=0x{cw_off:07X} ---")
        print_context(data, off, pa, 8, 8)
    print()

    # =======================================================================
    # 5. Search for 33333 (0x8235) in addiu/ori instructions
    # =======================================================================
    print("=" * 80)
    print("5. SEARCH: addiu/ori with 33333 (0x8235) - 1/30s in microseconds")
    print("=" * 80)
    matches_33333 = []
    for off in range(MEM_OFFSET, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, off)[0]
        imm = val & 0xFFFF
        if imm == 0x8235:
            op = (val >> 26) & 0x3F
            if op in (0x09, 0x0D, 0x0F):  # addiu, ori, lui
                psp_addr = PSP_BASE + (off - MEM_OFFSET)
                matches_33333.append((off, psp_addr, val))
    print(f"   Found {len(matches_33333)} matches")
    for off, pa, val in matches_33333:
        region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
        cw_off = pa - CWCHEAT_BASE
        print(f"\n   --- 0x{pa:08X} (0x{val:08X}) [{region}] CW=0x{cw_off:07X} ---")
        print_context(data, off, pa, 8, 8)
    print()

    # =======================================================================
    # 6. Search for other timing constants
    # =======================================================================
    print("=" * 80)
    print("6. SEARCH: Other timing constants")
    print("=" * 80)

    # 16667 = 0x411B (rounded up 1/60s)
    # 8333 = 0x208D (half of 16666, 1/120s)
    # Also search for the raw value 16666 as a 32-bit word in memory (data, not instruction)
    for name, val16 in [("16667 (0x411B)", 0x411B), ("8333 (0x208D)", 0x208D)]:
        matches_other = []
        for off in range(MEM_OFFSET, len(data) - 3, 4):
            val = struct.unpack_from("<I", data, off)[0]
            if (val & 0xFFFF) == val16:
                op = (val >> 26) & 0x3F
                if op in (0x09, 0x0D):  # addiu, ori
                    psp_addr = PSP_BASE + (off - MEM_OFFSET)
                    matches_other.append((off, psp_addr, val))
        print(f"\n   {name}: {len(matches_other)} instruction matches")
        for off, pa, val in matches_other[:10]:
            region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
            cw_off = pa - CWCHEAT_BASE
            print(f"     0x{pa:08X} (0x{val:08X}) [{region}] CW=0x{cw_off:07X}")
            print_context(data, off, pa, 5, 5)

    # Search for sceDisplayWaitVblankStart-like patterns
    # The timing might use vblank counting rather than microseconds
    # Search for "slti $reg, $reg, 1" which could be "if (count < 1)" for 2x speed
    print("\n   slti $any, $any, 1 (potential frame skip threshold):")
    matches_slti1 = []
    for off in range(MEM_OFFSET, len(data) - 3, 4):
        val = struct.unpack_from("<I", data, off)[0]
        if (val & 0xFC000000) == 0x28000000 and (val & 0xFFFF) == 0x0001:
            psp_addr = PSP_BASE + (off - MEM_OFFSET)
            matches_slti1.append((off, psp_addr, val))
    print(f"   Found {len(matches_slti1)} matches (showing first 10 in 0x088-0x09x range)")
    shown = 0
    for off, pa, val in matches_slti1:
        if pa >= 0x08800000 and shown < 10:
            region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
            rs = (val >> 21) & 0x1F
            rt = (val >> 16) & 0x1F
            cw_off = pa - CWCHEAT_BASE
            print(f"\n     0x{pa:08X} slti {REG_NAMES[rt]}, {REG_NAMES[rs]}, 1 [{region}] CW=0x{cw_off:07X}")
            print_context(data, off, pa, 5, 5)
            shown += 1
    print()

    # =======================================================================
    # 7. Summary: matches in 0x09000000+ region
    # =======================================================================
    print("=" * 80)
    print("7. SUMMARY: All matches in dynamic/PRX region (0x09000000+)")
    print("=" * 80)
    all_dynamic = []
    # Re-check all our findings
    for off, pa in [(o, p) for o, p, *_ in matches_broad if p >= 0x09000000]:
        all_dynamic.append(("slti_any_2", pa))
    for off, pa, val in matches_16666:
        if pa >= 0x09000000:
            all_dynamic.append(("16666us", pa))
    for off, pa, val in matches_33333:
        if pa >= 0x09000000:
            all_dynamic.append(("33333us", pa))

    if all_dynamic:
        for kind, pa in all_dynamic:
            print(f"   {kind} at 0x{pa:08X}")
    else:
        print("   No timing-related matches found in dynamic region.")
    print()

    # =======================================================================
    # 8. Search for frame counter patterns: lw + addiu +1 + sw sequences
    # =======================================================================
    print("=" * 80)
    print("8. SEARCH: Frame counter patterns (lw/addiu+1/sw sequences)")
    print("=" * 80)
    # Look for: lw $reg, off($base) ; addiu $reg, $reg, 1 ; sw $reg, off($base)
    count = 0
    for off in range(MEM_OFFSET, len(data) - 15, 4):
        w0 = struct.unpack_from("<I", data, off)[0]
        w1 = struct.unpack_from("<I", data, off + 4)[0]
        w2 = struct.unpack_from("<I", data, off + 8)[0]

        # w0 = lw (op=0x23)
        if (w0 >> 26) & 0x3F != 0x23:
            continue
        lw_rt = (w0 >> 16) & 0x1F
        lw_rs = (w0 >> 21) & 0x1F
        lw_imm = w0 & 0xFFFF

        # w1 = addiu $rt, $rt, 1 (same register)
        if (w1 >> 26) & 0x3F != 0x09:
            continue
        add_rt = (w1 >> 16) & 0x1F
        add_rs = (w1 >> 21) & 0x1F
        add_imm = w1 & 0xFFFF
        if add_rt != lw_rt or add_rs != lw_rt or add_imm != 1:
            continue

        # w2 = sw (op=0x2B) same register, same base+offset
        if (w2 >> 26) & 0x3F != 0x2B:
            continue
        sw_rt = (w2 >> 16) & 0x1F
        sw_rs = (w2 >> 21) & 0x1F
        sw_imm = w2 & 0xFFFF
        if sw_rt != lw_rt or sw_rs != lw_rs or sw_imm != lw_imm:
            continue

        psp_addr = PSP_BASE + (off - MEM_OFFSET)
        if psp_addr < 0x08800000:
            continue

        region = "DYNAMIC/PRX" if psp_addr >= 0x09000000 else "STATIC"
        cw_off = psp_addr - CWCHEAT_BASE
        count += 1
        if count <= 30:
            print(f"\n   --- Counter at 0x{psp_addr:08X} [{region}] CW=0x{cw_off:07X} ---")
            print_context(data, off, psp_addr, 5, 8)

    print(f"\n   Total frame-counter-like patterns found: {count}")
    print()

    # =======================================================================
    # 9. Search for sceDisplayWaitVblankStart syscall
    # =======================================================================
    print("=" * 80)
    print("9. SEARCH: sceDisplay syscall references")
    print("=" * 80)
    # In MIPS, syscalls often use: jr $ra after setting up args
    # But more useful: search for the string "sceDisplayWaitVblank"
    target_bytes = b"sceDisplay"
    found_strings = []
    pos = 0
    while True:
        idx = data.find(target_bytes, pos)
        if idx == -1:
            break
        # Read surrounding string
        end = idx
        while end < len(data) and data[end] != 0:
            end += 1
        s = data[idx:end].decode("ascii", errors="replace")
        pa = PSP_BASE + (idx - MEM_OFFSET)
        found_strings.append((pa, s))
        pos = idx + 1

    print(f"   Found {len(found_strings)} sceDisplay strings")
    for pa, s in found_strings:
        print(f"     0x{pa:08X}: \"{s}\"")
    print()

    # =======================================================================
    # 10. Bonus: search for delay/wait loops with specific timing values
    # =======================================================================
    print("=" * 80)
    print("10. SEARCH: sceKernelDelayThread calls with timing args")
    print("=" * 80)
    # sceKernelDelayThread(usec) - look for lui+ori or li loading timing values
    # then jal to the syscall stub
    # Search for lui $a0, 0x0000 followed by ori $a0, $a0, 0x411A (= 16666)
    # or addiu $a0, $zero, 16666 etc.
    # Let's search for any addiu $a0, $zero, VALUE where VALUE is interesting
    interesting = {16666: "1/60s", 16667: "1/60s+1", 33333: "1/30s", 33334: "1/30s+1",
                   8333: "1/120s", 1000: "1ms", 10000: "10ms", 5000: "5ms", 20000: "20ms"}
    for val_int, desc in interesting.items():
        imm16 = val_int & 0xFFFF
        if val_int < 0x8000:
            # Can be loaded with addiu $a0, $zero, val
            pattern = 0x24040000 | imm16  # addiu $a0, $zero, val
            for off in range(MEM_OFFSET, len(data) - 3, 4):
                w = struct.unpack_from("<I", data, off)[0]
                if w == pattern:
                    pa = PSP_BASE + (off - MEM_OFFSET)
                    if pa >= 0x08800000:
                        region = "DYNAMIC/PRX" if pa >= 0x09000000 else "STATIC"
                        cw_off = pa - CWCHEAT_BASE
                        print(f"   addiu $a0, $zero, {val_int} ({desc}) at 0x{pa:08X} [{region}] CW=0x{cw_off:07X}")
                        print_context(data, off, pa, 3, 5)
                        print()

    print("\nDone!")


if __name__ == "__main__":
    main()
