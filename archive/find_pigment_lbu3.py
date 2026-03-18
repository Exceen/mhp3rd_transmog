#!/usr/bin/env python3
"""Search MHP3rd decrypted memory (from save state) for lbu instructions reading offset 0x13 (pigment flag)."""

import struct
import os
import zstandard

SAVE_STATE_DIR = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"
GAME_ID = "ULJM05800"
EBOOT_BASE = 0x08804000  # text_addr from ~PSP header

# Armor table base addresses (from memory notes)
ARMOR_TABLES = {
    "HEAD":  0x089825AC,
    "CHEST": 0x08980144,
    "ARMS":  0x0897DFFC,
    "WAIST": 0x08984DAC,
    "LEGS":  0x08986F1C,
}

REG_NAMES = [
    "zero","at","v0","v1","a0","a1","a2","a3",
    "t0","t1","t2","t3","t4","t5","t6","t7",
    "s0","s1","s2","s3","s4","s5","s6","s7",
    "t8","t9","k0","k1","gp","sp","fp","ra"
]

def decode_instr(word):
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    simm = imm if imm < 0x8000 else imm - 0x10000
    rd = (word >> 11) & 0x1F
    sa = (word >> 6) & 0x1F
    funct = word & 0x3F

    if op == 0x24: return f"lbu ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x20: return f"lb ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x25: return f"lhu ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x21: return f"lh ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x23: return f"lw ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x0F: return f"lui ${REG_NAMES[rt]}, 0x{imm:04X}"
    elif op == 0x09: return f"addiu ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, {simm} (0x{imm:04X})"
    elif op == 0x0D: return f"ori ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, 0x{imm:04X}"
    elif op == 0x0A: return f"slti ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, {simm}"
    elif op == 0x0B: return f"sltiu ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, {simm}"
    elif op == 0x04: return f"beq ${REG_NAMES[rs]}, ${REG_NAMES[rt]}, {simm}"
    elif op == 0x05: return f"bne ${REG_NAMES[rs]}, ${REG_NAMES[rt]}, {simm}"
    elif op == 0x28: return f"sb ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x29: return f"sh ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x2B: return f"sw ${REG_NAMES[rt]}, 0x{imm:04X}(${REG_NAMES[rs]})"
    elif op == 0x03:
        target = ((word & 0x03FFFFFF) << 2) | 0x08000000
        return f"jal 0x{target:08X}"
    elif op == 0x02:
        target = ((word & 0x03FFFFFF) << 2) | 0x08000000
        return f"j 0x{target:08X}"
    elif op == 0x0C: return f"andi ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, 0x{imm:04X}"
    elif op == 0x00:
        if funct == 0x21: return f"addu ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x23: return f"subu ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x25: return f"or ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x24: return f"and ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x26: return f"xor ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x00: return f"sll ${REG_NAMES[rd]}, ${REG_NAMES[rt]}, {sa}"
        elif funct == 0x02: return f"srl ${REG_NAMES[rd]}, ${REG_NAMES[rt]}, {sa}"
        elif funct == 0x03: return f"sra ${REG_NAMES[rd]}, ${REG_NAMES[rt]}, {sa}"
        elif funct == 0x08: return f"jr ${REG_NAMES[rs]}"
        elif funct == 0x09: return f"jalr ${REG_NAMES[rd]}, ${REG_NAMES[rs]}"
        elif funct == 0x18: return f"mult ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x19: return f"multu ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x10: return f"mfhi ${REG_NAMES[rd]}"
        elif funct == 0x12: return f"mflo ${REG_NAMES[rd]}"
        elif funct == 0x2A: return f"slt ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x2B: return f"sltu ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x0B: return f"movn ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        elif funct == 0x0A: return f"movz ${REG_NAMES[rd]}, ${REG_NAMES[rs]}, ${REG_NAMES[rt]}"
        return f"special funct=0x{funct:02X} rs={REG_NAMES[rs]} rt={REG_NAMES[rt]} rd={REG_NAMES[rd]} sa={sa}"
    elif op == 0x01:
        if rt == 0x01: return f"bgez ${REG_NAMES[rs]}, {simm}"
        elif rt == 0x00: return f"bltz ${REG_NAMES[rs]}, {simm}"
        elif rt == 0x11: return f"bgezal ${REG_NAMES[rs]}, {simm}"
        return f"regimm rt=0x{rt:02X} rs={REG_NAMES[rs]} imm={simm}"
    elif op == 0x06: return f"blez ${REG_NAMES[rs]}, {simm}"
    elif op == 0x07: return f"bgtz ${REG_NAMES[rs]}, {simm}"
    return f"[0x{word:08X}] op=0x{op:02X}"


def find_save_state():
    for f in sorted(os.listdir(SAVE_STATE_DIR)):
        if f.startswith(GAME_ID) and f.endswith('.ppst') and 'undo' not in f:
            return os.path.join(SAVE_STATE_DIR, f)
    return None


def load_memory(save_state_path):
    with open(save_state_path, 'rb') as f:
        raw = f.read()
    compressed = raw[0xB0:]
    dctx = zstandard.ZstdDecompressor()
    mem = dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)
    return mem


def psp_to_mem_offset(psp_addr):
    return psp_addr - 0x08000000 + 0x48


def main():
    ss_path = find_save_state()
    if not ss_path:
        print("No save state found!")
        return
    print(f"Using save state: {os.path.basename(ss_path)}")

    mem = load_memory(ss_path)
    print(f"Memory size: {len(mem)} bytes (0x{len(mem):X})")

    # Extract the EBOOT code region (0x08804000 to ~0x08A00000)
    code_start_psp = 0x08804000
    code_end_psp = 0x08A28000  # generous range covering code + data tables
    code_start_mem = psp_to_mem_offset(code_start_psp)
    code_end_mem = psp_to_mem_offset(code_end_psp)

    # Verify we have valid code
    sample_addr = 0x0885C144  # equipment lookup function
    sample_off = psp_to_mem_offset(sample_addr)
    sample = struct.unpack_from("<I", mem, sample_off)[0]
    print(f"\nVerification - instruction at 0x{sample_addr:08X}: 0x{sample:08X} -> {decode_instr(sample)}")

    # Also verify armor table
    for name, addr in ARMOR_TABLES.items():
        off = psp_to_mem_offset(addr)
        val = struct.unpack_from("<I", mem, off)[0]
        model_m = val & 0xFFFF
        model_f = (val >> 16) & 0xFFFF
        flag_off = psp_to_mem_offset(addr + 4)
        flag = mem[flag_off]
        byte19_off = psp_to_mem_offset(addr + 19)
        byte19 = mem[byte19_off]
        print(f"  {name} table at 0x{addr:08X}: model_m={model_m}, model_f={model_f}, flag@+4=0x{flag:02X}, byte@+19=0x{byte19:02X}")

    # Show what's at offset +19 for a few entries
    print("\n=== Sample byte values at offset +19 in CHEST table ===")
    chest_base = ARMOR_TABLES["CHEST"]
    for eid in range(10):
        entry_addr = chest_base + eid * 40
        off = psp_to_mem_offset(entry_addr)
        entry_bytes = mem[off:off+40]
        model_m = struct.unpack_from("<H", entry_bytes, 0)[0]
        model_f = struct.unpack_from("<H", entry_bytes, 2)[0]
        flag = entry_bytes[4]
        byte19 = entry_bytes[19]
        print(f"  eid={eid}: model_m={model_m}, model_f={model_f}, flag=0x{flag:02X}, byte[19]=0x{byte19:02X}, bytes[16:24]={entry_bytes[16:24].hex()}")

    # =========================================================================
    # SEARCH 1: lbu with offset 0x13 in code region
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 1: lbu $rt, 0x13($rs) in code region")
    print("="*100)

    lbu_13_matches = []
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        op = (word >> 26) & 0x3F
        imm = word & 0xFFFF
        if op == 0x24 and imm == 0x0013:  # lbu offset 0x13
            psp_addr = off - 0x48 + 0x08000000
            lbu_13_matches.append((off, psp_addr, word))

    print(f"Found {len(lbu_13_matches)} matches")
    for off, psp_addr, word in lbu_13_matches:
        print(f"  0x{psp_addr:08X}: {decode_instr(word)}  ; 0x{word:08X}")

    # =========================================================================
    # SEARCH 2: lb with offset 0x13
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 2: lb $rt, 0x13($rs) in code region")
    print("="*100)

    lb_13_matches = []
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        op = (word >> 26) & 0x3F
        imm = word & 0xFFFF
        if op == 0x20 and imm == 0x0013:  # lb offset 0x13
            psp_addr = off - 0x48 + 0x08000000
            lb_13_matches.append((off, psp_addr, word))

    print(f"Found {len(lb_13_matches)} matches")
    for off, psp_addr, word in lb_13_matches:
        print(f"  0x{psp_addr:08X}: {decode_instr(word)}  ; 0x{word:08X}")

    # =========================================================================
    # SEARCH 3: Any load instruction with offset 0x13
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 3: Any load with offset 0x13 (lbu/lb/lhu/lh/lw)")
    print("="*100)

    all_load_13 = []
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        op = (word >> 26) & 0x3F
        imm = word & 0xFFFF
        if imm == 0x0013 and op in (0x20, 0x21, 0x23, 0x24, 0x25):
            psp_addr = off - 0x48 + 0x08000000
            all_load_13.append((off, psp_addr, word))

    print(f"Found {len(all_load_13)} matches")
    for off, psp_addr, word in all_load_13:
        print(f"  0x{psp_addr:08X}: {decode_instr(word)}  ; 0x{word:08X}")

    # =========================================================================
    # SEARCH 4: Disassemble equipment lookup function 0x0885C144
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 4: Equipment lookup function at 0x0885C144")
    print("="*100)

    func_addr = 0x0885C144
    func_off = psp_to_mem_offset(func_addr)
    jr_ra_count = 0
    for i in range(200):
        off = func_off + i * 4
        word = struct.unpack_from("<I", mem, off)[0]
        psp = func_addr + i * 4
        print(f"  0x{psp:08X}: {decode_instr(word):55s} ; 0x{word:08X}")
        # Stop after jr $ra + delay slot
        if (word >> 26) == 0 and (word & 0x3F) == 0x08 and ((word >> 21) & 0x1F) == 31:
            # Print delay slot
            nword = struct.unpack_from("<I", mem, off + 4)[0]
            print(f"  0x{psp+4:08X}: {decode_instr(nword):55s} ; 0x{nword:08X}")
            jr_ra_count += 1
            if jr_ra_count >= 2:  # might be multiple returns in the function
                break

    # =========================================================================
    # SEARCH 5: Find callers/references to equipment lookup function
    # Also look for code that multiplies by 40 (entry size) near lbu
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 5: Code calling equipment lookup 0x0885C144")
    print("="*100)

    # jal 0x0885C144: target = 0x0885C144 >> 2 = 0x02217051, opcode 0x03 -> 0x0E217051
    jal_target = (0x0885C144 >> 2) & 0x03FFFFFF
    jal_word = (0x03 << 26) | jal_target

    callers = []
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        if word == jal_word:
            psp_addr = off - 0x48 + 0x08000000
            callers.append((off, psp_addr))

    print(f"Found {len(callers)} callers")
    for off, psp_addr in callers:
        print(f"\n  Caller at 0x{psp_addr:08X}:")
        # Show context: 10 before, 20 after
        ctx_start = max(code_start_mem, off - 10*4)
        ctx_end = min(len(mem) - 3, off + 30*4)
        for ci in range(ctx_start, ctx_end, 4):
            cword = struct.unpack_from("<I", mem, ci)[0]
            cpsp = ci - 0x48 + 0x08000000
            marker = ">>>" if ci == off else "   "
            print(f"    {marker} 0x{cpsp:08X}: {decode_instr(cword):55s} ; 0x{cword:08X}")

    # =========================================================================
    # SEARCH 6: Find all lbu within 20 instructions of any *40 computation
    # *40 can be: sll by 3 then mul by 5, or sll by 5 then sub sll by 3, etc.
    # Or addiu $rt, $rs, 0x0028 (adding 40 to step through entries)
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 6: lbu near entry-size-40 patterns")
    print("="*100)

    # First find all addiu/ori with immediate 0x28 (40) or sll by 3
    size40_offsets = set()
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        op = (word >> 26) & 0x3F
        imm = word & 0xFFFF
        # addiu with 40 or -40 (0x28 or 0xFFD8)
        if op == 0x09 and imm in (0x0028, 0xFFD8):
            size40_offsets.add(off)
        # ori with 0x28
        if op == 0x0D and imm == 0x0028:
            size40_offsets.add(off)

    # Now find lbu instructions near these
    WINDOW = 30  # instructions
    lbu_near_40 = []
    for off in range(code_start_mem, min(code_end_mem, len(mem) - 3), 4):
        word = struct.unpack_from("<I", mem, off)[0]
        op = (word >> 26) & 0x3F
        imm = word & 0xFFFF
        # Any lbu with offset in range 0x10-0x1F (could access bytes 16-31 of entry)
        if op == 0x24 and 0x10 <= imm <= 0x1F:
            # Check if there's a *40 pattern nearby
            for w in range(-WINDOW, WINDOW+1):
                check = off + w * 4
                if check in size40_offsets:
                    psp_addr = off - 0x48 + 0x08000000
                    lbu_near_40.append((off, psp_addr, word, check))
                    break

    print(f"Found {len(lbu_near_40)} lbu (offset 0x10-0x1F) near *40 patterns")
    for off, psp_addr, word, ref_off in lbu_near_40:
        print(f"\n  lbu at 0x{psp_addr:08X}: {decode_instr(word)}")
        # Show context
        ctx_start = max(code_start_mem, off - 15*4)
        ctx_end = min(len(mem) - 3, off + 15*4)
        for ci in range(ctx_start, ctx_end, 4):
            cword = struct.unpack_from("<I", mem, ci)[0]
            cpsp = ci - 0x48 + 0x08000000
            marker = ">>>" if ci == off else ("***" if ci == ref_off else "   ")
            print(f"    {marker} 0x{cpsp:08X}: {decode_instr(cword):55s} ; 0x{cword:08X}")

    # =========================================================================
    # SEARCH 7: Look for the pigment value itself
    # If byte +19 has known values, find code that compares against them
    # Let's first see what values exist at +19
    # =========================================================================
    print("\n" + "="*100)
    print("SEARCH 7: Byte +19 value distribution across all armor entries")
    print("="*100)

    for name, base in ARMOR_TABLES.items():
        byte19_vals = {}
        for eid in range(300):
            entry_addr = base + eid * 40
            off = psp_to_mem_offset(entry_addr + 19)
            if off >= len(mem):
                break
            val = mem[off]
            byte19_vals[val] = byte19_vals.get(val, 0) + 1
        print(f"  {name}: {dict(sorted(byte19_vals.items()))}")


if __name__ == "__main__":
    main()
