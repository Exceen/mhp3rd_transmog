#!/usr/bin/env python3
"""Find controller button state addresses in MHP3rd save state."""

import struct
import zstandard as zstd

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_5.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
MEM_OFFSET = 0x48

# MIPS register names
REG_NAMES = [
    "zero","at","v0","v1","a0","a1","a2","a3",
    "t0","t1","t2","t3","t4","t5","t6","t7",
    "s0","s1","s2","s3","s4","s5","s6","s7",
    "t8","t9","k0","k1","gp","sp","fp","ra"
]

def addr_to_offset(addr):
    return addr - PSP_BASE + MEM_OFFSET

def read_u32(mem, offset):
    if offset + 4 > len(mem):
        return None
    return struct.unpack_from("<I", mem, offset)[0]

def disasm_andi(instr):
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF
    return f"andi ${REG_NAMES[rt]}, ${REG_NAMES[rs]}, 0x{imm:04X}"

def disasm_lui(instr):
    rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF
    return f"lui ${REG_NAMES[rt]}, 0x{imm:04X}"

def disasm_load(instr, op_name):
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF
    if imm >= 0x8000:
        imm_signed = imm - 0x10000
    else:
        imm_signed = imm
    return f"{op_name} ${REG_NAMES[rt]}, {imm_signed}(${REG_NAMES[rs]})"

def disasm_branch(instr, addr, op_name):
    rs = (instr >> 21) & 0x1F
    rt = (instr >> 16) & 0x1F
    imm = instr & 0xFFFF
    if imm >= 0x8000:
        imm_signed = imm - 0x10000
    else:
        imm_signed = imm
    target = addr + 4 + imm_signed * 4
    return f"{op_name} ${REG_NAMES[rs]}, ${REG_NAMES[rt]}, 0x{target:08X}"

def disasm_instr(instr, addr):
    op = (instr >> 26) & 0x3F
    if op == 0x0C:
        return disasm_andi(instr)
    elif op == 0x0F:
        return disasm_lui(instr)
    elif op == 0x23:
        return disasm_load(instr, "lw")
    elif op == 0x25:
        return disasm_load(instr, "lhu")
    elif op == 0x21:
        return disasm_load(instr, "lh")
    elif op == 0x24:
        return disasm_load(instr, "lbu")
    elif op == 0x20:
        return disasm_load(instr, "lb")
    elif op == 0x04:
        return disasm_branch(instr, addr, "beq")
    elif op == 0x05:
        return disasm_branch(instr, addr, "bne")
    else:
        return f"op=0x{op:02X} raw=0x{instr:08X}"

def find_load_source(mem, andi_addr, andi_instr):
    """Look backwards from andi for lui+lw/lhu pattern to find global address."""
    rs = (andi_instr >> 21) & 0x1F  # source register of andi
    results = []

    # Track which register we're looking for
    target_reg = rs

    # Look backwards up to 20 instructions
    for i in range(1, 21):
        check_addr = andi_addr - i * 4
        off = addr_to_offset(check_addr)
        instr = read_u32(mem, off)
        if instr is None:
            break

        op = (instr >> 26) & 0x3F
        rt = (instr >> 16) & 0x1F

        # Check for lw/lhu that writes to our target register
        if op in (0x23, 0x25, 0x21) and rt == target_reg:
            load_rs = (instr >> 21) & 0x1F
            load_imm = instr & 0xFFFF
            if load_imm >= 0x8000:
                load_imm_signed = load_imm - 0x10000
            else:
                load_imm_signed = load_imm

            op_name = {0x23: "lw", 0x25: "lhu", 0x21: "lh"}[op]

            # Now look for lui that sets the base register
            for j in range(i + 1, i + 21):
                lui_addr = andi_addr - j * 4
                lui_off = addr_to_offset(lui_addr)
                lui_instr = read_u32(mem, lui_off)
                if lui_instr is None:
                    break
                lui_op = (lui_instr >> 26) & 0x3F
                lui_rt = (lui_instr >> 16) & 0x1F
                if lui_op == 0x0F and lui_rt == load_rs:
                    lui_imm = lui_instr & 0xFFFF
                    global_addr = (lui_imm << 16) + load_imm_signed
                    results.append((check_addr, f"{op_name} from 0x{global_addr:08X}",
                                    disasm_instr(instr, check_addr),
                                    lui_addr, disasm_instr(lui_instr, lui_addr)))
                    break

            # Also check if load_rs == target_reg (self-dereference chain)
            # Follow the chain: update target_reg to load_rs
            if not results:
                target_reg = load_rs
            else:
                break

    return results

def search_region(mem, start_addr, end_addr, region_name):
    """Search a memory region for andi with 0x0100."""
    print(f"\n{'='*70}")
    print(f"Searching {region_name}: 0x{start_addr:08X} - 0x{end_addr:08X}")
    print(f"{'='*70}")

    andi_matches = []

    for addr in range(start_addr, end_addr, 4):
        off = addr_to_offset(addr)
        instr = read_u32(mem, off)
        if instr is None:
            continue

        op = (instr >> 26) & 0x3F
        imm = instr & 0xFFFF

        # andi with 0x0100
        if op == 0x0C and imm == 0x0100:
            andi_matches.append((addr, instr))
            print(f"\n  0x{addr:08X}: {disasm_andi(instr)}")

            # Look for load source
            sources = find_load_source(mem, addr, instr)
            for src_addr, desc, load_dis, lui_addr, lui_dis in sources:
                print(f"    <- 0x{lui_addr:08X}: {lui_dis}")
                print(f"    <- 0x{src_addr:08X}: {load_dis}")
                print(f"    => Button state loaded from: {desc}")

            # Check for bne/beq after andi (within next 3 instructions)
            for k in range(1, 4):
                next_addr = addr + k * 4
                next_off = addr_to_offset(next_addr)
                next_instr = read_u32(mem, next_off)
                if next_instr is None:
                    break
                next_op = (next_instr >> 26) & 0x3F
                if next_op in (0x04, 0x05):
                    br_name = "beq" if next_op == 0x04 else "bne"
                    print(f"    -> 0x{next_addr:08X}: {disasm_branch(next_instr, next_addr, br_name)}")
                    break

    print(f"\n  Total andi $r, $r, 0x0100 matches: {len(andi_matches)}")
    return andi_matches

def search_andi_other_masks(mem, start_addr, end_addr, region_name):
    """Also search for common pad-related andi masks."""
    print(f"\n{'='*70}")
    print(f"Bonus: Other button masks in {region_name}")
    print(f"{'='*70}")

    # PSP button masks
    BUTTONS = {
        0x0001: "SELECT", 0x0008: "START",
        0x0010: "UP", 0x0020: "RIGHT", 0x0040: "DOWN", 0x0080: "LEFT",
        0x0100: "L", 0x0200: "R",
        0x1000: "TRIANGLE", 0x2000: "CIRCLE", 0x4000: "CROSS", 0x8000: "SQUARE"
    }

    # Count andi instructions per immediate value for button masks
    counts = {}
    for addr in range(start_addr, end_addr, 4):
        off = addr_to_offset(addr)
        instr = read_u32(mem, off)
        if instr is None:
            continue
        op = (instr >> 26) & 0x3F
        imm = instr & 0xFFFF
        if op == 0x0C and imm in BUTTONS:
            if imm not in counts:
                counts[imm] = []
            counts[imm].append(addr)

    for mask in sorted(counts.keys()):
        name = BUTTONS[mask]
        addrs = counts[mask]
        print(f"  0x{mask:04X} ({name:8s}): {len(addrs)} matches", end="")
        if len(addrs) <= 6:
            print(" at " + ", ".join(f"0x{a:08X}" for a in addrs))
        else:
            print(f" (first 3: {', '.join(f'0x{a:08X}' for a in addrs[:3])})")


def main():
    print("Loading save state...")
    with open(SAVE_STATE, "rb") as f:
        f.seek(HEADER_SIZE)
        compressed = f.read()

    print("Decompressing...")
    dctx = zstd.ZstdDecompressor()
    mem = dctx.decompress(compressed, max_output_size=64 * 1024 * 1024)
    print(f"Decompressed size: {len(mem)} bytes (0x{len(mem):X})")

    # Search EBOOT area
    eboot_matches = search_region(mem, 0x08800000, 0x08B00000, "EBOOT (0x08800000-0x08B00000)")

    # Search overlay area
    overlay_matches = search_region(mem, 0x09C50000, 0x09DE0000, "Overlay (0x09C50000-0x09DE0000)")

    # Bonus: button mask stats
    search_andi_other_masks(mem, 0x08800000, 0x08B00000, "EBOOT")
    search_andi_other_masks(mem, 0x09C50000, 0x09DE0000, "Overlay")

    # Also: search for common pad state addresses by looking at frequently referenced globals
    # near andi 0x0100 instructions
    print(f"\n{'='*70}")
    print("Summary of unique button state source addresses")
    print(f"{'='*70}")

    all_sources = {}
    for addr, instr in eboot_matches + overlay_matches:
        sources = find_load_source(mem, addr, instr)
        for src_addr, desc, load_dis, lui_addr, lui_dis in sources:
            # Extract the global address
            parts = desc.split("0x")
            if len(parts) >= 2:
                gaddr = int(parts[-1], 16)
                if gaddr not in all_sources:
                    all_sources[gaddr] = []
                all_sources[gaddr].append(addr)

    for gaddr in sorted(all_sources.keys()):
        refs = all_sources[gaddr]
        # Read current value at that address
        off = addr_to_offset(gaddr)
        val = read_u32(mem, off)
        val_str = f"0x{val:08X}" if val is not None else "N/A"
        print(f"  0x{gaddr:08X} (current value: {val_str}) - referenced by {len(refs)} andi(s): {', '.join(f'0x{a:08X}' for a in refs)}")


if __name__ == "__main__":
    main()
