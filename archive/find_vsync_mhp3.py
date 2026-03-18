#!/usr/bin/env python3
"""
Find sceDisplayWaitVblankStart call addresses in MHP3rd (ULJM05800) save state.
"""

import struct
import zstandard as zstandard

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48  # offset in decompressed data where PSP RAM (0x08000000) starts
PSP_RAM_BASE = 0x08000000
CODE_BASE = 0x08800000  # typical game code base
CODE_END = 0x08C00000   # search a wider range

def decompress_save_state(path):
    with open(path, "rb") as f:
        f.seek(HEADER_SIZE)
        compressed = f.read()
    dctx = zstandard.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)

def psp_to_offset(psp_addr, data_offset=MEM_OFFSET):
    """Convert PSP address to offset in decompressed data."""
    return (psp_addr - PSP_RAM_BASE) + data_offset

def offset_to_psp(off, data_offset=MEM_OFFSET):
    """Convert decompressed data offset to PSP address."""
    return (off - data_offset) + PSP_RAM_BASE

def main():
    print(f"Decompressing {SAVE_STATE}...")
    data = decompress_save_state(SAVE_STATE)
    print(f"Decompressed size: {len(data)} bytes ({len(data)/1024/1024:.1f} MB)")

    # === Step 1: Search for "sceDisplay" strings ===
    print("\n=== Searching for 'sceDisplay' strings ===")
    search_str = b"sceDisplay"
    pos = 0
    display_string_offsets = []
    while True:
        idx = data.find(search_str, pos)
        if idx == -1:
            break
        # Read the full null-terminated string
        end = data.find(b'\x00', idx)
        full_str = data[idx:end].decode('ascii', errors='replace')
        psp_addr = offset_to_psp(idx)
        print(f"  0x{psp_addr:08X} (offset 0x{idx:08X}): \"{full_str}\"")
        display_string_offsets.append((idx, psp_addr, full_str))
        pos = idx + 1

    # === Step 2: Search for NID 0x984C27E7 ===
    print("\n=== Searching for NID 0x984C27E7 (sceDisplayWaitVblankStart) ===")
    nid_bytes = struct.pack("<I", 0x984C27E7)
    pos = 0
    nid_locations = []
    while True:
        idx = data.find(nid_bytes, pos)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        # Show surrounding context
        ctx_start = max(0, idx - 16)
        ctx_end = min(len(data), idx + 20)
        ctx_hex = data[ctx_start:ctx_end].hex()
        print(f"  0x{psp_addr:08X} (offset 0x{idx:08X})")
        # Check if preceded by jr $ra (0x03E00008) + nop (0x00000000)
        if idx >= 8:
            prev_word = struct.unpack_from("<I", data, idx - 8)[0]
            prev_word2 = struct.unpack_from("<I", data, idx - 4)[0]
            print(f"    prev instructions: 0x{prev_word:08X} 0x{prev_word2:08X}")
        nid_locations.append((idx, psp_addr))
        pos = idx + 1

    # === Step 3: Search for NID 0x46F186C3 (sceDisplayWaitVblank) too ===
    print("\n=== Searching for NID 0x46F186C3 (sceDisplayWaitVblank) ===")
    nid_bytes2 = struct.pack("<I", 0x46F186C3)
    pos = 0
    while True:
        idx = data.find(nid_bytes2, pos)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        print(f"  0x{psp_addr:08X} (offset 0x{idx:08X})")
        nid_locations.append((idx, psp_addr))
        pos = idx + 1

    # === Step 4: Find import stubs in the stub region ===
    # PPSSPP resolves imports: stubs become j <syscall_addr> + nop
    # The stub region is typically near the start of the module, around 0x08800000-0x08810000
    # But could also be at the module's import stub section.
    # Let's look for patterns: in PPSSPP, resolved stubs are:
    #   j <addr>    -> 0x08xxxxxx or 0x0Axxxxxx encoded as (0x08 | (addr>>26))<<26 | ((addr>>2) & 0x03FFFFFF)
    #   nop         -> 0x00000000
    # Actually PPSSPP replaces stubs with special instructions or direct jumps.

    # Let's try another approach: search for "WaitVblankStart" with partial match
    print("\n=== Searching for 'WaitVblank' strings ===")
    search_str2 = b"WaitVblank"
    pos = 0
    while True:
        idx = data.find(search_str2, pos)
        if idx == -1:
            break
        end = data.find(b'\x00', idx)
        if end == -1:
            end = idx + 40
        # go back to find start of string
        start = idx
        while start > 0 and data[start-1:start] != b'\x00' and data[start-1] >= 0x20:
            start -= 1
        full_str = data[start:end].decode('ascii', errors='replace')
        psp_addr = offset_to_psp(start)
        print(f"  0x{psp_addr:08X}: \"{full_str}\"")
        pos = idx + 1

    # === Step 5: In PPSSPP, import stubs are replaced with special syscall instructions ===
    # PPSSPP uses:
    #   lui $v0, 0x0000   -> but actually it uses a special "syscall" encoding
    # The pattern is: syscall <number> which is 0x0000000C with the code in bits 6-25
    # Actually, PPSSPP replaces import stubs with:
    #   encoding: 0x0000000C (syscall) with module/func encoded
    # OR it might use j <addr> where addr is in high memory

    # Let's look at the stub area. In PSP executables, the stub area is usually
    # right before or after the code section. Let's examine around where strings were found.

    # === Step 6: Look for PPSSPP's HLE stub pattern ===
    # In PPSSPP, resolved HLE stubs use the pattern:
    #   sc <module_num>, <func_num>  encoded as special instructions
    # Actually the encoding is just:
    #   0x0000000C  (syscall instruction with code field)
    # Let's search for syscall instructions in the stub area

    print("\n=== Examining stub region 0x08800000 - 0x08810000 ===")
    stub_start_off = psp_to_offset(0x08800000)
    stub_end_off = psp_to_offset(0x08810000)

    # Find all syscall instructions (opcode 0x0000000C, but code field varies)
    # syscall encoding: bits 31-26 = 0 (SPECIAL), bits 5-0 = 0x0C (SYSCALL)
    # Full: 0x{code}0C where code is in bits 6-25
    syscall_addrs = []
    for off in range(stub_start_off, min(stub_end_off, len(data)), 4):
        word = struct.unpack_from("<I", data, off)[0]
        if (word & 0xFC00003F) == 0x0000000C:  # SYSCALL instruction
            psp_addr = offset_to_psp(off)
            code = (word >> 6) & 0xFFFFF
            syscall_addrs.append((psp_addr, code))

    if syscall_addrs:
        print(f"  Found {len(syscall_addrs)} syscall instructions in stub region")
        # Show first 20
        for addr, code in syscall_addrs[:40]:
            print(f"    0x{addr:08X}: syscall 0x{code:05X}")
    else:
        print("  No syscall instructions found in stub region")

    # === Step 7: Look for PPSSPP's specific stub encoding ===
    # In PPSSPP, each import stub is 2 instructions:
    #   nop  (0x00000000)  -- actually not always
    # Let's just look at the first few hundred instructions at 0x08800000
    print("\n=== First 64 instructions at 0x08800000 ===")
    base_off = psp_to_offset(0x08800000)
    for i in range(64):
        off = base_off + i * 4
        if off + 4 > len(data):
            break
        word = struct.unpack_from("<I", data, off)[0]
        psp_addr = 0x08800000 + i * 4
        # Decode basic MIPS
        opcode = (word >> 26) & 0x3F
        if opcode == 3:  # JAL
            target = (word & 0x03FFFFFF) << 2
            # Upper bits come from PC
            target |= (psp_addr & 0xF0000000)
            desc = f"jal 0x{target:08X}"
        elif opcode == 2:  # J
            target = (word & 0x03FFFFFF) << 2
            target |= (psp_addr & 0xF0000000)
            desc = f"j 0x{target:08X}"
        elif opcode == 0 and (word & 0x3F) == 0x0C:
            code = (word >> 6) & 0xFFFFF
            desc = f"syscall 0x{code:05X}"
        elif opcode == 0 and (word & 0x3F) == 0x08:
            rs = (word >> 21) & 0x1F
            desc = f"jr ${['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra'][rs]}"
        elif word == 0:
            desc = "nop"
        else:
            desc = f"(op={opcode})"
        print(f"    0x{psp_addr:08X}: 0x{word:08X}  {desc}")

    # === Step 8: Look for j instructions targeting high addresses (PPSSPP HLE) ===
    # PPSSPP HLE functions are at addresses like 0x0880xxxx or special addresses
    # Let's search the whole code region for the stub pattern
    print("\n=== Looking for j+nop pairs (resolved stubs) in 0x08800000-0x08810000 ===")
    j_targets = {}
    for off in range(stub_start_off, min(stub_end_off, len(data)) - 4, 4):
        word = struct.unpack_from("<I", data, off)[0]
        opcode = (word >> 26) & 0x3F
        if opcode == 2:  # J instruction
            target = (word & 0x03FFFFFF) << 2
            psp_addr_of_j = offset_to_psp(off)
            target |= (psp_addr_of_j & 0xF0000000)
            # Check if next instruction is nop
            next_word = struct.unpack_from("<I", data, off + 4)[0]
            if next_word == 0x00000000:
                if target not in j_targets:
                    j_targets[target] = []
                j_targets[target].append(psp_addr_of_j)

    print(f"  Found {len(j_targets)} unique j+nop stub targets")
    for target, addrs in sorted(j_targets.items()):
        print(f"    Target 0x{target:08X}: stubs at {', '.join(f'0x{a:08X}' for a in addrs)}")

    # === Step 9: For each stub, find all JAL instructions calling it ===
    # Focus on stubs found above. The vsync function stub - we need to identify which one.
    # Let's find ALL jal instructions in the code region that call any of these stubs
    print("\n=== Searching for JAL instructions calling stubs (in 0x08800000-0x08C00000) ===")
    code_start_off = psp_to_offset(CODE_BASE)
    code_end_off = psp_to_offset(CODE_END)
    code_end_off = min(code_end_off, len(data))

    # Build set of stub addresses
    all_stub_addrs = set()
    for addrs in j_targets.values():
        all_stub_addrs.update(addrs)

    # For each stub, count how many JALs call it
    stub_callers = {addr: [] for addr in all_stub_addrs}

    for off in range(code_start_off, code_end_off, 4):
        word = struct.unpack_from("<I", data, off)[0]
        opcode = (word >> 26) & 0x3F
        if opcode == 3:  # JAL
            target = (word & 0x03FFFFFF) << 2
            caller_addr = offset_to_psp(off)
            target |= (caller_addr & 0xF0000000)
            if target in stub_callers:
                stub_callers[target].append(caller_addr)

    print("\n  Stubs sorted by number of callers:")
    for stub_addr, callers in sorted(stub_callers.items(), key=lambda x: len(x[1]), reverse=True):
        if callers:
            # Find what this stub jumps to
            stub_off = psp_to_offset(stub_addr)
            stub_word = struct.unpack_from("<I", data, stub_off)[0]
            stub_target = ((stub_word & 0x03FFFFFF) << 2) | (stub_addr & 0xF0000000)
            print(f"    Stub 0x{stub_addr:08X} -> 0x{stub_target:08X}: {len(callers)} callers")
            if len(callers) <= 5:
                for c in callers:
                    print(f"      called from 0x{c:08X}")

    # === Step 10: Try to identify vsync by looking for stubs called exactly once or few times ===
    # sceDisplayWaitVblankStart is typically called only 1-2 times
    print("\n=== Stubs called 1-3 times (likely vsync candidates) ===")
    for stub_addr, callers in sorted(stub_callers.items(), key=lambda x: x[0]):
        if 1 <= len(callers) <= 3:
            stub_off = psp_to_offset(stub_addr)
            stub_word = struct.unpack_from("<I", data, stub_off)[0]
            stub_target = ((stub_word & 0x03FFFFFF) << 2) | (stub_addr & 0xF0000000)
            print(f"    Stub 0x{stub_addr:08X} -> 0x{stub_target:08X}: {len(callers)} caller(s)")
            for c in callers:
                # Show context around the caller
                caller_off = psp_to_offset(c)
                print(f"      called from 0x{c:08X}")
                # Show a few instructions before and after
                for delta in range(-3, 5):
                    ins_off = caller_off + delta * 4
                    if 0 <= ins_off < len(data) - 3:
                        w = struct.unpack_from("<I", data, ins_off)[0]
                        ins_addr = c + delta * 4
                        marker = " <<< JAL" if delta == 0 else ""
                        op = (w >> 26) & 0x3F
                        if op == 3:
                            t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                            desc = f"jal 0x{t:08X}"
                        elif op == 2:
                            t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                            desc = f"j 0x{t:08X}"
                        elif w == 0:
                            desc = "nop"
                        else:
                            desc = ""
                        print(f"        0x{ins_addr:08X}: 0x{w:08X} {desc}{marker}")
                print()

    # === Step 11: Also check if PPSSPP stores function names somewhere ===
    print("\n=== Searching for 'sceDisplayWaitVblankStart' string ===")
    fname = b"sceDisplayWaitVblankStart"
    pos = 0
    while True:
        idx = data.find(fname, pos)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        print(f"  Found at 0x{psp_addr:08X} (offset 0x{idx:08X})")
        # Show surrounding bytes
        ctx_start = max(0, idx - 32)
        ctx_end = min(len(data), idx + 64)
        print(f"  Context hex: ...{data[ctx_start:idx].hex()} | {data[idx:ctx_end].hex()}")
        pos = idx + 1

    print("\nDone!")

if __name__ == "__main__":
    main()
