#!/usr/bin/env python3
"""
Find vsync/frame-rate-limiting mechanism in MHP3rd - v5

The game only imports 2 sceDisplay functions:
  - sceDisplaySetMode (NID 0x0E20F177) at stub 0x08960D28
  - sceDisplaySetFrameBuf (NID 0x289D82FE) at stub 0x08960D30

sceDisplayWaitVblankStart is NOT imported!

The game likely uses one of:
1. sceDisplaySetFrameBuf with sync=1 (VBLANK sync mode) - this waits for vblank
2. sceKernelDelayThread to sleep for ~16ms
3. Some other wait mechanism

Let's find:
- All calls to sceDisplaySetFrameBuf and check the sync parameter
- All sceKernelDelayThread calls
- Also search for any thread wait functions
"""

import struct
import zstandard

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_RAM_BASE = 0x08000000

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

def read32(data, psp_addr):
    off = psp_to_offset(psp_addr)
    return struct.unpack_from("<I", data, off)[0]

def read8(data, psp_addr):
    return data[psp_to_offset(psp_addr)]

def read16(data, psp_addr):
    return struct.unpack_from("<H", data, psp_to_offset(psp_addr))[0]

def read_string(data, psp_addr):
    off = psp_to_offset(psp_addr)
    end = data.find(b'\x00', off)
    return data[off:end].decode('ascii', errors='replace')

REGS = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
        's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']

def decode(word, addr):
    op = (word >> 26) & 0x3F
    if word == 0: return "nop"
    if op == 3:
        t = ((word & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
        return f"jal 0x{t:08X}"
    if op == 2:
        t = ((word & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
        return f"j 0x{t:08X}"
    if op == 0:
        func = word & 0x3F
        rd = (word >> 11) & 0x1F
        rt = (word >> 16) & 0x1F
        rs = (word >> 21) & 0x1F
        if func == 0x08: return f"jr ${REGS[rs]}"
        if func == 0x09: return f"jalr ${REGS[rs]}"
        if func == 0x21: return f"addu ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x0C:
            code = (word >> 6) & 0xFFFFF
            return f"syscall 0x{code:05X}"
        if func == 0x25: return f"or ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
    if op == 9:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"addiu ${REGS[rt]}, ${REGS[rs]}, {imm}"
    if op == 0x0F:
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        return f"lui ${REGS[rt]}, 0x{imm:04X}"
    if op == 0x0D:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        return f"ori ${REGS[rt]}, ${REGS[rs]}, 0x{imm:04X}"
    if op == 4:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        offset = word & 0xFFFF
        if offset >= 0x8000: offset -= 0x10000
        target = addr + 4 + offset * 4
        return f"beq ${REGS[rs]}, ${REGS[rt]}, 0x{target:08X}"
    if op == 5:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        offset = word & 0xFFFF
        if offset >= 0x8000: offset -= 0x10000
        target = addr + 4 + offset * 4
        return f"bne ${REGS[rs]}, ${REGS[rt]}, 0x{target:08X}"
    if op == 0x23:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"lw ${REGS[rt]}, {imm}(${REGS[rs]})"
    if op == 0x2B:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"sw ${REGS[rt]}, {imm}(${REGS[rs]})"
    return f"0x{word:08X}"

def show_context(data, center_addr, before=6, after=8):
    for delta in range(-before, after + 1):
        addr = center_addr + delta * 4
        off = psp_to_offset(addr)
        if 0 <= off < len(data) - 3:
            w = struct.unpack_from("<I", data, off)[0]
            marker = "  <<<" if delta == 0 else ""
            print(f"    0x{addr:08X}: 0x{w:08X}  {decode(w, addr)}{marker}")

def main():
    print("Decompressing...")
    data = decompress_save_state(SAVE_STATE)

    # First, let's build a complete map of ALL import stubs by scanning the PPSSPP metadata
    # at 0x0A206xxx. Each entry is 40 bytes:
    # +0x00: 2 bytes padding (zeros)
    # +0x02: 4 bytes stub address (LE)
    # +0x06: 4 bytes NID (LE)
    # +0x0A: 30 bytes library name (null-padded)
    #
    # Wait, from the hex dump the format looks like:
    # The entries at stride 0x28 (40 bytes) starting from... let me recalculate.
    # From the raw dump:
    # 0x0A206E70: 00 00 20 0D 96 08 E4 40 7E E4 73 63 65 44 69 73
    # So at 0x0A206E70: 00 00 = padding
    # 0x0A206E72: 20 0D 96 08 = 0x0896_0D20 (stub addr, LE)
    # 0x0A206E76: E4 40 7E E4 = 0xE47E40E4 ... wait that's not right
    # Actually reading as 4 bytes LE from offset +2: bytes 20 0D 96 08 = 0x08960D20. Good.
    # Reading 4 bytes LE from offset +6: bytes E4 40 7E E4 = 0xE47E40E4. Hmm, but what function has NID 0xE47E40E4?
    # That doesn't match any known sceDisplay function.
    #
    # Wait, looking more carefully at aligned reads:
    # 0x0A206E70: 0x0D200000 -> in LE bytes: 00 00 20 0D
    # 0x0A206E74: 0x40E40896 -> in LE bytes: 96 08 E4 40
    # So the stub ptr and NID span across aligned words.
    # Let me read unaligned:
    # bytes at file offset for 0x0A206E70: 00 00 20 0D 96 08 E4 40 7E E4
    # As 2 padding + 4-byte LE stub + 4-byte LE NID:
    # stub = data[+2:+6] = 20 0D 96 08 -> LE = 0x08960D20
    # NID  = data[+6:+10] = E4 40 7E E4 -> LE = 0xE47E40E4
    #
    # But 0xE47E40E4 isn't a known sceDisplay NID.
    # Hmm wait... Let me recheck. The next entry at +0x28:
    # 0x0A206E98: 00 00 28 0D 96 08 77 F1 20 0E
    # stub = 28 0D 96 08 -> 0x08960D28
    # NID = 77 F1 20 0E -> 0x0E20F177
    # YES! That matches. So the first entry has NID 0xE47E40E4 for an sceDisplay function
    # at stub 0x08960D20. This must be a function not in the game's import table.
    # (PPSSPP may register extra stubs internally.)

    # Let's scan ALL metadata entries and build stub->name mapping
    print("\n=== Building stub->function name map from PPSSPP metadata ===")

    # Known PPSSPP NIDs (from the gist)
    NID_MAP = {
        0x0E20F177: "sceDisplaySetMode",
        0x289D82FE: "sceDisplaySetFrameBuf",
        0x984C27E7: "sceDisplayWaitVblankStart",
        0x46F186C3: "sceDisplayWaitVblankStartCB",
        0x7ED59BC4: "sceDisplaySetHoldMode",
        0xEEDA2E54: "sceDisplayGetFrameBuf",
        0x36CDFADE: "sceDisplayWaitVblank",
        0x8EB9EC49: "sceDisplayWaitVblankCB",
        0x9C6EAAD7: "sceDisplayGetVcount",
        0xDEA197D4: "sceDisplayGetMode",
        0xDBA6C4C4: "sceDisplayGetFramePerSec",
        0xB4F378FA: "sceDisplayIsForeground",
        0x4D4E10EC: "sceDisplayIsVblank",
        0xE47E40E4: "??sceDisplay_E47E40E4",  # Unknown
        # sceCtrl
        0x1F4011E6: "sceCtrlSetSamplingCycle",
        0x1F803938: "sceCtrlReadBufferPositive",
        0x6A2774F3: "sceCtrlSetSamplingMode",
        # sceKernel thread functions
        0xCEADEB47: "sceKernelDelayThread",
        0x68DA9E36: "sceKernelDelayThreadCB",
        0x9ACE131E: "sceKernelSleepThread",
        0x82826F70: "sceKernelSleepThreadCB",
        0x278C0DF5: "sceKernelWaitThreadEnd",
    }

    # Scan the metadata region. We know entries start around 0x0A206C48 or earlier.
    # Let's scan from 0x0A206800 with 40-byte stride, looking for valid entries.
    # Actually, let's search for known stubs (0x0896xxxx) in the metadata region

    # Better: scan all 40-byte aligned positions looking for the pattern
    metadata_entries = []
    scan_start = psp_to_offset(0x0A206000)
    scan_end = psp_to_offset(0x0A20A000)
    scan_end = min(scan_end, len(data))

    # Find the first entry by looking for a known stub address
    # We know 0x08960D28 appears at metadata offset 0x0A206E9A (unaligned)
    # The entries are at stride 40 from some base.
    # 0x0A206E98 = base of an entry. So base could be 0x0A206E98 - N*40
    # 0x0A206E98 - 0x0A206000 = 0xE98
    # 0xE98 / 40 = 93.4 -> not aligned to base 0x0A206000
    # 0x0A206E98 mod 40 = ? 0x0A206E98 in decimal... Let's just use the known stride.

    # From output: entries at 0x0A206E70, 0x0A206E98, 0x0A206EC0, ...
    # Diff = 0x28 = 40. Starting at 0x0A206E70.
    # Let's go backwards to find more entries
    entry_base = 0x0A206E70
    # Go back
    addr = entry_base - 40
    while addr >= 0x0A200000:
        off = psp_to_offset(addr + 2)
        if off + 8 <= len(data):
            stub = struct.unpack_from("<I", data, off)[0]
            nid = struct.unpack_from("<I", data, off + 4)[0]
            if 0x08960000 <= stub <= 0x08970000:
                entry_base = addr
                addr -= 40
                continue
        break

    print(f"  First metadata entry at 0x{entry_base:08X}")

    # Now scan forward
    addr = entry_base
    all_stubs = {}
    while addr < 0x0A210000:
        off = psp_to_offset(addr + 2)
        if off + 8 > len(data):
            break
        stub = struct.unpack_from("<I", data, off)[0]
        nid = struct.unpack_from("<I", data, off + 4)[0]
        if not (0x08960000 <= stub <= 0x08970000):
            break
        # Read library name
        name_off = psp_to_offset(addr + 10)
        name_end = data.find(b'\x00', name_off, name_off + 30)
        lib_name = data[name_off:name_end].decode('ascii', errors='replace') if name_end > name_off else ""

        func_name = NID_MAP.get(nid, f"unknown_0x{nid:08X}")
        all_stubs[stub] = (nid, func_name, lib_name)
        metadata_entries.append((addr, stub, nid, func_name, lib_name))

        addr += 40

    print(f"  Found {len(metadata_entries)} metadata entries")

    # Show all entries
    for meta_addr, stub, nid, func_name, lib_name in metadata_entries:
        print(f"    0x{stub:08X}: {lib_name}::{func_name} (NID 0x{nid:08X})")

    # Now let's specifically look for thread delay / wait functions
    print("\n\n=== Looking for sceKernelDelayThread and similar stubs ===")
    delay_stubs = []
    for stub, (nid, fname, lname) in all_stubs.items():
        if "Delay" in fname or "Sleep" in fname or "Wait" in fname or "Vblank" in fname:
            delay_stubs.append((stub, fname, lname))
            print(f"  Stub 0x{stub:08X}: {lname}::{fname}")

    # Also check: the game might import these from ThreadManForUser
    # Let's parse the actual import table more carefully
    print("\n\n=== Parsing ALL import table entries ===")
    # We found entries at 0x08961400+ area, each 20 bytes
    # Let's scan from a bit before
    import_base = 0x089613E0
    while import_base < 0x08961700:
        name_ptr = read32(data, import_base)
        if 0x08961700 <= name_ptr <= 0x08962000:
            # Valid name pointer
            name = read_string(data, name_ptr)
            if name and name[0].isalpha():
                ent_len = read8(data, import_base + 8)
                var_count = read8(data, import_base + 9)
                func_count = read16(data, import_base + 10)
                nid_ptr = read32(data, import_base + 12)
                stub_ptr = read32(data, import_base + 16)

                if 0x08960000 <= stub_ptr <= 0x08970000 and func_count > 0 and func_count < 100:
                    print(f"\n  {name} at 0x{import_base:08X}: {func_count} funcs, {var_count} vars")
                    print(f"    NID table: 0x{nid_ptr:08X}, Stub table: 0x{stub_ptr:08X}")

                    for i in range(func_count):
                        nid = read32(data, nid_ptr + i * 4)
                        s_addr = stub_ptr + i * 8
                        fname = NID_MAP.get(nid, f"unknown_0x{nid:08X}")
                        # Also check metadata
                        if s_addr in all_stubs:
                            _, mfname, _ = all_stubs[s_addr]
                            fname = mfname

                        print(f"    [{i}] 0x{s_addr:08X}: {fname} (NID 0x{nid:08X})")

        import_base += 20

    # Now find the frame rate control: search for sceKernelDelayThread calls
    # or sceDisplayWaitVblank calls (even if not in import table, maybe in a loaded module)

    # Let's search for ALL syscalls with known display module (0xE) in the ENTIRE code
    print("\n\n=== ALL module 0xE (sceDisplay) syscalls in full memory ===")
    code_start = psp_to_offset(0x08800000)
    code_end = min(psp_to_offset(0x0A000000), len(data))

    for off in range(code_start, code_end, 4):
        word = struct.unpack_from("<I", data, off)[0]
        if (word & 0x3F) == 0x0C and word != 0:
            code = (word >> 6) & 0xFFFFF
            module = code >> 12
            func = code & 0xFFF
            if module == 0xE:
                addr = offset_to_psp(off)
                # Check previous instruction
                prev = struct.unpack_from("<I", data, off - 4)[0]
                print(f"  0x{addr:08X}: syscall 0x{code:05X} (display func {func}), prev: 0x{prev:08X}")

    # Let's look for the PPSSPP sceDisplay module function table to know the func indices
    # PPSSPP assigns syscall IDs based on the order functions are registered in HLETables.cpp
    # For sceDisplay, the typical order is:
    # From PPSSPP source (sceDisplay.cpp RegisterModule):
    # The functions are registered in the sceDisplay[] array, which is:
    # We need to fetch this from PPSSPP source

    # Instead, let's correlate: we know:
    #   stub 0x08960D28 = syscall 0x0E000 = sceDisplaySetMode (NID 0x0E20F177)
    #   stub 0x08960D30 = syscall 0x0E001 = sceDisplaySetFrameBuf (NID 0x289D82FE)
    # So in PPSSPP's registration order:
    #   func 0 = sceDisplaySetMode
    #   func 1 = sceDisplaySetFrameBuf

    # Now the metadata also showed stub 0x08960D20 with NID 0xE47E40E4.
    # Let's check what syscall that is
    w1 = read32(data, 0x08960D20)
    w2 = read32(data, 0x08960D24)
    print(f"\n  Stub 0x08960D20: 0x{w1:08X} 0x{w2:08X}")
    if w1 == 0x03E00008:
        code = (w2 >> 6) & 0xFFFFF
        print(f"    -> syscall 0x{code:05X}")

    # Now let's find the sceDisplaySetFrameBuf calls and check their sync parameter
    print("\n\n=== sceDisplaySetFrameBuf callers (stub 0x08960D30, 3 callers) ===")
    # Callers: 0x08821ED8, 0x08821FA0, 0x08822490
    for caller in [0x08821ED8, 0x08821FA0, 0x08822490]:
        print(f"\n  Caller at 0x{caller:08X}:")
        show_context(data, caller, 12, 8)

    # sceDisplaySetFrameBuf(void *topaddr, int bufferwidth, int pixelformat, int sync)
    # sync parameter: 0 = immediate, 1 = wait for vblank
    # If sync=1, it effectively does a vsync wait

    # Let's also look for the main game loop
    # Search for a tight loop that calls sceDisplaySetFrameBuf
    # The pattern would be: ... jal sceDisplaySetFrameBuf ... j <loop_start>

    # Let's find all sceKernel thread management functions
    print("\n\n=== Finding sceKernelDelayThread and sleep functions ===")
    # Search PPSSPP metadata for ThreadManForUser entries
    for meta_addr, stub, nid, func_name, lib_name in metadata_entries:
        if "Delay" in func_name or "delay" in func_name.lower():
            print(f"  Found: {lib_name}::{func_name} at stub 0x{stub:08X}")
            # Find callers
            jal_word = 0x0C000000 | ((stub >> 2) & 0x03FFFFFF)
            for off in range(psp_to_offset(0x08800000), min(psp_to_offset(0x08C00000), len(data)), 4):
                w = struct.unpack_from("<I", data, off)[0]
                if w == jal_word:
                    c = offset_to_psp(off)
                    print(f"    Called from 0x{c:08X}")
                    show_context(data, c, 6, 6)
                    print()

    print("\nDone!")

if __name__ == "__main__":
    main()
