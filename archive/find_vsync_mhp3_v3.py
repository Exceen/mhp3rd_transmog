#!/usr/bin/env python3
"""
Find sceDisplayWaitVblankStart in MHP3rd - v3
Decode the import table to find the exact stub address.
"""

import struct
import zstandard

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_RAM_BASE = 0x08000000

# Known NIDs for sceDisplay functions
KNOWN_NIDS = {
    0x984C27E7: "sceDisplayWaitVblankStart",
    0x46F186C3: "sceDisplayWaitVblank",
    0x9C6EAAD7: "sceDisplayGetVcount",
    0xDEA197D4: "sceDisplayGetMode",
    0xDBA6C4C4: "sceDisplayGetFramePerSec",
    0x289D82FE: "sceDisplaySetMode",
    0x7ED59BC4: "sceDisplaySetFrameBuf",
    0xEEDA2E54: "sceDisplayGetFrameBuf",
    0xB4F378FA: "sceDisplayIsForeground",
    0x36CDFADE: "sceDisplayWaitVblankCB",
    0x8EB9EC49: "sceDisplayWaitVblankStartCB",
}

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

def read16(data, psp_addr):
    off = psp_to_offset(psp_addr)
    return struct.unpack_from("<H", data, off)[0]

def read8(data, psp_addr):
    off = psp_to_offset(psp_addr)
    return data[off]

def read_string(data, psp_addr):
    off = psp_to_offset(psp_addr)
    end = data.find(b'\x00', off)
    return data[off:end].decode('ascii', errors='replace')

def main():
    print("Decompressing...")
    data = decompress_save_state(SAVE_STATE)
    print(f"Decompressed: {len(data)} bytes")

    # The import stub table entry for sceDisplay is at 0x08961428
    # PSP stub table format (per library):
    #   +0: name_ptr (u32)
    #   +4: flags/version (u32) - actually: version(u16), attr(u16)  -- but packed oddly
    #   Actually the format varies. Let me just parse what we see.
    #
    # From the output:
    #   0x08961428: 0x08961748  -> name ptr -> "sceDisplay"
    #   0x0896142C: 0x40010011  -> flags
    #   0x08961430: 0x00020005  -> varCount=0, funcCount=2 (or entrySize=5, varCount=0, funcCount=2)
    #   0x08961434: 0x08961AD4  -> NID table ptr
    #   0x08961438: 0x08960D28  -> stub table ptr

    # Let's parse all import entries. They seem to be at 0x08961400 area.
    # Each entry is 20 bytes (5 words) based on entrySize=5
    # Let's find the start of the import table

    # First, let's look at the struct we found
    print("\n=== Parsing sceDisplay import entry at 0x08961428 ===")
    name_ptr = read32(data, 0x08961428)
    flags = read32(data, 0x0896142C)
    size_counts = read32(data, 0x08961430)
    nid_ptr = read32(data, 0x08961434)
    stub_ptr = read32(data, 0x08961438)

    entry_size = (size_counts >> 24) & 0xFF
    var_count = (size_counts >> 16) & 0xFF
    func_count = size_counts & 0xFFFF

    name = read_string(data, name_ptr)
    print(f"  Name: {name} (ptr: 0x{name_ptr:08X})")
    print(f"  Flags: 0x{flags:08X}")
    print(f"  Entry size: {entry_size}, Var count: {var_count}, Func count: {func_count}")
    print(f"  NID table: 0x{nid_ptr:08X}")
    print(f"  Stub table: 0x{stub_ptr:08X}")

    # Read the NIDs and stubs
    print(f"\n  Functions:")
    for i in range(func_count):
        nid = read32(data, nid_ptr + i * 4)
        stub_addr = stub_ptr + i * 8  # Each stub is 2 instructions = 8 bytes
        # Read the stub instruction
        stub_word = read32(data, stub_addr)
        stub_word2 = read32(data, stub_addr + 4)
        nid_name = KNOWN_NIDS.get(nid, f"unknown_0x{nid:08X}")
        print(f"    [{i}] NID 0x{nid:08X} = {nid_name}")
        print(f"        Stub at 0x{stub_addr:08X}: 0x{stub_word:08X} 0x{stub_word2:08X}")

    # Now let's scan ALL import entries in the table
    # The entry before sceDisplay (at 0x08961428 - 20 = 0x08961414) should be another import
    print("\n\n=== Scanning all import table entries ===")
    # Let's find the table boundaries by scanning backwards and forwards
    # Each entry is entry_size*4 bytes. entry_size=5 -> 20 bytes

    # Scan backwards from 0x08961428
    addr = 0x08961428
    entries = []
    while True:
        name_ptr = read32(data, addr)
        # Check if this looks like a valid name pointer (in the string area)
        if 0x08960000 <= name_ptr <= 0x08970000:
            try:
                name = read_string(data, name_ptr)
                if name.startswith("sce") or name.startswith("Kd") or name.startswith("Io"):
                    entries.append(addr)
                    addr -= 20
                    continue
            except:
                pass
        break

    entries.reverse()

    # Scan forward from 0x08961428 + 20
    addr = 0x08961428 + 20
    while True:
        name_ptr = read32(data, addr)
        if 0x08960000 <= name_ptr <= 0x08970000:
            try:
                name = read_string(data, name_ptr)
                if name.startswith("sce") or name.startswith("Kd") or name.startswith("Io") or name.startswith("Util"):
                    entries.append(addr)
                    addr += 20
                    continue
            except:
                pass
        break

    # Add the sceDisplay entry if not already there
    if 0x08961428 not in entries:
        entries.append(0x08961428)
        entries.sort()

    vsync_stub_addr = None

    for entry_addr in entries:
        name_ptr = read32(data, entry_addr)
        flags = read32(data, entry_addr + 4)
        size_counts = read32(data, entry_addr + 8)
        nid_ptr = read32(data, entry_addr + 12)
        stub_ptr = read32(data, entry_addr + 16)

        entry_size = (size_counts >> 24) & 0xFF
        var_count = (size_counts >> 16) & 0xFF
        func_count = size_counts & 0xFFFF

        name = read_string(data, name_ptr)
        print(f"\n  Library: {name} (entry at 0x{entry_addr:08X})")
        print(f"    Func count: {func_count}, Var count: {var_count}")
        print(f"    NID table: 0x{nid_ptr:08X}, Stub table: 0x{stub_ptr:08X}")

        for i in range(func_count):
            nid = read32(data, nid_ptr + i * 4)
            stub_addr = stub_ptr + i * 8
            stub_word = read32(data, stub_addr)
            nid_name = KNOWN_NIDS.get(nid, f"0x{nid:08X}")
            print(f"    [{i}] NID 0x{nid:08X} ({nid_name}) -> stub 0x{stub_addr:08X}: 0x{stub_word:08X}")

            if nid in (0x984C27E7, 0x46F186C3, 0x36CDFADE, 0x8EB9EC49):
                vsync_stub_addr = stub_addr
                print(f"    *** VSYNC FUNCTION FOUND: stub at 0x{stub_addr:08X} ***")

    # Now find all JAL instructions that call the vsync stub
    if vsync_stub_addr:
        print(f"\n\n=== Searching for JAL to 0x{vsync_stub_addr:08X} ===")
        # Encode the JAL instruction
        jal_target = (vsync_stub_addr >> 2) & 0x03FFFFFF
        jal_word = 0x0C000000 | jal_target

        code_start = psp_to_offset(0x08800000)
        code_end = min(psp_to_offset(0x08C00000), len(data))

        callers = []
        for off in range(code_start, code_end, 4):
            word = struct.unpack_from("<I", data, off)[0]
            if word == jal_word:
                caller = offset_to_psp(off)
                callers.append(caller)

        print(f"  Found {len(callers)} JAL instructions calling vsync stub")
        for caller in callers:
            print(f"\n  Caller at 0x{caller:08X}:")
            # Show context
            caller_off = psp_to_offset(caller)
            for delta in range(-8, 12):
                ins_off = caller_off + delta * 4
                if 0 <= ins_off < len(data) - 3:
                    w = struct.unpack_from("<I", data, ins_off)[0]
                    ins_addr = caller + delta * 4
                    marker = "  <<<" if delta == 0 else ""
                    op = (w >> 26) & 0x3F
                    desc = ""
                    if w == 0:
                        desc = "nop"
                    elif op == 3:
                        t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                        desc = f"jal 0x{t:08X}"
                    elif op == 2:
                        t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                        desc = f"j 0x{t:08X}"
                    print(f"    0x{ins_addr:08X}: 0x{w:08X}  {desc}{marker}")

    # Also search for sceDisplayWaitVblank (without Start)
    print("\n\n=== Also checking all sceDisplay stubs for callers ===")
    # From the import table parse, collect all sceDisplay stubs
    nid_ptr_display = read32(data, 0x08961434)
    stub_ptr_display = read32(data, 0x08961438)
    func_count_display = read32(data, 0x08961430) & 0xFFFF

    for i in range(func_count_display):
        nid = read32(data, nid_ptr_display + i * 4)
        stub_addr = stub_ptr_display + i * 8
        nid_name = KNOWN_NIDS.get(nid, f"0x{nid:08X}")

        jal_target = (stub_addr >> 2) & 0x03FFFFFF
        jal_word = 0x0C000000 | jal_target

        code_start = psp_to_offset(0x08800000)
        code_end = min(psp_to_offset(0x08C00000), len(data))

        callers = []
        for off in range(code_start, code_end, 4):
            word = struct.unpack_from("<I", data, off)[0]
            if word == jal_word:
                callers.append(offset_to_psp(off))

        print(f"\n  {nid_name} (stub 0x{stub_addr:08X}): {len(callers)} callers")
        for c in callers:
            print(f"    0x{c:08X}")
            # Show a few lines of context
            c_off = psp_to_offset(c)
            for delta in range(-4, 6):
                ins_off = c_off + delta * 4
                if 0 <= ins_off < len(data) - 3:
                    w = struct.unpack_from("<I", data, ins_off)[0]
                    ins_addr = c + delta * 4
                    marker = "  <<<" if delta == 0 else ""
                    op = (w >> 26) & 0x3F
                    desc = ""
                    if w == 0:
                        desc = "nop"
                    elif op == 3:
                        t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                        desc = f"jal 0x{t:08X}"
                    elif op == 2:
                        t = ((w & 0x03FFFFFF) << 2) | (ins_addr & 0xF0000000)
                        desc = f"j 0x{t:08X}"
                    print(f"      0x{ins_addr:08X}: 0x{w:08X}  {desc}{marker}")

    print("\nDone!")

if __name__ == "__main__":
    main()
