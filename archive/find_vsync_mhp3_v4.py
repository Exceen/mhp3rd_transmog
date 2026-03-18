#!/usr/bin/env python3
"""
Find sceDisplayWaitVblankStart in MHP3rd - v4
The sceDisplay library has 2 function imports. We need to identify them.
From v3 output:
  NID table at 0x08961AD4, 2 functions (var_count=2, but that might be misread)
  Stubs at 0x08960D28

Actually let me re-examine the import table format more carefully.
The PSP SceLibraryStubTable is:
  +0: name_ptr (u32)
  +4: version(u8), flags/attr(u8), entry_size(u8), var_count(u8)  -- or similar packing
  +8: func_count(u16), var_count(u16) -- or nid_count, etc.
  ...

Let me just directly examine the NID table and correlate with PPSSPP source.
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

    # The import stub table entry structure (SceLibraryStubTable) for PSP:
    # struct {
    #   u32 name;         // +0: pointer to library name
    #   u16 version;      // +4: version
    #   u16 attribute;    // +6: attribute flags
    #   u8  entLen;       // +8: length of each entry (in u32 words)
    #   u8  varCount;     // +9: number of variable entries
    #   u16 funcCount;    // +10: number of function entries
    #   u32 *nidTable;    // +12: pointer to NID table
    #   u32 *stubTable;   // +16: pointer to stub table
    # };
    # Total: 20 bytes

    # From the raw dump at 0x08961428:
    #   +0:  0x08961748 = name ptr -> "sceDisplay"
    #   +4:  0x40010011 = version=0x0011, attribute=0x4001
    #   +8:  0x00020005 = entLen=0x00, varCount=0x02, funcCount=0x0005
    #                   Wait, that doesn't work. Let me read byte by byte.

    print("\n=== Raw bytes of sceDisplay import entry at 0x08961428 ===")
    base = 0x08961428
    for i in range(20):
        b = read8(data, base + i)
        print(f"  +{i:2d}: 0x{b:02X}")

    # Actually let me reconsider. The format is:
    # Offset  Size  Field
    # 0       4     name pointer
    # 4       2     version
    # 6       2     flags/attribute
    # 8       1     entry length (in words, typically 5)
    # 9       1     number of variables
    # 10      2     number of functions
    # 12      4     pointer to NID table
    # 16      4     pointer to stub table

    name_ptr = read32(data, base)
    version = read16(data, base + 4)
    attr = read16(data, base + 6)
    ent_len = read8(data, base + 8)
    var_count = read8(data, base + 9)
    func_count = read16(data, base + 10)
    nid_ptr = read32(data, base + 12)
    stub_ptr = read32(data, base + 16)

    name = read_string(data, name_ptr)
    print(f"\n  Name: {name}")
    print(f"  Version: 0x{version:04X}")
    print(f"  Attr: 0x{attr:04X}")
    print(f"  Entry length: {ent_len} words")
    print(f"  Var count: {var_count}")
    print(f"  Func count: {func_count}")
    print(f"  NID table: 0x{nid_ptr:08X}")
    print(f"  Stub table: 0x{stub_ptr:08X}")

    # The entry length = 5 means 5*4=20 bytes per entry, which is the standard
    # But wait, ent_len here shows 0x00. Let me check the format again.
    # Maybe the struct packing is different for newer firmware

    # Let me try different packing: maybe it's a compact format
    # version(u16) attr(u16) size_of_this_struct_in_words(u8) ???
    # Actually some sources say:
    # +0 name(u32) +4 flags(u16,u16) +8 counts(u8,u8,u16) +12 nid(u32) +16 stub(u32)
    # = 20 bytes exactly

    # From raw: +8=0x05, +9=0x00, +10-11=0x0002
    print(f"\n  Re-reading +8..+11:")
    print(f"    +8: 0x{read8(data, base+8):02X} (ent_len)")
    print(f"    +9: 0x{read8(data, base+9):02X} (var_count)")
    print(f"    +10-11: 0x{read16(data, base+10):04X} (func_count)")

    ent_len = read8(data, base + 8)
    var_count = read8(data, base + 9)
    func_count = read16(data, base + 10)

    print(f"\n  Corrected: entry_len={ent_len}, var_count={var_count}, func_count={func_count}")

    # Read NIDs
    print(f"\n=== sceDisplay NIDs (table at 0x{nid_ptr:08X}, {func_count} funcs) ===")
    for i in range(func_count + var_count):
        nid = read32(data, nid_ptr + i * 4)
        print(f"  [{i}] NID 0x{nid:08X}")

    # Read stubs
    print(f"\n=== sceDisplay stubs (table at 0x{stub_ptr:08X}) ===")
    # Each stub is 8 bytes (2 instructions) - standard PSP import stub
    for i in range(func_count):
        addr = stub_ptr + i * 8
        w1 = read32(data, addr)
        w2 = read32(data, addr + 4)
        print(f"  [{i}] 0x{addr:08X}: 0x{w1:08X} 0x{w2:08X}")
        # In PPSSPP, resolved stubs are: jr $ra (0x03E00008) + syscall N (0x00XX00YC)
        if w1 == 0x03E00008:
            # The second word encodes the syscall
            code = (w2 >> 6) & 0xFFFFF
            print(f"       -> jr $ra + syscall 0x{code:05X}")

    # Now let's figure out which NID is sceDisplayWaitVblankStart
    # MHP3rd uses firmware 6.xx. The NIDs are scrambled.
    # PPSSPP maps these internally. The NID 0x0E20F177 is known.
    # Let me check PPSSPP's sceDisplay module to understand the mapping.

    # From PPSSPP source, sceDisplay functions have these NIDs (original):
    # 0x0E20F177 -> sceDisplaySetMode  (wait, the raw says 0x289D82FE = sceDisplaySetMode?)
    # Actually, looking at the high memory area from v2:
    #   0x0A206E72: 0x08960D20 (close to stub area)
    #   0x0A206E76: 0xE47E40E4
    # Then "sceDisplay" at 0x0A206E7A
    # Then:
    #   0x0A206E9A: 0x08960D28 (= first stub!)
    #   0x0A206E9E: 0x0E20F177 (= first NID!)
    # This looks like PPSSPP's internal resolved import info.

    # Let me look at this PPSSPP metadata more carefully
    print("\n\n=== PPSSPP internal module info around 0x0A206E00 ===")
    # Each entry seems to be: stub_ptr(u32), nid(u32), name_ptr?, "sceXxx"
    # Let's scan the area for a pattern

    start = 0x0A206E00
    for off in range(0, 0x200, 4):
        addr = start + off
        try:
            word = read32(data, addr)
            raw = data[psp_to_offset(addr):psp_to_offset(addr)+4]
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            print(f"  0x{addr:08X}: 0x{word:08X}  {ascii_repr}")
        except:
            break

    # Let me try a different approach: look at what PPSSPP's syscall numbers map to
    # In PPSSPP, syscall numbers encode: module_num << 12 | func_index
    # Module 0x0E = sceDisplay (14 decimal)
    # So syscall 0x0E000 would be sceDisplay func 0, 0x0E001 = func 1, etc.

    # From the stubs we found:
    # stub 0x08960D28: syscall 0x0E000 -> module 0x0E, func 0
    # stub 0x08960D30: syscall 0x0E001 -> module 0x0E, func 1
    # Wait, let me recheck. The syscall encoding from v2 was:
    # 0x089609EC: 0x0018000C  syscall 0x06000
    # 0x089609F4: 0x0018004C  syscall 0x06001

    # Actually the sceDisplay stubs were at 0x08960D28 with:
    # 0x03E00008 0x0038000C -> syscall value = 0x0038000C
    # code = (0x0038000C >> 6) & 0xFFFFF = 0x0E0000
    # Hmm that's 0xE0000. Let me recalculate.
    # 0x0038000C: binary = 0000 0000 0011 1000 0000 0000 0000 1100
    # bits 6-25: (0x0038000C >> 6) & 0xFFFFF = 0x00380 >> ...
    # 0x0038000C >> 6 = 0x000E0000
    # & 0xFFFFF = 0xE0000 ... that's too large
    # Wait, syscall encoding: 0x{code_20bit}0C where code is in bits 6-25
    # 0x0038000C: bits 25-6 = 0x0038000C >> 6 = 0xE0000 ... no
    # Let me be more careful:
    # 0x0038000C in binary:
    # 0000 0000 0011 1000 0000 0000 0000 1100
    # bits 25-6: 00 0000 1110 0000 0000 0000 = 0x0E000? No...
    # bits [25:6] = bits 25 down to bit 6
    # bit 25 = 0, bit 24 = 0, bit 23 = 0, bit 22 = 0, bit 21 = 1, bit 20 = 1,
    # bit 19 = 1, bit 18 = 0, bit 17 = 0, bit 16 = 0, ...all zeros to bit 6
    # So code = 0b00001110_00000000_0000 = 0x0E000? Hmm
    # (0x0038000C >> 6) = 0x0038000C / 64 = 0xE0000 ... that's 917504
    # 0xE0000 & 0xFFFFF = 0xE0000
    # But module encoding is typically module_index * N + func_index
    # If code = 0xE0000, then module = 0xE0000 >> 12 = 0xE0 = 224? That's too high.
    # Or maybe: 0x0038000C >> 6 = let me calculate properly
    w2 = 0x0038000C
    code = (w2 >> 6) & 0xFFFFF
    print(f"\n  Syscall 0x{w2:08X}: code = 0x{code:05X}")
    # 0x0038000C = 3670028
    # >> 6 = 57344.1875 -> 57344 = 0xE000
    print(f"  0x0038000C >> 6 = {0x0038000C >> 6} = 0x{0x0038000C >> 6:X}")
    # 3670028 >> 6 = 57344 = 0xE000
    # So code = 0xE000, and module = 0xE000 >> ?
    # In PPSSPP: syscall number = module_index * 0x1000 + func_index (maybe)
    # 0xE000 / 0x1000 = 14 = 0xE -> sceDisplay is typically module 14?
    # func_index = 0xE000 & 0xFFF = 0

    # So the mapping might be:
    # syscall 0xE000 = sceDisplay func 0
    # syscall 0xE001 = sceDisplay func 1
    # etc.

    # Let's check what PPSSPP assigns to sceDisplayWaitVblankStart
    # In PPSSPP source (HLETables.cpp), sceDisplay functions are registered in order.
    # The typical order in PPSSPP's sceDisplay module:
    # Looking at PPSSPP source code sceDisplay.cpp, the functions are:
    # 0: sceDisplaySetMode (NID 0x0E20F177 in old firmware)
    # 1: sceDisplaySetFrameBuf (NID 0x289D82FE... wait that's SetMode)

    # Actually, let me just correlate via PPSSPP's metadata area we found

    print("\n=== Examining PPSSPP metadata for sceDisplay (around 0x0A206E7A) ===")
    # The pattern at 0x0A206E72 was:
    #   0x08960D20 (stub area, but 0x08960D20 is before our first stub 0x08960D28?)
    #   Wait, stubs are at 0x08960D28, 0x08960D30, 0x08960D38, 0x08960D40, 0x08960D48
    #   And there are TWO sceDisplay blocks in PPSSPP's metadata:
    #   Block 1 at ~0x0A206E72: stub 0x08960D20, NID 0xE47E40E4, "sceDisplay"
    #   Block 2 at ~0x0A206E9A: stub 0x08960D28, NID 0x0E20F177, "sceDisplay"

    # Let me scan the PPSSPP metadata area more broadly to find ALL display-related entries
    # Search for all occurrences of 0x08960D in the 0x0A2 range
    print("\n=== Scanning PPSSPP metadata for stub references ===")
    search_start = psp_to_offset(0x0A200000)
    search_end = psp_to_offset(0x0A210000)
    search_end = min(search_end, len(data))

    # The metadata entries seem to follow a fixed format. Let me look at more entries
    # Going from 0x0A206E50 to 0x0A207000
    print("\n=== Full dump 0x0A206E40 - 0x0A207040 ===")
    for off in range(0, 0x200, 4):
        addr = 0x0A206E40 + off
        try:
            word = read32(data, addr)
            raw = data[psp_to_offset(addr):psp_to_offset(addr)+4]
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            # Check if this could be a PSP address
            note = ""
            if 0x08960000 <= word <= 0x08970000:
                note = " <- stub area ptr"
            print(f"  0x{addr:08X}: 0x{word:08X}  {ascii_repr}{note}")
        except:
            break

    # From the earlier output, the PPSSPP metadata for each imported function seems to be
    # a 40-byte (0x28) record: stub_ptr, NID, then name "sceXxx"
    # Let me look at the pattern spacing

    # 0x0A206E72: stub 0x08960D20
    # 0x0A206E9A: stub 0x08960D28 (diff = 0x28 = 40!)
    # 0x0A206EC2: stub 0x08960D30 (diff = 0x28 = 40!)
    # So each metadata entry is 40 bytes!

    print("\n=== PPSSPP metadata entries (40-byte stride from 0x0A206E72) ===")
    # But the addresses aren't 4-byte aligned. Let me re-examine.
    # 0x0A206E72 is NOT 4-byte aligned. The data might be packed differently.
    # Let me look at the raw bytes

    base_addr = 0x0A206E60
    base_off = psp_to_offset(base_addr)
    raw_chunk = data[base_off:base_off+0x200]
    print(f"  Raw hex dump from 0x{base_addr:08X}:")
    for i in range(0, min(len(raw_chunk), 0x200), 16):
        hex_str = ' '.join(f'{raw_chunk[i+j]:02X}' for j in range(min(16, len(raw_chunk)-i)))
        asc_str = ''.join(chr(raw_chunk[i+j]) if 32 <= raw_chunk[i+j] < 127 else '.' for j in range(min(16, len(raw_chunk)-i)))
        print(f"  0x{base_addr+i:08X}: {hex_str:<48s}  {asc_str}")

    # Now let's look for sceDisplay entries with WaitVblank by checking ALL stubs that use
    # module 0xE syscalls
    print("\n\n=== All module 0xE (sceDisplay) syscalls ===")
    search_start = psp_to_offset(0x08960000)
    search_end = psp_to_offset(0x08970000)
    search_end = min(search_end, len(data))

    display_stubs = []
    for off in range(search_start, search_end, 4):
        word = struct.unpack_from("<I", data, off)[0]
        if (word & 0x3F) == 0x0C and word != 0x0000000C:  # syscall
            code = (word >> 6) & 0xFFFFF
            module = code >> 12
            if module == 0xE:  # sceDisplay module
                func_idx = code & 0xFFF
                addr = offset_to_psp(off)
                # The stub starts 4 bytes before (jr $ra is first)
                stub_addr = addr - 4
                prev_word = read32(data, stub_addr)
                display_stubs.append((stub_addr, func_idx, code))
                print(f"  0x{stub_addr:08X}: 0x{prev_word:08X} 0x{word:08X}  -> module 0xE func {func_idx}")

    # Now let's look up what func_idx maps to in PPSSPP
    # From PPSSPP source code (Core/HLE/sceDisplay.cpp), the function table:
    # The registration order determines the func_idx:
    # Looking at typical PPSSPP sceDisplay module registration, approximate order:
    # 0: sceDisplaySetMode
    # 1: sceDisplaySetFrameBuf
    # 2: sceDisplaySetFrameBufferInternal (or similar)
    # 3: sceDisplayGetFrameBuf
    # 4: sceDisplayGetVcount
    # 5: sceDisplayWaitVblank
    # 6: sceDisplayWaitVblankStart
    # 7: sceDisplayWaitVblankCB
    # 8: sceDisplayWaitVblankStartCB
    # 9: sceDisplayGetCurrentHcount
    # etc.
    # But the actual order depends on the PPSSPP version.

    # A simpler approach: let's find ALL jal instructions calling any sceDisplay stub
    # and examine their context
    print("\n\n=== Finding ALL callers of sceDisplay stubs ===")
    code_start = psp_to_offset(0x08800000)
    code_end = min(psp_to_offset(0x08C00000), len(data))

    for stub_addr, func_idx, code in display_stubs:
        jal_target = (stub_addr >> 2) & 0x03FFFFFF
        jal_word_1 = 0x0C000000 | jal_target
        # Also check jal to stub_addr+4 (the syscall instruction itself)
        # Actually, the JAL should target the stub which starts with jr $ra
        # But in PPSSPP, the stub is: jr $ra / syscall N
        # And callers do: jal <stub_addr>

        callers = []
        for off in range(code_start, code_end, 4):
            word = struct.unpack_from("<I", data, off)[0]
            if word == jal_word_1:
                callers.append(offset_to_psp(off))

        if callers:
            print(f"\n  Stub 0x{stub_addr:08X} (sceDisplay func {func_idx}): {len(callers)} caller(s)")
            for c in callers:
                print(f"    JAL at 0x{c:08X}")
                # Show context
                c_off = psp_to_offset(c)
                for delta in range(-4, 8):
                    ins_off = c_off + delta * 4
                    if 0 <= ins_off < len(data) - 3:
                        w = struct.unpack_from("<I", data, ins_off)[0]
                        ia = c + delta * 4
                        marker = "  <<<" if delta == 0 else ""
                        op = (w >> 26) & 0x3F
                        desc = ""
                        if w == 0: desc = "nop"
                        elif op == 3:
                            t = ((w & 0x03FFFFFF) << 2) | (ia & 0xF0000000)
                            desc = f"jal 0x{t:08X}"
                        elif op == 2:
                            t = ((w & 0x03FFFFFF) << 2) | (ia & 0xF0000000)
                            desc = f"j 0x{t:08X}"
                        print(f"      0x{ia:08X}: 0x{w:08X} {desc}{marker}")

    # Let me also check the PPSSPP log/metadata to find function names
    # Search for "WaitVblank" in the 0x0A region
    print("\n=== Search for 'Vblank' string in 0x0A000000-0x0B000000 ===")
    search_start = psp_to_offset(0x0A000000)
    search_end = min(psp_to_offset(0x0B000000), len(data))

    pos = search_start
    while pos < search_end:
        idx = data.find(b"Vblank", pos, search_end)
        if idx == -1:
            break
        # Find string boundaries
        start = idx
        while start > 0 and data[start-1] >= 0x20 and data[start-1] < 0x7F:
            start -= 1
        end = data.find(b'\x00', idx, idx + 100)
        if end == -1: end = idx + 50
        s = data[start:end].decode('ascii', errors='replace')
        print(f"  0x{offset_to_psp(start):08X}: \"{s}\"")
        pos = idx + 1

    print("\nDone!")

if __name__ == "__main__":
    main()
