#!/usr/bin/env python3
"""
Find sceDisplayWaitVblankStart in MHP3rd save state - v2
Broader search: find import stubs by looking for PPSSPP's syscall encoding
and also search for j+nop patterns across ALL memory.
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

def decode_instruction(word, addr):
    opcode = (word >> 26) & 0x3F
    if word == 0:
        return "nop"
    if opcode == 3:
        target = ((word & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
        return f"jal 0x{target:08X}"
    if opcode == 2:
        target = ((word & 0x03FFFFFF) << 2) | (addr & 0xF0000000)
        return f"j 0x{target:08X}"
    if opcode == 0:
        func = word & 0x3F
        if func == 0x08:
            rs = (word >> 21) & 0x1F
            regs = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']
            return f"jr ${regs[rs]}"
        if func == 0x0C:
            code = (word >> 6) & 0xFFFFF
            return f"syscall 0x{code:05X}"
    if opcode == 0x0F:
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        regs = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7','s0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']
        return f"lui ${regs[rt]}, 0x{imm:04X}"
    return f"op={opcode}"

def main():
    print("Decompressing...")
    data = decompress_save_state(SAVE_STATE)
    print(f"Decompressed: {len(data)} bytes")

    # Find where the actual code starts (first non-zero region after 0x08800000)
    print("\n=== Finding code start ===")
    base_off = psp_to_offset(0x08800000)
    first_code = None
    for off in range(base_off, min(base_off + 0x100000, len(data)), 4):
        word = struct.unpack_from("<I", data, off)[0]
        if word != 0:
            first_code = off
            psp_addr = offset_to_psp(off)
            print(f"  First non-zero at 0x{psp_addr:08X}")
            break

    # Show first 32 instructions from first code
    if first_code:
        print(f"\n=== First 32 instructions from 0x{offset_to_psp(first_code):08X} ===")
        for i in range(32):
            off = first_code + i * 4
            word = struct.unpack_from("<I", data, off)[0]
            addr = offset_to_psp(off)
            print(f"  0x{addr:08X}: 0x{word:08X}  {decode_instruction(word, addr)}")

    # Search the "sceDisplay" string location more carefully
    print("\n=== Examining around sceDisplay string at 0x08961748 ===")
    # The string "sceDisplay" at 0x08961748 could be part of the module's import table
    # Look before it for struct data
    str_off = psp_to_offset(0x08961748)
    print("  Bytes around the string:")
    for delta in range(-64, 80, 4):
        off = str_off + delta
        word = struct.unpack_from("<I", data, off)[0]
        addr = offset_to_psp(off)
        # Try to read as ascii too
        raw = data[off:off+4]
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        print(f"  0x{addr:08X}: 0x{word:08X}  {ascii_repr}")

    # PSP import tables have a specific format:
    # struct SceLibraryStubTable {
    #   char *name;        // pointer to library name string
    #   u16 version;       // version
    #   u16 attr;          // attributes
    #   u8 entrySize;      // size of each entry in words
    #   u8 varCount;       // number of variables
    #   u16 funcCount;     // number of functions
    #   u32 *nidTable;     // pointer to NID table
    #   u32 *stubTable;    // pointer to stub function table
    # };

    # Let's search for pointers TO the "sceDisplay" string address
    str_psp_addr = 0x08961748
    str_bytes = struct.pack("<I", str_psp_addr)
    print(f"\n=== Searching for pointers to 0x{str_psp_addr:08X} ===")
    pos = 0
    while True:
        idx = data.find(str_bytes, pos)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        print(f"  Found at 0x{psp_addr:08X} (offset 0x{idx:08X})")
        # Dump the struct around it
        struct_start = idx
        for delta in range(0, 32, 4):
            off = struct_start + delta
            word = struct.unpack_from("<I", data, off)[0]
            addr = offset_to_psp(off)
            print(f"    0x{addr:08X}: 0x{word:08X}")
        pos = idx + 1

    # Let's also search for all syscall instructions in the ENTIRE memory
    print("\n=== Searching for syscall instructions in 0x08800000-0x08A00000 ===")
    search_start = psp_to_offset(0x08800000)
    search_end = psp_to_offset(0x08A00000)
    search_end = min(search_end, len(data))
    syscalls = []
    for off in range(search_start, search_end, 4):
        word = struct.unpack_from("<I", data, off)[0]
        if (word & 0xFC00003F) == 0x0000000C and word != 0x0000000C:
            addr = offset_to_psp(off)
            code = (word >> 6) & 0xFFFFF
            syscalls.append((addr, code, word))
    print(f"  Found {len(syscalls)} syscall instructions")
    for addr, code, word in syscalls[:50]:
        print(f"    0x{addr:08X}: 0x{word:08X}  syscall 0x{code:05X}")

    # PPSSPP uses a different stub mechanism. Let me check:
    # In PPSSPP, HLE-replaced functions use special encoding.
    # The stubs might actually be "jr $ra / nop" pairs that got replaced,
    # or they could be jump instructions to PPSSPP's HLE handler.

    # Let's look for the "sceDisplay" references in high memory (0x0A...)
    print("\n=== Examining sceDisplay refs in high memory ===")
    for str_addr_psp in [0x0A206E7A, 0x0A206EA2]:
        off = psp_to_offset(str_addr_psp)
        end = data.find(b'\x00', off)
        s = data[off:end].decode('ascii', errors='replace')
        print(f"  0x{str_addr_psp:08X}: \"{s}\"")
        # Look around for more context
        for delta in range(-32, 64, 4):
            doff = off + delta
            if 0 <= doff < len(data) - 3:
                word = struct.unpack_from("<I", data, doff)[0]
                raw = data[doff:doff+4]
                ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
                print(f"    0x{offset_to_psp(doff):08X}: 0x{word:08X}  {ascii_repr}")

    # Let's try yet another approach: look for "sceDisplayWaitVblank" in ALL of memory
    print("\n=== Searching for 'WaitVblank' anywhere ===")
    search_bytes = b"WaitVblank"
    pos = 0
    while True:
        idx = data.find(search_bytes, pos)
        if idx == -1:
            break
        # find start of string
        start = idx
        while start > 0 and data[start-1] >= 0x20 and data[start-1] < 0x7F:
            start -= 1
        end = data.find(b'\x00', idx)
        if end == -1:
            end = idx + 50
        s = data[start:end].decode('ascii', errors='replace')
        psp_addr = offset_to_psp(start)
        print(f"  0x{psp_addr:08X}: \"{s}\"")
        pos = idx + 1

    # === APPROACH: Look at the sceDisplay string at 0x0A6AB980 ===
    print("\n=== Examining 0x0A6AB980 area (sceDisplay in high mem) ===")
    off = psp_to_offset(0x0A6AB980)
    # Show more context - this might be PPSSPP's internal module info
    for delta in range(-128, 256, 4):
        doff = off + delta
        if 0 <= doff < len(data) - 3:
            word = struct.unpack_from("<I", data, doff)[0]
            raw = data[doff:doff+4]
            ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
            addr = offset_to_psp(doff)
            if ascii_repr.replace('.', ''):  # has some printable chars
                print(f"    0x{addr:08X}: 0x{word:08X}  {ascii_repr}")

    print("\nDone!")

if __name__ == "__main__":
    main()
