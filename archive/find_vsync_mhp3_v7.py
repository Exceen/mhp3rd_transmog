#!/usr/bin/env python3
"""
Find vsync in MHP3rd - v7 (FINAL)

Summary of findings:
- MHP3rd does NOT import sceDisplayWaitVblankStart
- It uses sceDisplaySetFrameBuf (NID 0x289D82FE) at stub 0x08960D30 with sync=1 for vsync
- There are 3 call sites for sceDisplaySetFrameBuf:
  1. 0x08821ED8 - in display init function at 0x08821E24 (sync=1 from $a3 set at 0x08821EA8)
  2. 0x08821FA0 - in another display function at 0x08821EF8 (sync=0, $a3 set at 0x08821F30)
  3. 0x08822490 - in swap buffer function at 0x08822464 (sync=1 from $a3 set at 0x0882247C)

The function at 0x08822458/0x08822464 is the per-frame swap buffer.
It's likely called via function pointer (jalr) since no JAL targets it.

For a speed hack, we can:
1. Change sync=1 to sync=0 at 0x0882247C: 0x24070001 -> 0x24070000
2. Also possibly at 0x08821EA8: 0x24070001 -> 0x24070000

Let's also check: is the function at 0x08822458 called via a function pointer stored somewhere?
And let's check the jump chain: 0x08822458 -> j 0x08822448 -> ...
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
    return struct.unpack_from("<I", data, psp_to_offset(psp_addr))[0]

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
    if op == 9:
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"addiu ${REGS[rt]}, ${REGS[rs]}, {imm}"
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

def show_range(data, start_addr, count):
    for i in range(count):
        addr = start_addr + i * 4
        off = psp_to_offset(addr)
        if 0 <= off < len(data) - 3:
            w = struct.unpack_from("<I", data, off)[0]
            print(f"    0x{addr:08X}: 0x{w:08X}  {decode(w, addr)}")

def main():
    print("Decompressing...")
    data = decompress_save_state(SAVE_STATE)

    # Let's look at the jump chain to 0x08822460
    # At 0x0882245C: j 0x08822448
    # Let's look at 0x08822440-0x08822460
    print("\n=== Jump chain before 0x08822460 ===")
    show_range(data, 0x08822420, 24)

    # Look at what's at 0x08822448
    print("\n=== Around 0x08822448 ===")
    show_range(data, 0x08822430, 16)

    # The function at 0x08822458 seems to have:
    # 0x08822458: lui $t1, 0x08A2
    # 0x0882245C: j 0x08822448
    # 0x08822460: lw $a0, 1704($t1)  <- delay slot of the j above!
    # Wait no, the j at 0x0882245C jumps to 0x08822448, and 0x08822460 is the delay slot.
    # So the code flow is:
    # 0x0882245C: j 0x08822448  (delay slot executes 0x08822460)
    # 0x08822460: lw $a0, 1704($t1) <- executes as delay slot
    # Then execution continues at 0x08822448
    #
    # But 0x08822464 is addiu $sp, $sp, -16 which is a function prologue.
    # This means 0x08822458 is an ENTRY POINT (perhaps reached via function pointer)
    # that does: lui $t1, 0x08A2 / j 0x08822448 (delay: lw $a0, 0x6A8($t1))
    # And then 0x08822448 leads into the swap buffer code.
    #
    # While 0x08822464 is a DIFFERENT entry point to the same function body.

    # Let's check 0x08822448
    print("\n=== Code at 0x08822448 ===")
    show_range(data, 0x08822440, 16)

    # Search for function pointer: address 0x08822458 stored in memory
    print("\n=== Searching for function pointer 0x08822458 in data ===")
    target_bytes = struct.pack("<I", 0x08822458)
    off = 0
    count = 0
    while count < 20:
        idx = data.find(target_bytes, off)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        print(f"  0x{psp_addr:08X}")
        off = idx + 1
        count += 1

    # Also search for 0x08822464
    print("\n=== Searching for function pointer 0x08822464 in data ===")
    target_bytes = struct.pack("<I", 0x08822464)
    off = 0
    count = 0
    while count < 20:
        idx = data.find(target_bytes, off)
        if idx == -1:
            break
        psp_addr = offset_to_psp(idx)
        print(f"  0x{psp_addr:08X}")
        off = idx + 1
        count += 1

    # Now for CWCheat format:
    # To change 0x0882247C from 0x24070001 to 0x24070000:
    # CW addr = 0x0882247C - 0x08800000 = 0x0002247C
    # CWCheat: _L 0x2002247C 0x24070000
    #
    # For the other site at 0x08821EA8:
    # CW addr = 0x08821EA8 - 0x08800000 = 0x00021EA8
    # CWCheat: _L 0x20021EA8 0x24070000
    #
    # But these might not be enough. The function at 0x08821E24 calls
    # sceDisplaySetMode first, then conditionally calls sceDisplaySetFrameBuf.
    # It might be the display initialization, not the per-frame swap.
    #
    # The per-frame swap is at 0x08822464/0x08822458, which has sync=1 at 0x0882247C.
    # This is the one to patch for a speed hack.

    print("\n\n========================================")
    print("SUMMARY OF FINDINGS")
    print("========================================")
    print()
    print("MHP3rd (ULJM05800) does NOT import sceDisplayWaitVblankStart.")
    print("Frame synchronization is done via sceDisplaySetFrameBuf with sync=1.")
    print()
    print("sceDisplaySetFrameBuf stub: 0x08960D30 (syscall 0x0E001)")
    print()
    print("Call sites for sceDisplaySetFrameBuf:")
    print("  1. 0x08821ED8 - display init/mode set function (sync=1)")
    print("  2. 0x08821FA0 - another display function (sync=0)")
    print("  3. 0x08822490 - per-frame swap buffer (sync=1) <-- MAIN VSYNC")
    print()
    print("The per-frame vsync wait is at 0x08822490 (jal sceDisplaySetFrameBuf)")
    print("The sync parameter is set at 0x0882247C: addiu $a3, $zero, 1")
    print()
    print("=== CWCheat codes for speed hack ===")
    print()
    print("Option A: Change sync from 1 to 0 (remove vblank wait in SetFrameBuf):")
    print("  _L 0x2002247C 0x24070000")
    print()
    print("Option B: NOP the sceDisplaySetFrameBuf call entirely:")
    print("  _L 0x20022490 0x00000000")
    print()
    print("Option C: NOP both the call and delay slot:")
    print("  _L 0x20022490 0x00000000")
    print("  _L 0x20022494 0x00000000")
    print()
    print("Note: Option A is preferred as it still updates the display,")
    print("      just without waiting for vblank.")
    print()

    # Also verify: let's confirm what the instruction at 0x08821EA8 does
    # 0x08821EA4: beq $v0, $t0, 0x08821ED0 (branch to SetFrameBuf call)
    # 0x08821EA8: addiu $a3, $zero, 1 (delay slot - sets sync=1)
    # This is in the branch delay slot, so it always executes.
    # If branch taken -> goes to 0x08821ED0 which does jal SetFrameBuf with sync=1
    # If branch not taken -> falls through to register restore and return

    # The function at 0x08821E24 is called with parameters that determine the display mode.
    # It calls sceDisplaySetMode first, then if condition met, calls sceDisplaySetFrameBuf.
    # This looks like the initial mode setup, not per-frame.

    # The function at 0x08821EF8 calls SetFrameBuf with sync=0 ($a3=0 from 0x08821F30)
    # This is a different path that does immediate framebuffer update.

    # So the ONLY per-frame vsync is at 0x08822490 via the swap buffer function.

    print("=== Verification: instruction at 0x0882247C ===")
    w = read32(data, 0x0882247C)
    print(f"  0x0882247C: 0x{w:08X} = {decode(w, 0x0882247C)}")
    assert w == 0x24070001, f"Expected 0x24070001, got 0x{w:08X}"
    print("  Confirmed: addiu $a3, $zero, 1 (sync = PSP_DISPLAY_SETBUF_NEXTFRAME)")
    print()
    print("CWCheat offset: 0x0882247C - 0x08800000 = 0x0002247C")
    print("CWCheat line:   _L 0x2002247C 0x24070000")

if __name__ == "__main__":
    main()
