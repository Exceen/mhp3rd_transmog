#!/usr/bin/env python3
"""
Find the vsync call in MHP3rd main loop - v6

Key findings so far:
- sceDisplaySetMode (NID 0x0E20F177) at stub 0x08960D28, called from 0x08821E8C and 0x088753CC
- sceDisplaySetFrameBuf (NID 0x289D82FE) at stub 0x08960D30, called from 0x08821ED8, 0x08821FA0, 0x08822490
  - At 0x08822490 and 0x08821EA8, $a3=1 (sync=VBLANK) is set before call

The sceDisplaySetFrameBuf with sync=1 acts as the vsync wait.
The main game loop is likely around 0x08821E00.
Let me also check what the stub at 0x08960D20 (unknown sceDisplay NID 0xE47E40E4, syscall 0x22000) is.
Syscall 0x22000 -> module 0x22 = not sceDisplay (that's 0xE). So module 0x22 is something else entirely.

The function at 0x08822460 seems to be the frame swap function: it calls sceDisplaySetFrameBuf with sync=1.
Let me find who calls 0x08822460 (the function entry).
"""

import struct
import zstandard

SAVE_STATE = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
HEADER_SIZE = 0xB0
MEM_OFFSET = 0x48
PSP_RAM_BASE = 0x08000000

REGS = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
        's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']

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
        if func == 0x25: return f"or ${REGS[rd]}, ${REGS[rs]}, ${REGS[rt]}"
        if func == 0x0C:
            code = (word >> 6) & 0xFFFFF
            return f"syscall 0x{code:05X}"
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
    if op == 0x25:  # lhu
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        if imm >= 0x8000: imm -= 0x10000
        return f"lhu ${REGS[rt]}, {imm}(${REGS[rs]})"
    if op == 6:  # blez
        rs = (word >> 21) & 0x1F
        offset = word & 0xFFFF
        if offset >= 0x8000: offset -= 0x10000
        target = addr + 4 + offset * 4
        return f"blez ${REGS[rs]}, 0x{target:08X}"
    if op == 7:  # bgtz
        rs = (word >> 21) & 0x1F
        offset = word & 0xFFFF
        if offset >= 0x8000: offset -= 0x10000
        target = addr + 4 + offset * 4
        return f"bgtz ${REGS[rs]}, 0x{target:08X}"
    if op == 0x0C:  # andi
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        imm = word & 0xFFFF
        return f"andi ${REGS[rt]}, ${REGS[rs]}, 0x{imm:04X}"
    return f"0x{word:08X}"

def show_range(data, start_addr, count):
    for i in range(count):
        addr = start_addr + i * 4
        off = psp_to_offset(addr)
        if 0 <= off < len(data) - 3:
            w = struct.unpack_from("<I", data, off)[0]
            print(f"    0x{addr:08X}: 0x{w:08X}  {decode(w, addr)}")

def find_jal_callers(data, target_addr, search_start=0x08800000, search_end=0x08C00000):
    """Find all JAL instructions calling target_addr."""
    jal_word = 0x0C000000 | ((target_addr >> 2) & 0x03FFFFFF)
    callers = []
    start_off = psp_to_offset(search_start)
    end_off = min(psp_to_offset(search_end), len(data))
    for off in range(start_off, end_off, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w == jal_word:
            callers.append(offset_to_psp(off))
    return callers

def main():
    print("Decompressing...")
    data = decompress_save_state(SAVE_STATE)

    # The function at 0x08822460 calls sceDisplaySetFrameBuf with sync=1
    # This is likely the "swap buffers" function. Let's find who calls it.
    print("\n=== Function at 0x08822460 (sceDisplaySetFrameBuf wrapper) ===")
    show_range(data, 0x08822460, 24)

    # Find callers of 0x08822460
    print("\n=== Callers of 0x08822460 ===")
    callers = find_jal_callers(data, 0x08822460)
    print(f"  Found {len(callers)} callers")
    for c in callers:
        print(f"\n  Caller at 0x{c:08X}:")
        show_range(data, c - 24, 20)

    # Let's also look at the larger display function around 0x08821E00
    # The sceDisplaySetMode (0x08960D28) is called from 0x08821E8C
    # and sceDisplaySetFrameBuf (0x08960D30) from 0x08821ED8
    # These are in the same function. Let's dump it.
    print("\n\n=== Display function around 0x08821D00-0x08822000 ===")
    show_range(data, 0x08821D00, 200)

    # Now let's check: maybe the frame rate is controlled by sceDisplaySetFrameBuf sync=1
    # OR maybe there's a sceKernelWaitEventFlag or semaphore-based vsync
    # Let me look at the main loop structure

    # The call at 0x088753CC to sceDisplaySetMode might be interesting too
    print("\n\n=== Function around 0x088753B0 ===")
    show_range(data, 0x088753A0, 40)

    # Now, to make a speed cheat, we need to NOP the vsync wait.
    # If the game uses sceDisplaySetFrameBuf with sync=1, changing sync to 0 would remove the wait.
    # The instruction `addiu $a3, $zero, 1` at 0x0882247C sets sync=1.
    # Changing it to `addiu $a3, $zero, 0` (or NOP) would make it immediate.

    # But there might also be other vsync waits. Let me look for sceDisplayWaitVblank
    # which might be imported by a loaded plugin/module

    # Check the function at 0x088753CC more - it calls sceDisplaySetMode then something else
    print("\n\n=== Around 0x088753B0 (sceDisplaySetMode caller) ===")
    show_range(data, 0x088753B0, 30)

    # Also check: sceGe function calls around the display code
    # sceGe_user contains sceGeDrawSync which the game might use for vsync
    # Let's look at stub 0x08960D10 (called right after sceDisplaySetMode at 0x088753D8)
    w1 = read32(data, 0x08960D10)
    w2 = read32(data, 0x08960D14)
    print(f"\n\nStub 0x08960D10: 0x{w1:08X} 0x{w2:08X}")
    if w1 == 0x03E00008:
        code = (w2 >> 6) & 0xFFFFF
        module = code >> 12
        func = code & 0xFFF
        print(f"  -> syscall 0x{code:05X} (module 0x{module:X} func {func})")

    # Let's check what module 0xB is (that's the sceGe module likely)
    # Stub 0x08960D10 is between sceGe_user entries (0x08960CC0-0x08960D20)

    # SUMMARY:
    # The vsync mechanism in MHP3rd is sceDisplaySetFrameBuf with sync=1 (4th param)
    # To make a speed hack, we need to either:
    # 1. Change the sync parameter from 1 to 0 at the call sites
    # 2. NOP the sceDisplaySetFrameBuf call entirely

    # The simplest approach: patch the `addiu $a3, $zero, 1` to `addiu $a3, $zero, 0`
    # at 0x0882247C (the function that wraps sceDisplaySetFrameBuf)
    # 0x24070001 -> 0x24070000

    # But also check: is there a sceDisplaySetFrameBuf call in the inner rendering loop
    # that does sync=1 on every frame?

    # Let me find what calls function 0x08821E00 area (the big display function with
    # both SetMode and SetFrameBuf)
    # The function seems to start around 0x08821D60 (look for stack frame setup)
    # Actually let me find the function entry by looking backward from 0x08821E8C
    # for addiu $sp, $sp, -N

    print("\n\n=== Looking for function entry before 0x08821E8C ===")
    addr = 0x08821E8C
    while addr > 0x08821C00:
        addr -= 4
        w = read32(data, addr)
        op = (w >> 26) & 0x3F
        if op == 9:  # addiu
            rt = (w >> 16) & 0x1F
            rs = (w >> 21) & 0x1F
            imm = w & 0xFFFF
            if imm >= 0x8000: imm -= 0x10000
            if rs == 29 and rt == 29 and imm < 0:  # addiu $sp, $sp, -N
                print(f"  Possible function entry at 0x{addr:08X}: {decode(w, addr)}")
                # Show the function
                show_range(data, addr, 80)
                break

    # Also let's look at the callers of the main display function
    # Actually, the code at 0x08821ED8 jumps to 0x08821EB0 after the SetFrameBuf call,
    # which restores registers and returns. So this looks like a tail call pattern.
    # The display function seems more like a dispatch/callback system.

    # The REAL question: which call site is in the main game loop?
    # 0x08822490 is in the function at 0x08822460, which is the simplest.
    # Let me find its callers.

    # Actually 0x08822460 loads $a0 from a fixed address (0x089706A8 area)
    # Let me find callers of this wrapper function
    print("\n\n=== Callers of 0x08822460 (swap buffer function) ===")
    # The function entry might be 0x08822460 (addiu $sp, $sp, -16 is at 0x08822464)
    # Wait, 0x08822460 is `lw $a0, 1704($t1)`. The addiu $sp is at 0x08822464.
    # So function entry is 0x08822464.
    # But there's a `lw $a0` before it. Actually 0x08822460 could be part of a prior instruction.
    # Let me check what's before it.
    show_range(data, 0x08822450, 8)

    # Hmm, the function entry is at 0x08822464 based on the stack setup.
    # But 0x08822460 has lw $a0 which loads the framebuffer address, and
    # 0x08822464 sets up the stack. This pattern suggests 0x08822460 is also an entry point
    # (some PSP functions don't set up stack immediately).

    # Let me search for jal to both 0x08822460 and 0x08822464
    for target in [0x08822460, 0x08822464]:
        callers = find_jal_callers(data, target)
        if callers:
            print(f"\n  Callers of 0x{target:08X}: {len(callers)}")
            for c in callers:
                print(f"    0x{c:08X}")
                show_range(data, c - 16, 12)

    # Let me also search for the main loop by looking for a pattern:
    # In MH games, the main loop typically:
    # 1. calls game logic
    # 2. calls rendering
    # 3. calls swap/vsync
    # 4. loops back

    # The 0x08821ED8 and 0x08821FA0 calls to SetFrameBuf are in a larger function
    # Let me understand that function better
    print("\n\n=== Full function containing SetFrameBuf calls (0x08821E00-0x08822000) ===")
    show_range(data, 0x08821E00, 128)

    print("\nDone!")

if __name__ == "__main__":
    main()
