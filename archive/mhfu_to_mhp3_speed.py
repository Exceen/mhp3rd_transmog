#!/usr/bin/env python3
"""
MHP3rd Speed Hack - Derived from reverse-engineering the MHFU working speed cheat.

METHODOLOGY:
============
1. Analyzed MHFU's working speed cheat which patches 0x088590BC
2. Found it modifies a VBLANK CALLBACK function registered via sceKernelRegisterSubIntrHandler
3. The callback counts vblanks and runs game logic every 2nd vblank
4. The cheat makes the counter jump to 65536, so game logic runs EVERY vblank = 2x speed
5. Found the identical mechanism in MHP3rd by tracing the same registration pattern

MHFU ANALYSIS:
==============
- Registration stub at 0x08859094 passes callback address 0x088590A8 to 0x08804678
- 0x08804678 calls sceKernelRegisterSubIntrHandler(0x1E, ...) for vblank interrupt
- Callback at 0x088590A8:
    counter = load(0x08A5DD18)
    counter += 1                    <-- PATCHED by speed cheat
    store(0x08A5DD18, counter)
    if counter < 2: set_flag(1); return
    if counter >= 2: reset_counter; call_game_update(); sceDisplayWaitVblankStart()

MHP3RD EQUIVALENT:
==================
- Registration stub at 0x088754F8 passes callback address 0x08875510 to 0x08804698
- 0x08804698 calls sceKernelRegisterSubIntrHandler(0x1E, ...) for vblank interrupt
- Callback at 0x08875510:
    counter = load(0x08AACEB0)      [lui $a2, 0x8AB; lw $v0, -0x3150($a2)]
    counter += 1                    <-- PATCH TARGET at 0x08875528
    store(0x08AACEB0, counter)
    if counter < 2: set_flag(1); return
    if counter >= 2: reset_counter; call_game_update(); sceDisplayWaitVblankStart()
"""

import struct
import os

# ============================================================================
# MHFU Reference (ULJM05500) - Known working
# ============================================================================
MHFU_CHEAT_1 = """
_C1 Speed Up [On=L+R+DpadRight/Off=L+R+DpadLeft]
_L 0xD031C5DC 0x00000320
_L 0x200590BC 0x3C040001
_L 0xD031C5DC 0x00000380
_L 0x200590BC 0x24840001
"""

MHFU_CHEAT_2 = """
_C0 Game SpeedUp
_L 0x1025DD18 0x00000001
"""

# ============================================================================
# MHP3rd (ULJM05800) - Derived speed cheats
# ============================================================================

# Key addresses
MHP3RD_CALLBACK_FUNC = 0x08875510   # Vblank callback function
MHP3RD_PATCH_ADDR    = 0x08875528   # addiu $a1, $v0, 1 instruction
MHP3RD_COUNTER_ADDR  = 0x08AACEB0   # Frame counter variable
MHP3RD_SLTI_ADDR     = 0x0887552C   # slti $v1, $a1, 2
MHP3RD_BRANCH_ADDR   = 0x08875534   # bnez $v1, skip_game_logic

# Original instructions
ORIG_ADDIU = 0x24450001   # addiu $a1, $v0, 1
ORIG_SLTI  = 0x28A30002   # slti $v1, $a1, 2

# Patched instructions
PATCH_LUI  = 0x3C050001   # lui $a1, 0x0001 ($a1 = 65536, always >= 2)


def psp_to_cwcheat_offset(psp_addr):
    """Convert PSP address to CWCheat offset."""
    return psp_addr - 0x08800000


def generate_cheats():
    """Generate all speed hack CWCheat codes for MHP3rd."""

    cw_patch = psp_to_cwcheat_offset(MHP3RD_PATCH_ADDR)
    cw_counter = psp_to_cwcheat_offset(MHP3RD_COUNTER_ADDR)
    cw_slti = psp_to_cwcheat_offset(MHP3RD_SLTI_ADDR)
    cw_branch = psp_to_cwcheat_offset(MHP3RD_BRANCH_ADDR)

    cheats = []

    # Approach 1: Code patch (exact equivalent of MHFU cheat #1)
    # Replace "addiu $a1, $v0, 1" with "lui $a1, 0x0001"
    # This makes the counter value 65536 which always passes the >= 2 check
    cheats.append({
        'name': 'Approach 1: Code Patch (toggle)',
        'description': 'Replaces counter increment with lui to force counter=65536. Toggle with L+R+DpadRight/Left.',
        'psp_addr': MHP3RD_PATCH_ADDR,
        'original': ORIG_ADDIU,
        'patched': PATCH_LUI,
        'code': f"""_C1 Speed Up [On=L+R+DpadRight/Off=L+R+DpadLeft]
_L 0xD031C5DC 0x00000320
_L 0x2{cw_patch:07X} 0x{PATCH_LUI:08X}
_L 0xD031C5DC 0x00000380
_L 0x2{cw_patch:07X} 0x{ORIG_ADDIU:08X}"""
    })

    # Approach 1b: Always-on code patch
    cheats.append({
        'name': 'Approach 1b: Code Patch (always on)',
        'description': 'Same as Approach 1 but always active.',
        'psp_addr': MHP3RD_PATCH_ADDR,
        'original': ORIG_ADDIU,
        'patched': PATCH_LUI,
        'code': f"""_C0 Speed Up (2x)
_L 0x2{cw_patch:07X} 0x{PATCH_LUI:08X}"""
    })

    # Approach 2: Data write (exact equivalent of MHFU cheat #2)
    # Continuously write 1 to the frame counter
    # Each frame: counter=1, callback increments to 2, passes threshold check
    cheats.append({
        'name': 'Approach 2: Data Write',
        'description': 'Writes 1 to counter each frame. Counter becomes 2 on next vblank, always triggers.',
        'psp_addr': MHP3RD_COUNTER_ADDR,
        'original': 'variable (counter)',
        'patched': '0x0001 (halfword)',
        'code': f"""_C0 Game SpeedUp
_L 0x1{cw_counter:07X} 0x00000001"""
    })

    # Approach 3: NOP the skip branch
    # The bnez branches to the "skip game logic" path when counter < 2
    # NOPing it means game logic always runs
    cheats.append({
        'name': 'Approach 3: NOP Branch',
        'description': 'NOPs the branch that skips game logic when counter < 2.',
        'psp_addr': MHP3RD_BRANCH_ADDR,
        'original': 0x14600005,  # bnez
        'patched': 0x00000000,
        'code': f"""_C0 Speed Up (NOP branch)
_L 0x2{cw_branch:07X} 0x00000000"""
    })

    # Approach 4: Lower the threshold
    # Change slti $v1, $a1, 2 -> slti $v1, $a1, 1
    # Counter goes 0->1 which is >= 1, so triggers every vblank
    cheats.append({
        'name': 'Approach 4: Lower Threshold',
        'description': 'Changes threshold from 2 to 1 in slti comparison.',
        'psp_addr': MHP3RD_SLTI_ADDR,
        'original': ORIG_SLTI,
        'patched': 0x28A30001,
        'code': f"""_C0 Speed Up (threshold=1)
_L 0x2{cw_slti:07X} 0x28A30001"""
    })

    return cheats


def verify_with_save_state(state_path):
    """Verify instructions match expected values in a save state."""
    import zstd

    with open(state_path, 'rb') as f:
        data = f.read()

    decompressed = zstd.decompress(data[0xB0:])

    checks = [
        (MHP3RD_PATCH_ADDR, ORIG_ADDIU, "addiu $a1, $v0, 1"),
        (MHP3RD_SLTI_ADDR, ORIG_SLTI, "slti $v1, $a1, 2"),
    ]

    all_ok = True
    for psp_addr, expected, desc in checks:
        off = psp_addr - 0x08000000 + 0x48
        actual = struct.unpack_from('<I', decompressed, off)[0]
        ok = actual == expected
        status = "OK" if ok else "MISMATCH"
        print(f"  [{status}] 0x{psp_addr:08X}: 0x{actual:08X} (expected 0x{expected:08X} = {desc})")
        if not ok:
            all_ok = False

    # Also show counter value
    off = MHP3RD_COUNTER_ADDR - 0x08000000 + 0x48
    counter = struct.unpack_from('<I', decompressed, off)[0]
    print(f"  [INFO] Counter at 0x{MHP3RD_COUNTER_ADDR:08X}: {counter}")

    return all_ok


def write_cheat_file(cheats, output_path):
    """Write cheats to a CWCheat INI file."""
    with open(output_path, 'w') as f:
        f.write("_S ULJM-05800\n")
        f.write("_G Monster Hunter Portable 3rd\n")
        for cheat in cheats:
            f.write(f"\n// {cheat['name']}: {cheat['description']}\n")
            f.write(cheat['code'] + "\n")


if __name__ == '__main__':
    print("=" * 70)
    print("MHP3rd Speed Hack Generator")
    print("Derived from MHFU (ULJM05500) working speed cheat analysis")
    print("=" * 70)
    print()

    # Generate cheats
    cheats = generate_cheats()

    for cheat in cheats:
        print(f"--- {cheat['name']} ---")
        print(f"Description: {cheat['description']}")
        print(f"PSP Address: 0x{cheat['psp_addr']:08X}")
        orig = cheat['original']
        patched = cheat['patched']
        orig_str = orig if isinstance(orig, str) else f'0x{orig:08X}'
        patch_str = patched if isinstance(patched, str) else f'0x{patched:08X}'
        print(f"Original:    {orig_str}")
        print(f"Patched:     {patch_str}")
        print(f"CWCheat:")
        for line in cheat['code'].strip().split('\n'):
            print(f"  {line}")
        print()

    # Verify against save state if available
    state_path = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_2.ppst"
    if os.path.exists(state_path):
        print("=" * 70)
        print("Verification against save state")
        print("=" * 70)
        try:
            ok = verify_with_save_state(state_path)
            print(f"\nVerification: {'PASSED' if ok else 'FAILED'}")
        except Exception as e:
            print(f"  Error: {e}")

    # Write cheat file
    print()
    print("=" * 70)
    print("RECOMMENDED: Use Approach 1 (toggle) first.")
    print("This is the exact equivalent of the proven MHFU speed cheat.")
    print("=" * 70)

    # Write to PPSSPP cheat file
    ppsspp_cheat = "/Users/Exceen/Documents/PPSSPP/PSP/Cheats/ULJM05800.ini"

    print(f"\nReady to write cheats to: {ppsspp_cheat}")
    print("Codes to add:")
    print()

    # Print the recommended toggle cheat
    print(cheats[0]['code'])
    print()
    print("Alternative (data write, simpler):")
    print(cheats[2]['code'])
