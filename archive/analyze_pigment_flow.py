#!/usr/bin/env python3
"""Analyze the get_pigment_flag function flow to understand why the patch doesn't work."""
import struct, zstandard

PPST = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/ULJM05800_1.02_0.ppst"
HEADER_SIZE = 0xB0
PSP_BASE = 0x08000000
STATE_OFFSET_BASE = 0x48

def psp_to_state(addr):
    return addr - PSP_BASE + STATE_OFFSET_BASE

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open(PPST, 'rb') as f:
    raw = f.read()
data = zstandard.ZstdDecompressor().decompress(raw[HEADER_SIZE:], max_output_size=64*1024*1024)

print("=== get_pigment_flag (0x0885C7BC) control flow ===\n")
print("Function takes $a1 = equipment slot data pointer")
print("  $a1+0: some field")
print("  $a1+1: equipment type byte (0-4=armor, 5-17=weapons)")
print("  $a1+2: equipment ID (halfword)")
print()
print("FLOW:")
print("  0x0885C7C8: lhu $v0, 2($a1)   → read equipment_id")
print("  0x0885C7CC: beq $v0, $zero → 0x0885C828   *** if no equipment, goto RETURN_0 ***")
print()
print("  0x0885C7D4: lbu $v1, 1($a1)   → read type byte")
print("  0x0885C7D8: addiu $v0, $v1, -5")
print("  0x0885C7DC: andi $v0, $v0, 0xFF")
print("  0x0885C7E0: sltiu $v0, $v0, 4  → true if type in [5,6,7,8]")
print("  0x0885C7E4: bne $v0, $zero → 0x0885C83C   *** if type 5-8, goto LOOKUP ***")
print()
print("  0x0885C7F0: beq type, 12 → 0x0885C83C     *** if DB, goto LOOKUP ***")
print("  0x0885C7FC: beq type, 13 → 0x0885C83C     *** if GL, goto LOOKUP ***")
print("  0x0885C808: beq type, 14 → 0x0885C83C     *** if SA(?), goto LOOKUP ***")
print("  0x0885C814: beq type, 16 → 0x0885C83C     *** if HH, goto LOOKUP ***")
print("  0x0885C820: beq type, 17 → 0x0885C83C     *** if Bow, goto LOOKUP ***")
print()
print("  *** FALL THROUGH for types 0-4 (ALL ARMOR), 9, 10, 11, 15 ***")
print()
print("RETURN_0 (0x0885C828):")
print("  0x0885C82C: addu $v0, $zero, $zero  → return 0")
print("  0x0885C834: jr $ra")
print()
print("LOOKUP (0x0885C83C):")
print("  0x0885C83C: jal 0x0885BE6C   → call equipment_entry_lookup")
print("  0x0885C844: lbu $v0, 0x13($v0)  → read pigment flag from entry+19  *** OUR PATCH ***")
print("  0x0885C850: jr $ra")
print()
print("=" * 60)
print("PROBLEM: Armor types 0-4 (CHEST, ARMS, WAIST, LEGS, HEAD)")
print("         NEVER reach the LOOKUP path at 0x0885C83C!")
print("         They always fall through to RETURN_0.")
print("         Our patch at 0x0885C844 only affects weapons.")
print("=" * 60)

# Verify type filtering
print("\n=== Type routing (simulated) ===")
type_names = {0:'CHEST', 1:'ARMS', 2:'WAIST', 3:'LEGS', 4:'HEAD',
              5:'GS', 6:'SNS', 7:'Lance', 8:'Hammer', 9:'LBG', 10:'HBG',
              11:'?11', 12:'LS', 13:'DB', 14:'GL', 15:'SA', 16:'HH', 17:'Bow'}
for t in range(18):
    v = (t - 5) & 0xFF
    if v < 4:
        path = "→ LOOKUP (branch at 0x0885C7E4)"
    elif t == 12 or t == 13 or t == 14 or t == 16 or t == 17:
        path = "→ LOOKUP (beq branch)"
    else:
        path = "→ RETURN_0 (fall through) *** ALWAYS RETURNS 0 ***"
    name = type_names.get(t, f'?{t}')
    print(f"  Type {t:2d} ({name:6s}): {path}")

# Proposed fix
print("\n=== PROPOSED FIX ===")
print("Option A: Patch the fallthrough return to return 1:")
print("  _L 0x2005C82C 0x24020001  ; addiu $v0, $zero, 1")
print("  (Also returns 1 for empty equipment slots - usually harmless)")
print()
print("Option B: Skip type check entirely, always do lookup + force result:")
print("  _L 0x2005C7D4 0x0A21720F  ; j 0x0885C83C (skip type checks)")
print("  _L 0x2005C7D8 0x00000000  ; nop (delay slot)")
print("  _L 0x2005C844 0x24020001  ; addiu $v0, $zero, 1 (force result)")
print()
print("Option C: Change sltiu range to include all types:")
print("  _L 0x2005C7E0 0x2C420100  ; sltiu $v0, $v0, 256 (always true)")
print("  _L 0x2005C844 0x24020001  ; force return 1")
