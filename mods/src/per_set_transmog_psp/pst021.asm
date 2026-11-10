.psp
CODE      equ 0x089E1100      ; original mod code, unchanged (position independent), 0x424 bytes
COMMON    equ 0x089E1524
TRAMPS    equ 0x089E1790

.createfile "psp.bin", 0
; block 1: mod code (no start-up call)
.word CODE, 0x424
.incbin "code.bin"

; block 2: shared "make sure the sets file was read" routine, then continue into the mod
.word COMMON, common_end - common_start
.headersize COMMON - orga()
common_start:
    sw      t0, 0x44(sp)        ; t0 = entry index * 4 (set by trampoline)
    sw      ra, 0x04(sp)
    sw      v0, 0x08(sp)
    sw      v1, 0x0C(sp)
    sw      a0, 0x10(sp)
    sw      a1, 0x14(sp)
    sw      a2, 0x18(sp)
    sw      a3, 0x1C(sp)
    sw      t1, 0x20(sp)
    sw      t2, 0x24(sp)
    sw      t3, 0x28(sp)
    sw      t4, 0x2C(sp)
    sw      t5, 0x30(sp)
    sw      t6, 0x34(sp)
    sw      t7, 0x38(sp)
    sw      t8, 0x3C(sp)
    sw      t9, 0x40(sp)
    lui     t1, (loaded_flag >> 16) + ((loaded_flag >> 15) & 1)
    lbu     t2, (loaded_flag & 0xFFFF)(t1)
    bne     t2, zero, @@loaded
    ori     t2, zero, 1
    jal     CODE                ; mod's init: read TRANSMOG_SETSn.BIN for the current save slot
    sb      t2, (loaded_flag & 0xFFFF)(t1)
@@loaded:
    lw      ra, 0x04(sp)
    lw      v0, 0x08(sp)
    lw      v1, 0x0C(sp)
    lw      a0, 0x10(sp)
    lw      a1, 0x14(sp)
    lw      a2, 0x18(sp)
    lw      a3, 0x1C(sp)
    lw      t1, 0x20(sp)
    lw      t2, 0x24(sp)
    lw      t3, 0x28(sp)
    lw      t4, 0x2C(sp)
    lw      t5, 0x30(sp)
    lw      t6, 0x34(sp)
    lw      t7, 0x38(sp)
    lw      t8, 0x3C(sp)
    lw      t9, 0x40(sp)
    lw      at, 0x44(sp)
    lui     t0, (targets >> 16) + ((targets >> 15) & 1)
    addu    t0, t0, at
    lw      at, (targets & 0xFFFF)(t0)
    lw      t0, 0x00(sp)
    jr      at
    addiu   sp, sp, 0x48
common_end:
.headersize 0 - orga()
b3:
; block 3: trampolines, target table, flag
.word TRAMPS, tramps_end - tramps_start
.headersize TRAMPS - orga()
tramps_start:
tramp0:
    addiu   sp, sp, -0x48
    sw      t0, 0x00(sp)
    j       COMMON
    ori     t0, zero, 0
tramp1:
    addiu   sp, sp, -0x48
    sw      t0, 0x00(sp)
    j       COMMON
    ori     t0, zero, 4
tramp2:
    addiu   sp, sp, -0x48
    sw      t0, 0x00(sp)
    j       COMMON
    ori     t0, zero, 8
targets:
    .word CODE + 0x8C, CODE + 0x174, CODE + 0x1F0
loaded_flag:
    .word 0
tramps_end:
.headersize 0 - orga()
b4:
; hooks in the village overlay (same places as the 0.26 mod)
.word 0x09D2E320, 4
.word 0x08000000 | ((tramp0 >> 2) & 0x03FFFFFF)
.word 0x09D27888, 8
.word 0x08000000 | ((tramp1 >> 2) & 0x03FFFFFF), 0
.word 0x09D2EA68, 8
.word 0x0C000000 | ((tramp2 >> 2) & 0x03FFFFFF), 0
.close
