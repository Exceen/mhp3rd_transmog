.psp
CAVE equ 0x089E1600

.createfile "transmog.bin", 0
.include "inplace.inc"

; weapon: stubs load the spare byte into t7 (same bytes as the original mod)
.word 0x088692D4, 0x24
.word 0x906F0051, 0x94A6004E, 0x90AF0051, 0x0A21A47F, 0x90A50076, 0x94A60002, 0x90AF0005, 0x0A21A47F, 0x90A50001

; cave block
.word CAVE, cave_end - cave_start
.headersize CAVE - orga()
cave_start:
wep:                                ; original mod routine (was at 0x08800200)
    slti    at, t7, 2
    bne     at, zero, @@go
    nop
    addiu   a2, t7, -2
    addiu   a3, t7, -2
@@go:
    j       0x0885C144
    ori     t7, zero, 5
smith1:                             ; was 0x08800440
    beq     t2, zero, @@s
    nop
    addu    t0, t2, zero
@@s:
    addiu   a1, t1, 12
    addu    v1, a1, zero
    j       0x09D0D0BC
    nop
smith2:                             ; was 0x0880045C
    beq     a0, zero, @@s
    nop
    addu    v1, a0, zero
@@s:
    addiu   a1, a1, 2
    j       0x09D0D134
    nop
install:                            ; was 0x09F00300; runs at the end of 0x088628xx, puts the menu hooks into the village overlay
    lui     t0, 0x09C5
    addiu   t0, t0, 0x7CA0
    lw      t1, 0(t0)
    lui     t0, 0x6262
    addiu   t0, t0, 0x6F6C
    bne     t0, t1, @@out
    nop
    lui     t0, 0x09D3
    addiu   t0, t0, 0x0F10
    lui     t1, (0x08000000 | ((input >> 2) & 0x03FFFFFF)) >> 16
    ori     t1, t1, (0x08000000 | ((input >> 2) & 0x03FFFFFF)) & 0xFFFF
    sw      zero, 4(t0)
    sw      t1, 0(t0)
    lui     t0, 0x09D1
    addiu   t0, t0, -12108
    lui     t1, (0x08000000 | ((smith1 >> 2) & 0x03FFFFFF)) >> 16
    ori     t1, t1, (0x08000000 | ((smith1 >> 2) & 0x03FFFFFF)) & 0xFFFF
    sw      zero, 4(t0)
    sw      t1, 0(t0)
    lui     t0, 0x09D1
    addiu   t0, t0, -11988
    lui     t1, (0x08000000 | ((smith2 >> 2) & 0x03FFFFFF)) >> 16
    ori     t1, t1, (0x08000000 | ((smith2 >> 2) & 0x03FFFFFF)) & 0xFFFF
    sw      t1, 0(t0)
@@out:
    jr      ra
    nop
input:                              ; was 0x08800900; Square in Arrange Equipment
    addu    s0, v0, zero
    andi    v0, v0, 0x8000
    beq     zero, v0, @@done
    nop
    addiu   sp, sp, -24
    sw      t0, 0(sp)
    sw      t1, 4(sp)
    sw      t2, 8(sp)
    sw      t3, 12(sp)
    sw      t4, 16(sp)
    sw      t5, 20(sp)
    lui     t0, 0x09E7
    addiu   t0, t0, -21662
    lui     t1, 0x09B5
    addiu   t1, t1, -27804
    lh      t2, 2(t0)
    sll     t3, t2, 3
    sll     t2, t2, 2
    addu    t2, t1, t2
    addu    t2, t3, t2
    lh      t3, 0(t0)
    sll     t4, t3, 3
    sll     t3, t3, 2
    addu    t3, t1, t3
    addu    t3, t4, t3
    lb      t4, 1(t2)
    lb      t5, 1(t3)
    bne     t4, t5, @@restore
    nop
    lh      t5, 2(t2)
    slti    at, t4, 5
    beq     at, zero, @@weapon
    nop
    sb      t5, 5(t3)
    j       @@clear
    nop
@@weapon:
    addiu   t5, t5, 2
    sb      t5, 5(t3)
@@clear:
    lui     t0, 0x09E7
    addiu   t0, t0, -21673
    sb      zero, 0(t0)
@@restore:
    lw      t0, 0(sp)
    lw      t1, 4(sp)
    lw      t2, 8(sp)
    lw      t3, 12(sp)
    lw      t4, 16(sp)
    lw      t5, 20(sp)
    addiu   sp, sp, 24
@@done:
    addu    v0, s0, zero
    andi    v0, v0, 0x4000
    j       0x09D30F18
    nop
cave_end:
.headersize 0 - orga()
hk:
; hooks
.word 0x08869298, 8
.word 0x0C000000 | ((CAVE >> 2) & 0x03FFFFFF), 0
.word 0x08869274, 8
.word 0x0C000000 | ((CAVE >> 2) & 0x03FFFFFF), 0
.word 0x088628BC, 4
.word 0x08000000 | ((install >> 2) & 0x03FFFFFF)
.word 0xFFFFFFFF, 0
.close
