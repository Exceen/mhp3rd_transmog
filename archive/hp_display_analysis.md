# HP Display Cheat Analysis: MHFU v3.1+ and MHP3rd

## Table of Contents
1. [MHFU v3.1+ Full Disassembly](#mhfu-v31-full-disassembly)
2. [MHP3rd HP_Display Full Disassembly](#mhp3rd-hp_display-full-disassembly)
3. [Address Mapping Table](#address-mapping-table)
4. [MHP3rd Game-Specific Addresses](#mhp3rd-game-specific-addresses)
5. [MHP3rd Monster Entity Struct Layout](#mhp3rd-monster-entity-struct-layout)
6. [Architecture Comparison](#architecture-comparison)
7. [Plan for New Version](#plan-for-new-version)

---

## 1. MHFU v3.1+ Full Disassembly

### Memory Layout
- Code injection region: `0x09FF7DFC - 0x09FF8448`
- Register save area: `0x09FF7FE8 - 0x09FF7FFC`
- Data/strings: `0x09FF7E80 - 0x09FF7E94`, `0x09FF7F50 - 0x09FF7F58`, `0x09FF80DC - 0x09FF8130`
- Frame counter: `0x09FF814C` (1 byte, current monster index for detailed view)
- Sub-counter: `0x09FF814E` (1 byte, frame delay counter for cycling)

### CWCheat Control Lines (Part 1/11)

```
; Configurable parameters (written each frame by CWCheat engine):
0x09FF8060: addiu $a1, $zero, 0      ; Font color for simple list (0=white)
0x09FF80A8: slti $v0, $s0, 7         ; Max monster count for simple list (7)
0x09FF8384: li $a1, 0x7FFF           ; Font color for detailed single-monster view
0x09FF8390: lui $a1, 0x4080          ; Font size (float 4.0)
0x09FF8184: addiu $a1, $zero, 0      ; Font color for detailed view labels

; Toggle via L+Select / R+Select:
; Button address: 0x08B1C5DC (CW offset 0x0031C5DC)
_L 0xD031C5DC 0x00000101    ; IF buttons == 0x0101 (L+Select pressed)
_L 0x20041DD0 0x0A7FE000    ;   THEN hook: patch 0x08841DD0 with J 0x09FF8000
_L 0xD031C5DC 0x00000201    ; IF buttons == 0x0201 (R+Select pressed)
_L 0x20041DD0 0x0E209BC9    ;   THEN unhook: restore original JAL 0x08826F24

; Detailed view toggle (L+Select cycles through monsters):
_L 0xD031C5DC 0x00000101    ; IF L+Select
_L 0x217F80B4 0x0A7FE054    ;   Enable detailed view jump
_L 0xD031C5DC 0x00000140    ; IF L+R (both shoulders)
_L 0x217F80B4 0x00000000    ;   Disable detailed view (NOP the jump)
```

### Hook Point

```
; Original instruction at 0x08841DD0:
;   0x0E209BC9 = JAL 0x08826F24  (some game function called every frame during render)
;
; When activated, this becomes:
;   0x0A7FE000 = J 0x09FF8000    (jump to our code)
;
; Return point: 0x08841E30 (after our code finishes, jump back here)
```

### Subroutine: text_render_wrapper @ 0x09FF7DFC

```asm
; text_render_wrapper(a1=x_pos, a2=y_pos, t0=fmt_string, t1..t3=args)
; Sets up font position and calls game's sprintf+render function.
;
; The game's text render context is loaded from [0x08A5E278] (a global pointer).

0x09FF7DFC: lui $v0, 0x08A6                ;
0x09FF7E00: lw $a0, -0x1D88($v0)           ; $a0 = *(0x08A5E278) = text render context
0x09FF7E04: sh $a1, 0x120($a0)             ; context->x_pos = $a1
0x09FF7E08: sh $a2, 0x122($a0)             ; context->y_pos = $a2
0x09FF7E0C: move $a1, $t0                  ; $a1 = format string ptr
0x09FF7E10: move $a2, $t1                  ; $a2 = arg1 (vararg for sprintf)
0x09FF7E14: move $a3, $t2                  ; $a3 = arg2
0x09FF7E18: move $t0, $t3                  ; $t0 = arg3 (MIPS o32: stack/reg overflow)
0x09FF7E1C: j 0x08890E0C                   ; TAIL CALL: game's text_render(ctx, fmt, ...)
0x09FF7E20: nop                             ; branch delay slot
; (never returns here - tail call)

0x09FF7E24: jr $ra                          ; Alternate return (unused path)
0x09FF7E28: nop
```

### Subroutine: name_resolve @ 0x09FF7E50

```asm
; name_resolve(t2=value_to_check, t1=name_string_base_ptr)
; If t2 > 0: use format "%s:%3d" (numeric)
; If t2 <= 0: use format "%s:%s" with string "無効" (immune/invalid)
; Returns: t0=format_ptr, t2=name_string_ptr (for immune case)

0x09FF7E50: blez $t2, 0x09FF7E68           ; if value <= 0, goto immune path
0x09FF7E54: nop
; --- numeric path ---
0x09FF7E58: lui $t0, 0x09FF
0x09FF7E5C: ori $t0, $t0, 0x7E80           ; $t0 = 0x09FF7E80 -> "%s:%3d"
0x09FF7E60: jr $ra
0x09FF7E64: nop
; --- immune path ---
0x09FF7E68: lui $t0, 0x09FF
0x09FF7E6C: ori $t0, $t0, 0x7E88           ; $t0 = 0x09FF7E88 -> "%s:%s"
0x09FF7E70: lui $t2, 0x09FF
0x09FF7E74: ori $t2, $t2, 0x7E90           ; $t2 = 0x09FF7E90 -> "無効" (immune)
0x09FF7E78: jr $ra
0x09FF7E7C: nop
```

### Subroutine: get_monster_name @ 0x09FF7E98

```asm
; get_monster_name(a2=entity_type_id) -> a2=name_string_ptr
; Uses a two-level lookup:
;   1. Table at 0x089A9710: halfword lookup by type_id -> secondary index
;   2. Table at 0x089C7574: word pointers to name strings

0x09FF7E98: lui $v1, 0x089A
0x09FF7E9C: ori $v1, $v1, 0x9710           ; $v1 = 0x089A9710 (name index table)
0x09FF7EA0: sll $v0, $a2, 1                ; $v0 = type_id * 2 (halfword index)
0x09FF7EA4: addu $v1, $v1, $v0             ; $v1 = &table[type_id]
0x09FF7EA8: lhu $v0, 0($v1)                ; $v0 = table[type_id] (secondary index)
0x09FF7EAC: beq $v0, $zero, 0x09FF7EB8     ; if 0, use original type_id + 0x67
0x09FF7EB0: addiu $a2, $a2, 103            ; $a2 = type_id + 103 (fallback)
0x09FF7EB4: move $a2, $v0                  ; $a2 = secondary index (from table)
0x09FF7EB8: lui $v0, 0x089C
0x09FF7EBC: ori $v0, $v0, 0x7574           ; $v0 = 0x089C7574 (name string ptr table)
0x09FF7EC0: sll $a2, $a2, 2                ; $a2 *= 4 (word index)
0x09FF7EC4: addu $v1, $v0, $a2             ; $v1 = &name_ptrs[index]
0x09FF7EC8: lw $v1, 0($v1)                 ; $v1 = name_ptrs[index] (ptr to string)
0x09FF7ECC: jr $ra
0x09FF7ED0: addu $a2, $v0, $v1             ; $a2 = base + offset = final string ptr
```

### Main Entry Point @ 0x09FF8000

```asm
; Entry: hijacked from 0x08841DD0 (replaces JAL 0x08826F24)

0x09FF8000: jal 0x08826F24                 ; Call the ORIGINAL function we replaced
0x09FF8004: nop                             ; (delay slot)

; Save callee-saved registers to scratch area
0x09FF8008: lui $v0, 0x09FF
0x09FF800C: sw $s5, 0x7FFC($v0)            ; save $s5 to 0x09FF7FFC
0x09FF8010: sw $s4, 0x7FF8($v0)            ; save $s4
0x09FF8014: sw $s3, 0x7FF4($v0)            ; save $s3
0x09FF8018: sw $s2, 0x7FF0($v0)            ; save $s2
0x09FF801C: sw $s1, 0x7FEC($v0)            ; save $s1
0x09FF8020: sw $s0, 0x7FE8($v0)            ; save $s0

0x09FF8024: j 0x09FF8330                   ; Jump to "target lock display" section first
; (this displays the target-locked monster's HP at top of screen)
```

### Target Lock Display @ 0x09FF8330

```asm
; Displays HP of the currently-targeted (locked-on) monster

0x09FF8330: lui $v0, 0x09A4
0x09FF8334: ori $s2, $v0, 0xADC8           ; $s2 = 0x09A4ADC8 (entity pointer table)

; Set up font
0x09FF8338: lui $v0, 0x08A6
0x09FF833C: lw $a0, -0x1D88($v0)           ; $a0 = text render context
0x09FF8340: addiu $a1, $zero, 14            ; font size = 14
0x09FF8344: jal 0x088908A8                  ; call set_font_size(ctx, 14)
0x09FF8348: addiu $a2, $zero, 16            ; a2=16 (param for next call, in delay slot)
0x09FF834C: jal 0x088908F8                  ; call set_font_color_or_style(ctx, ...)
0x09FF8350: addiu $a1, $zero, 23            ; a1=23 (color/style param, delay slot)

; Load target monster pointer (entity_table[1] = first large monster = target)
0x09FF8354: lw $s3, 4($s2)                 ; $s3 = entity_table[1] (target monster)
0x09FF8358: beq $s3, $zero, 0x09FF837C     ; if null, skip
0x09FF835C: nop

; Read HP
0x09FF8360: lh $t1, 0x2E4($s3)             ; $t1 = current HP
0x09FF8364: lh $t2, 0x41E($s3)             ; $t2 = max HP
0x09FF8368: lui $v0, 0x09FF
0x09FF836C: ori $t0, $v0, 0x80E4           ; $t0 = "HP:%5d/%5d" format string
0x09FF8370: addiu $a2, $zero, 96            ; y=96
0x09FF8374: jal 0x09FF7DFC                  ; call text_render_wrapper(x=5, y=96, ...)
0x09FF8378: addiu $a1, $zero, 5             ; x=5 (delay slot)

0x09FF837C: j 0x09FF802C                   ; Continue to simple list display
0x09FF8380: nop
```

### Simple Monster List Display @ 0x09FF802C

```asm
; Iterates through entity table, displays all large monsters' HP
; Uses entity_table at 0x09C0D3C0

0x09FF802C: nop                             ; (padding)
0x09FF8030: li $s0, 0                       ; $s0 = monster index counter
0x09FF8034: li $s1, 0                       ; $s1 = Y offset accumulator

0x09FF8038: lui $v0, 0x09C0
0x09FF803C: ori $s2, $v0, 0xD3C0           ; $s2 = 0x09C0D3C0 (entity pointer table)

; --- Loop start ---
0x09FF8048: lui $v0, 0x08A6
0x09FF804C: lw $a0, -0x1D88($v0)           ; $a0 = text render context
0x09FF8050: addiu $a1, $zero, 12            ; font size = 12
0x09FF8054: jal 0x088908A8                  ; set_font_size(ctx, 12)
0x09FF8058: addiu $a2, $zero, 14            ; font style = 14
0x09FF805C: jal 0x088908F8                  ; set_font_style(ctx, color)
0x09FF8060: addiu $a1, $zero, 0             ; color = 0 (white) [CONFIGURABLE]

; Load monster pointer
0x09FF8064: sll $v0, $s0, 2                ; $v0 = index * 4
0x09FF8068: addu $v0, $s2, $v0             ; $v0 = &entity_table[index]
0x09FF806C: lw $s3, 0($v0)                 ; $s3 = entity_table[index]
0x09FF8070: beq $s3, $zero, 0x09FF80A8     ; if null, skip to next

; Get monster name
0x09FF8078: jal 0x09FF7E98                  ; call get_monster_name
0x09FF807C: lb $a2, 0x1E8($s3)             ; $a2 = entity_type_id (byte at +0x1E8)
0x09FF8080: move $t1, $a2                  ; $t1 = name string ptr (return value in $a2)

; Read HP values
0x09FF8084: lh $t2, 0x2E4($s3)             ; $t2 = current HP (signed 16-bit at +0x2E4)
0x09FF8088: lh $t3, 0x41E($s3)             ; $t3 = max HP (signed 16-bit at +0x41E)

; Prepare render call
0x09FF808C: lui $v0, 0x09FF
0x09FF8090: ori $t0, $v0, 0x7F50           ; $t0 = "%s:%d/%d" format
0x09FF8094: addiu $a2, $zero, 144           ; base_y = 144
0x09FF8098: addi $a1, $zero, 5              ; x = 5
0x09FF809C: jal 0x09FF7DFC                  ; call text_render_wrapper
0x09FF80A0: addu $a2, $a2, $s1             ; y = 144 + y_offset (delay slot)

0x09FF80A4: addiu $s1, $s1, 16             ; y_offset += 16 (line spacing)

; Loop control
0x09FF80A8: slti $v0, $s0, 7               ; max 7 monsters [CONFIGURABLE]
0x09FF80AC: bne $v0, $zero, 0x09FF8048     ; loop if index < 7
0x09FF80B0: addiu $s0, $s0, 1              ; index++ (delay slot)

; --- Branch point: detailed view or exit ---
0x09FF80B4: (DYNAMIC: NOP or J 0x09FF8150)  ; [CONFIGURABLE via CWCheat conditional]
; If NOP: skip to exit
; If J: enter detailed single-monster view
```

### Detailed Single-Monster View @ 0x09FF8150

```asm
; Shows detailed stats for one monster at a time, cycling through with L+Select

; Frame counter management (smooth cycling)
0x09FF8150: lui $v0, 0x0A00
0x09FF8154: lb $v1, -0x7EB4($v0)           ; $v1 = frame_counter at 0x09FF814C
0x09FF8158: andi $t0, $v1, 0x7F            ; $t0 = counter & 0x7F (mask off high bit)
0x09FF815C: slti $v1, $t0, 8               ; if counter < 8 (max monsters)
0x09FF8160: beql $v1, $zero, 0x09FF816C    ; if counter >= 8
0x09FF8164: sw $zero, -0x7EB4($v0)         ;   reset counter to 0
0x09FF8168: sb $t0, -0x7EB4($v0)           ; store masked counter

; Font setup for detailed view
0x09FF816C: lui $v0, 0x08A6
0x09FF8170: lw $a0, -0x1D88($v0)           ; text render context
0x09FF8174: addiu $a1, $zero, 14            ; font size = 14
0x09FF8178: jal 0x088908A8                  ; set_font_size
0x09FF817C: addiu $a2, $zero, 16            ; font style
0x09FF8180: jal 0x088908F8                  ; set_font_color
0x09FF8184: addiu $a1, $zero, 0             ; color = 0 [CONFIGURABLE]

; Load monster by counter index
0x09FF8188: sll $v0, $t0, 2                ; $v0 = counter * 4
0x09FF818C: addu $v0, $s2, $v0             ; $v0 = &entity_table[counter]
0x09FF8190: lw $s4, 0($v0)                 ; $s4 = entity pointer
0x09FF8194: beq $s4, $zero, 0x09FF82E8     ; if null, skip to button check

; Get monster name
0x09FF819C: jal 0x09FF7E98                  ; get_monster_name
0x09FF81A0: lb $a2, 0x1E8($s4)             ; entity_type_id

; Display name
0x09FF81A4: move $t1, $a2                  ; name string ptr
0x09FF81A8: lui $s5, 0x09FF
0x09FF81AC: ori $t0, $s5, 0x80DC           ; "%s" format
0x09FF81B0: addiu $a1, $zero, 336           ; x=336
0x09FF81B4: jal 0x09FF7DFC                  ; render name
0x09FF81B8: addiu $a2, $zero, 32            ; y=32

; Display HP
0x09FF81BC: addiu $a1, $zero, 352           ; x=352
0x09FF81C0: addiu $a2, $zero, 48            ; y=48
0x09FF81C4: lh $t1, 0x2E4($s4)             ; current HP
0x09FF81C8: lh $t2, 0x41E($s4)             ; max HP
0x09FF81CC: jal 0x09FF7DFC
0x09FF81D0: ori $t0, $s5, 0x80E4           ; "HP:%5d/%5d"

; Display Size
0x09FF81D4: addiu $a1, $zero, 416           ; x=416
0x09FF81D8: addiu $a2, $zero, 64            ; y=64
0x09FF81DC: lh $t1, 0x274($s4)             ; size value
0x09FF81E0: jal 0x09FF7DFC
0x09FF81E4: ori $t0, $s5, 0x80F0           ; "Siz:%3d%%"

; Display ATK multiplier (float at +0x380, multiply by 100.0)
0x09FF81E8: lw $a2, 0x380($s4)             ; load ATK float (raw bits)
0x09FF81EC: mtc1 $a2, $f0                  ; move to FPU
0x09FF81F0: lui $v1, 0x42C8                ; 100.0 in float
0x09FF81F4: mtc1 $v1, $f1
0x09FF81F8: mul.s $f0, $f0, $f1            ; ATK * 100
0x09FF81FC: lw $v0, 0x384($s4)             ; load DEF float
0x09FF8200: cvt.w.s $f0, $f0               ; convert to int
0x09FF8204: mfc1 $a2, $f0                  ; $a2 = ATK percentage
0x09FF8208: mtc1 $v0, $f0                  ; DEF float -> FPU
0x09FF820C: mul.s $f0, $f0, $f1            ; DEF * 100
0x09FF8210: cvt.w.s $f0, $f0
0x09FF8214: mfc1 $s1, $f0                  ; $s1 = DEF percentage

; Render ATK
0x09FF8218: move $t1, $a2
0x09FF821C: addiu $a1, $zero, 416
0x09FF8220: addiu $a2, $zero, 80
0x09FF8224: jal 0x09FF7DFC                  ; "ATK:%3d%%"
0x09FF8228: ori $t0, $s5, 0x80FC

; Render DEF
0x09FF822C: move $t1, $s1
0x09FF8230: addiu $a1, $zero, 416
0x09FF8234: addiu $a2, $zero, 96
0x09FF8238: jal 0x09FF7DFC                  ; "DEF:%3d%%"
0x09FF823C: ori $t0, $s5, 0x8108

; Status resistances (using name_resolve for immune check)
; Sleep resistance (+0x444)
0x09FF8240: lh $t2, 0x444($s4)             ; sleep tolerance current
0x09FF8244: jal 0x09FF7E50                  ; name_resolve (checks if immune)
0x09FF8248: ori $t1, $s5, 0x8114           ; name = "睡耐" (sleep resist)
0x09FF824C: addiu $a1, $zero, 416
0x09FF8250: jal 0x09FF7DFC
0x09FF8254: addiu $a2, $zero, 112           ; y=112

; Poison resistance (+0x450)
0x09FF8258: lh $t2, 0x450($s4)
0x09FF825C: jal 0x09FF7E50
0x09FF8260: ori $t1, $s5, 0x811C           ; "毒耐"
0x09FF8264: addiu $a1, $zero, 416
0x09FF8268: jal 0x09FF7DFC
0x09FF826C: addiu $a2, $zero, 128           ; y=128

; Paralysis resistance (+0x456)
0x09FF8270: lh $t2, 0x456($s4)
0x09FF8274: jal 0x09FF7E50
0x09FF8278: ori $t1, $s5, 0x8124           ; "麻耐"
0x09FF827C: addiu $a1, $zero, 416
0x09FF8280: jal 0x09FF7DFC
0x09FF8284: addiu $a2, $zero, 144           ; y=144

; Stun/KO resistance (+0x566)
0x09FF8288: lh $t2, 0x566($s4)
0x09FF828C: jal 0x09FF7E50
0x09FF8290: ori $t1, $s5, 0x812C           ; "気耐"
0x09FF8294: addiu $a1, $zero, 416
0x09FF8298: jal 0x09FF7DFC
0x09FF829C: addiu $a2, $zero, 160           ; y=160

0x09FF82A0: j 0x09FF82E0                   ; skip button handling, go to quest timer
```

### Button Cycling Logic @ 0x09FF82A8

```asm
; When entity is null, check if L+Select was pressed to cycle monster index

0x09FF82E8: lui $v0, 0x08B2                ; Load button state
0x09FF82EC: j 0x09FF82A8
0x09FF82F0: lh $v1, -0x3A24($v0)           ; $v1 = buttons at 0x08B1C5DC

0x09FF82A8: xori $v1, $v1, 0x0110          ; check for L+Select (0x0110)
0x09FF82AC: bne $v1, $zero, 0x09FF82D8     ; if not L+Select, skip
0x09FF82B0: lui $v0, 0x0A00

; Increment sub-counter
0x09FF82B4: lb $t0, -0x7EB2($v0)           ; sub_counter at 0x09FF814E
0x09FF82B8: addiu $t0, $t0, 1
0x09FF82BC: slti $v1, $t0, 8               ; if sub_counter < 8 (debounce delay)
0x09FF82C0: bnel $v1, $zero, 0x09FF82D8    ;   just store and skip
0x09FF82C4: sb $t0, -0x7EB2($v0)

; Sub-counter reached 8 -> advance monster index
0x09FF82C8: lb $v1, -0x7EB4($v0)           ; main counter at 0x09FF814C
0x09FF82CC: addiu $v1, $v1, 1              ; increment
0x09FF82D0: sb $v1, -0x7EB4($v0)           ; store
0x09FF82D4: sb $zero, -0x7EB2($v0)         ; reset sub-counter

0x09FF82D8: j 0x09FF80BC                   ; jump to register restore
```

### Quest Timer Display @ 0x09FF83B0 (and elemental resistances)

```asm
; Reached from 0x09FF82E0 after detailed view
; Displays quest timer values and elemental resistance data

0x09FF83B0-0x09FF83C0: nop padding

0x09FF83C4: lui $s5, 0x09FF

; Quest timer / hunter status values displayed at bottom of screen
; Each block: load halfword from monster struct, render with "%s:%3d" or "%s:%s"
; Offsets: +0x580, +0x588, +0x590, +0x598 (row 1 at y=240)
;          +0x5A0, +0x5A8, +0x5B0        (row 2 at y=256)

; Example for +0x580:
0x09FF83C8: addiu $a1, $zero, 117           ; x=117
0x09FF83CC: addiu $a2, $zero, 240           ; y=240
0x09FF83D0: lh $t1, 0x580($s4)             ; data value
0x09FF83D4: jal 0x09FF7DFC
0x09FF83D8: ori $t0, $s5, 0x7E83           ; format string (inside "%s:%3d\0")
; ... repeats for +0x588 (x=165), +0x590 (x=213), +0x598 (x=261)
; ... and +0x5A0 (x=117,y=256), +0x5A8 (x=165,y=256), +0x5B0 (x=213,y=256)
```

### Register Restore and Return @ 0x09FF80BC

```asm
0x09FF80BC: lui $v0, 0x09FF
0x09FF80C0: lw $s5, 0x7FFC($v0)
0x09FF80C4: lw $s4, 0x7FF8($v0)
0x09FF80C8: lw $s3, 0x7FF4($v0)
0x09FF80CC: lw $s2, 0x7FF0($v0)
0x09FF80D0: lw $s1, 0x7FEC($v0)
0x09FF80D4: j 0x08841E30                   ; Return to game code (after hook point)
0x09FF80D8: lw $s0, 0x7FE8($v0)            ; (delay slot: restore $s0)
```

### Format Strings

| Address | String | Used By |
|---------|--------|---------|
| 0x09FF7F50 | `%s:%d/%d` | Simple list: name + HP |
| 0x09FF7E80 | `%s:%3d` | Detailed view: resistance (numeric) |
| 0x09FF7E88 | `%s:%s` | Detailed view: resistance (immune) |
| 0x09FF7E90 | `無効` | "Immune" string |
| 0x09FF80DC | `%s` | Monster name display |
| 0x09FF80E0 | `%d` | Numeric display |
| 0x09FF80E4 | `HP:%5d/%5d` | Detailed HP display |
| 0x09FF80F0 | `Siz:%3d%%` | Size percentage |
| 0x09FF80FC | `ATK:%3d%%` | Attack multiplier |
| 0x09FF8108 | `DEF:%3d%%` | Defense multiplier |
| 0x09FF8114 | `睡耐` | Sleep resistance label |
| 0x09FF811C | `毒耐` | Poison resistance label |
| 0x09FF8124 | `麻耐` | Paralysis resistance label |
| 0x09FF812C | `気耐` | Stun/KO resistance label |

---

## 2. MHP3rd HP_Display Full Disassembly

### Memory Layout
- Code injection region: `0x08801000 - 0x08801A74`
- Register save area: `0x08801FE8 - 0x08801FFC`
- Data/strings: `0x08802000 - 0x0880206C`
- Display mode byte: `0x08800FFC` (byte, 0-5 = detail level)
- Debounce counter: `0x08800FFE` (byte)
- Font size byte: `0x08800FFA` (byte, written by CWCheat conditional)

### CWCheat Control Lines

```
; Guard condition: only run if in quest
_L 0xD1457C90 0x00005FA0    ; IF halfword at 0x09C57C90 != 0x5FA0: execute next line
_L 0x21563E0C 0x0A200400    ;   Write hook: 0x09D63E0C = J 0x08801000

; Toggle ON (L+Select = 0x0110):
_L 0xD033885C 0x00000310    ; IF buttons at 0x08B3885C == 0x0310
_L 0x2000101C 0x00000000    ;   NOP (disable skip -> enable display)

; Toggle OFF (R+Select = 0x0140):
_L 0xD033885C 0x00000340    ; IF buttons == 0x0340 (note: different button encoding than MHFU)
_L 0x2000101C 0x10000267    ;   B 0x088019BC (branch to exit -> disable display)

; Detailed view toggle (L+R = 0x0380? or similar):
_L 0xD033885C 0x00000380    ; IF L+R
_L 0x200010A0 0x10500007    ;   BEQ $v0,$s0,+7 (enable detail view path)
_L 0xD033885C 0x00000320    ; IF R+Start (or similar)
_L 0x200010A0 0x00000000    ;   NOP (disable detail view)

; Font size D-pad controls:
_L 0xD033885C 0x00000011    ; IF D-pad Up + something
_L 0x00000FFA 0x00000000    ;   font_size_byte = 0x00
_L 0xD033885C 0x00000041    ; IF D-pad Right + something
_L 0x00000FFA 0x00000002    ;   font_size_byte = 0x02
_L 0xD033885C 0x00000081    ; IF D-pad Down + something
_L 0x00000FFA 0x00000005    ;   font_size_byte = 0x05
_L 0xD033885C 0x00000021    ; IF D-pad Left + something
_L 0x00000FFA 0x0000000E    ;   font_size_byte = 0x0E
```

### Hook Point

```
; Original instruction at 0x09D63E0C:
;   (unknown - this is in the render pipeline, likely a JAL to some render function)
;
; When activated (via guard condition):
;   0x0A200400 = J 0x08801000  (jump to our code)
;
; Return point: 0x09D63A64 (the address we jump back to after our code)
; This is EARLIER than the hook, meaning the hook is at end-of-frame and we return
; to an earlier point (or it's a different return path).
```

### Main Entry Point @ 0x08801000

```asm
; Save registers
0x08801000: lui $v0, 0x0880
0x08801004: sw $s5, 0x1FFC($v0)            ; save $s5
0x08801008: sw $s4, 0x1FF8($v0)            ; save $s4
0x0880100C: sw $s3, 0x1FF4($v0)            ; save $s3
0x08801010: sw $s2, 0x1FF0($v0)            ; save $s2
0x08801014: sw $s1, 0x1FEC($v0)            ; save $s1
0x08801018: sw $s0, 0x1FE8($v0)            ; save $s0

; Toggle check - this instruction is dynamically patched:
0x0880101C: nop                             ; or B 0x088019BC (skip all if OFF)
;           When ON:  NOP (0x00000000) -> falls through to display code
;           When OFF: B 0x088019BC (0x10000267) -> jump to register restore

; Initialize counters
0x08801020: li $s0, 0                       ; monster index = 0
0x08801024: li $s1, 0                       ; Y offset = 0

; Load display mode / font size
0x08801028: lbu $s4, 0x0FFA($v0)           ; $s4 = font_size_byte from 0x08800FFA
0x0880102C: lui $s5, 0x0880                ; $s5 = base pointer (0x08800000)
```

### Font Setup + Monster Loop @ 0x08801030

```asm
; --- Loop start (iterates entity table) ---
0x08801030: lui $v0, 0x08A6                ; (note: $v0 = 0x08A60000 but NOT used to load)

; Font setup - uses $fp-relative addressing (different from MHFU!)
0x08801034: lw $a0, -0x60E8($fp)           ; $a0 = text render context (via $fp)
;            This loads from [$fp - 0x60E8] which points to same render context
;            MHFU used: *(0x08A5E278); MHP3rd uses $fp-relative

0x08801038: li $a1, 0x000E                 ; font size = 14
0x0880103C: jal 0x088E6FF0                 ; call set_font_size (MHP3rd address!)
0x08801040: li $a2, 0x000E                 ; font style = 14

; Entity table lookup
0x08801044: lui $v0, 0x09DA
0x08801048: ori $v0, $v0, 0x9860           ; $v0 = 0x09DA9860 (entity pointer table)
0x0880104C: sll $v1, $s0, 2                ; $v1 = index * 4
0x08801050: addu $v0, $v0, $v1             ; $v0 = &entity_table[index]
0x08801054: lw $s2, 0($v0)                 ; $s2 = entity pointer

0x08801058: beq $s2, $zero, 0x088010AC     ; if null, skip to loop control
```

### Name Resolution + Simple HP Display

```asm
; Get monster name (delay slot loads entity_type field)
0x08801060: jal 0x08801A58                  ; call get_monster_name_mhp3
0x08801064: lbu $t1, 0x62($s2)             ; $t1 = entity_type_id (byte at +0x62)

; (gap at 0x08801068-0x0880106C: not written = NOP)

; Load HP values
0x08801070: lh $t2, 0x246($s2)             ; $t2 = current HP (at +0x246)
0x08801074: lh $t3, 0x288($s2)             ; $t3 = max HP (at +0x288)

; Set up render call
0x08801078: li $a2, 0x0006                 ; x = 6
0x0880107C: li $a3, 0x0086                 ; base_y = 134
0x08801080: addu $a3, $a3, $s1             ; y = 134 + y_offset
0x08801084: move $a1, $s4                  ; $a1 = font_size

; Call text render
0x0880108C: jal 0x08801A00                  ; call text_render_wrapper_mhp3
0x08801090: ori $t0, $s5, 0x2000           ; $t0 = 0x08802000 -> "%s:%d/%d"

; Advance Y
0x08801094: addiu $s1, $s1, 14             ; y_offset += 14

; Detail view check (dynamically patched)
0x0880109C: lbu $v0, 0x0FFC($s5)           ; $v0 = display_mode from 0x08800FFC
; (gap = nop at 0x100)
0x088010A0: (DYNAMIC)                       ; BEQ $v0,$s0,+7 or NOP
;            When detail enabled: if display_mode == current_index, show details
;            When disabled: NOP, always skip detail view
```

### Loop Control

```asm
0x088010AC: slti $v0, $s0, 5               ; max 5 monsters (MHP3rd has fewer slots)
0x088010B0: bne $v0, $zero, 0x08801030     ; loop back
0x088010B4: addiu $s0, $s0, 1              ; index++

0x088010B8: j 0x08801950                   ; jump to button handler
```

### Detailed View @ 0x088010C0

```asm
; Entered when display_mode == current monster index

0x088010C0: move $a1, $s4                  ; font size

; Header: monster name + full stats
0x088010C4: li $a2, 0x0076                 ; x = 118
0x088010C8: li $a3, 0x0014                 ; y = 20
0x088010CC: ori $t0, $s5, 0x2009           ; format = "%s  HP:%d/%d STA:%d/%d Siz:%d%%"
0x088010D0: jal 0x08801A58                  ; get monster name
0x088010D4: lbu $t1, 0x62($s2)             ; entity_type_id

; Load all stats for header line
0x088010E4: lh $t2, 0x246($s2)             ; current HP (+0x246)
0x088010E8: lh $t3, 0x288($s2)             ; max HP (+0x288)
0x088010EC: lh $t4, 0xBC2($s2)             ; current stamina (+0xBC2)
0x088010F0: lh $t5, 0xBC0($s2)             ; max stamina (+0xBC0)
0x088010F4: lh $t6, 0x0D4($s2)             ; size (+0x0D4)
0x08801100: jal 0x08801A00                  ; render header line

; --- Status effect section ---
; Row: 毒 (poison) and 痺 (paralysis)
0x08801110: move $a1, $s4
0x08801114: li $a2, 0x0006                 ; x=6
0x08801118: li $a3, 0x00DA                 ; y=218
0x0880111C: ori $t0, $s5, 0x202A           ; "毒:%3d/%3d\n痺:%3d/%3d"
0x08801120: lh $t1, 0x23C($s2)             ; poison current (+0x23C)
0x08801124: lh $t2, 0x252($s2)             ; poison max (+0x252)
0x08801128: lh $t3, 0x25A($s2)             ; paralysis max (+0x25A)
0x0880112C: lh $t4, 0x258($s2)             ; paralysis current (+0x258)
0x08801130: jal 0x08801A00                  ; render

; Row: 眠 (sleep) and 絶 (exhaust/stun)
0x08801138: move $a1, $s4
0x0880113C: li $a2, 0x0006
0x08801140: li $a3, 0x00F6                 ; y=246
0x08801144: ori $t0, $s5, 0x2044           ; "眠:%3d/%3d\n絶:%3d/%3d"
0x08801148: lh $t1, 0x24E($s2)             ; sleep current (+0x24E)
0x0880114C: lh $t2, 0x24C($s2)             ; sleep max (+0x24C)
0x08801150: lh $t3, 0xC5C($s2)             ; exhaust current (+0xC5C)
0x08801154: lh $t4, 0xC5E($s2)             ; exhaust max (+0xC5E)
0x08801158: jal 0x08801A00                  ; render

; Body part HP sections (6 body parts, each showing current/max for 2 hitzone types)
; Body part 1: offsets +0xB32/+0xB34 and +0xB3A/+0xB3C
0x08801170: move $a1, $s4
0x08801174: li $a2, 0x0050                 ; x=80
0x08801178: li $a3, 0x00F6                 ; y=246
0x0880117C: ori $t0, $s5, 0x205E           ; "%4d/%d\r\n%4d/%d"
0x08801180: lh $t1, 0xB32($s2)             ; part1 hp_current_a
0x08801184: lh $t2, 0xB34($s2)             ; part1 hp_max_a
0x0880118C: lh $t3, 0xB3A($s2)             ; part1 hp_current_b
0x08801190: lh $t4, 0xB3C($s2)             ; part1 hp_max_b
0x08801198: jal 0x08801A00                  ; render

; Body part 2: +0xB42/+0xB44 and +0xB4A/+0xB4C (x=136)
; Body part 3: +0xB52/+0xB54 and +0xB5A/+0xB5C (x=192)
; Body part 4: +0xB62/+0xB64 and +0xB6A/+0xB6C (x=248)
; (all at y=246 with format "%4d/%d\r\n%4d/%d")
; ... [same pattern repeated for parts 2-4]
```

### Button Handler / Display Mode Cycling @ 0x08801948

```asm
; Jump here after monster loop completes (from 0x088010B8)
0x08801948: j 0x088010AC                   ; (used as re-entry for detail view continuation?)

; Button reading and mode cycling
0x08801950: lui $v0, 0x08B4
0x08801954: lhu $a0, -0x77A4($v0)          ; $a0 = buttons at 0x08B3885C
0x08801958: lui $v0, 0x0880
0x0880195C: ori $a1, $v0, 0x0FF0           ; $a1 = 0x08800FF0 (state struct base)

; Check for L+Select (0x0110)
0x08801960: xori $at, $a0, 0x0110
0x08801964: addiu $a3, $zero, -1            ; direction = -1 (previous)
0x08801968: beq $at, $zero, 0x08801978     ; if L+Select, goto adjust
0x0880196C: xori $at, $a0, 0x0140          ; (delay slot) check R+Select
0x08801970: bne $at, $zero, 0x088019BC     ; if neither, skip to exit
0x08801974: addiu $a3, $zero, 1             ; direction = +1 (next)

; Adjust display mode with debounce
0x08801978: lbu $a2, 14($a1)               ; debounce counter at [0x08800FFE]
0x0880197C: addi $a2, $a2, 1
0x08801980: slti $at, $a2, 6               ; if debounce < 6
0x08801984: bne $at, $zero, 0x088019B8     ;   just store counter, don't change mode

; Debounce expired -> change mode
0x0880198C: lb $a2, 12($a1)                ; display_mode at [0x08800FFC]
0x08801990: add $a2, $a2, $a3              ; mode += direction
0x08801994: bgez $a2, 0x088019A0           ; if mode >= 0, ok
0x0880199C: addiu $a2, $zero, 0            ; clamp to 0

0x088019A0: slti $at, $a2, 5               ; if mode < 5
0x088019A4: bne $at, $zero, 0x088019B0     ;   ok
0x088019AC: addiu $a2, $zero, 5            ; clamp to 5

0x088019B0: sb $a2, 12($a1)                ; store new mode at [0x08800FFC]
0x088019B4: addiu $a2, $zero, 0
0x088019B8: sb $a2, 14($a1)                ; store debounce counter at [0x08800FFE]
```

### Register Restore and Return

```asm
0x088019BC: lui $v0, 0x0880
0x088019C0: lw $s5, 0x1FFC($v0)
0x088019C4: lw $s4, 0x1FF8($v0)
0x088019C8: lw $s3, 0x1FF4($v0)
0x088019CC: lw $s2, 0x1FF0($v0)
0x088019D0: lw $s1, 0x1FEC($v0)
0x088019D4: lw $s0, 0x1FE8($v0)
0x088019D8: j 0x09D63A64                   ; Return to game code
```

### Subroutine: text_render_wrapper_mhp3 @ 0x08801A00

```asm
; text_render_wrapper(a1=font_size, a2=x, a3=y, t0=fmt, t1-t6=args)
; Sets position, font size, and tail-calls game's text render function.

0x08801A00: lw $a0, -0x60E8($fp)           ; $a0 = text render context (via $fp)
0x08801A08: sb $a1, 0x12E($a0)             ; context->font_size = $a1 (byte at +0x12E!)
0x08801A0C: sh $a2, 0x120($a0)             ; context->x_pos = $a2
0x08801A10: sh $a3, 0x122($a0)             ; context->y_pos = $a3
; Shift varargs into correct argument positions:
0x08801A14: move $a1, $t0                  ; format string
0x08801A18: move $a2, $t1                  ; arg1
0x08801A1C: move $a3, $t2                  ; arg2
0x08801A20: move $t0, $t3                  ; arg3
0x08801A24: move $t1, $t4                  ; arg4
0x08801A28: move $t2, $t5                  ; arg5
0x08801A2C: move $t3, $t6                  ; arg6
0x08801A30: j 0x088EAA64                   ; TAIL CALL: game text_render function
```

### Subroutine: get_monster_name_mhp3 @ 0x08801A58

```asm
; get_monster_name(t1=entity_type_id) -> t1=name_string_ptr
; Uses a single-level lookup table with offset calculation.

0x08801A58: lui $at, 0x08A3
0x08801A5C: ori $at, $at, 0x9F4C           ; $at = 0x08A39F4C (name pointer table base)
0x08801A60: addiu $v0, $t1, 382            ; $v0 = type_id + 382 (index bias)
0x08801A64: sll $v0, $v0, 2                ; $v0 *= 4 (word offset)
0x08801A68: addu $v0, $at, $v0             ; $v0 = &name_table[type_id + 382]
0x08801A6C: lw $v0, 0($v0)                 ; $v0 = name_table[type_id + 382] (offset)
0x08801A70: addu $t1, $v0, $at             ; $t1 = base + offset = name string ptr
0x08801A74: jr $ra
```

### Format Strings

| Address | String | Used By |
|---------|--------|---------|
| 0x08802000 | `%s:%d/%d` | Simple list: name + HP |
| 0x08802009 | `%s  HP:%d/%d STA:%d/%d Siz:%d%%` | Detailed header |
| 0x0880202A | `毒:%3d/%3d\r\n痺:%3d/%3d` | Poison + paralysis |
| 0x08802044 | `眠:%3d/%3d\r\n絶:%3d/%3d` | Sleep + exhaust/stun |
| 0x0880205E | `%4d/%d\r\n%4d/%d` | Body part HP |

---

## 3. Address Mapping Table

| Function/Data | MHFU Address | MHP3rd Address |
|---------------|-------------|----------------|
| **Hook point** | 0x08841DD0 | 0x09D63E0C |
| **Return address** | 0x08841E30 | 0x09D63A64 |
| **Original instruction at hook** | JAL 0x08826F24 | (unknown, overwritten) |
| **Text render context global** | *(0x08A5E278) | $fp - 0x60E8 (i.e. *(0x08A59F18) via lw $a0,-0x60E8($fp)) |
| **Text render context field: x** | +0x120 (halfword) | +0x120 (halfword) |
| **Text render context field: y** | +0x122 (halfword) | +0x122 (halfword) |
| **Text render context field: font_size** | (set via function call) | +0x12E (byte) |
| **set_font_size()** | 0x088908A8 | 0x088E6FF0 |
| **set_font_style/color()** | 0x088908F8 | (not used; direct byte write to +0x12E) |
| **text_render() (sprintf+draw)** | 0x08890E0C | 0x088EAA64 |
| **Entity pointer table (main)** | 0x09C0D3C0 | 0x09DA9860 |
| **Entity pointer table (target lock)** | 0x09A4ADC8 | (not implemented) |
| **Button input address** | 0x08B1C5DC | 0x08B3885C |
| **Name index table** | 0x089A9710 (two-level) | 0x08A39F4C (single-level, +382 bias) |
| **Name string base** | 0x089C7574 | 0x08A39F4C (same as table base) |
| **Code injection region** | 0x09FF7DFC-0x09FF8448 | 0x08801000-0x08801A74 |
| **Guard condition address** | N/A (always active) | 0x09C57C90 (check != 0x5FA0) |

---

## 4. MHP3rd Game-Specific Addresses

### Confirmed Working (from existing cheat)

| Address | Description |
|---------|-------------|
| `0x088E6FF0` | set_font_size(context, size) |
| `0x088EAA64` | text_render(context, fmt, ...) - the main sprintf+draw function |
| `$fp - 0x60E8` | Text render context pointer (equivalent to MHFU's global at 0x08A5E278) |
| `0x09DA9860` | Monster entity pointer table base (array of 5 pointers) |
| `0x08B3885C` | Button input register (halfword) |
| `0x09D63E0C` | Hook point in render pipeline |
| `0x09D63A64` | Return address after hook |
| `0x09C57C90` | Quest active flag (guard: != 0x5FA0 means in quest) |
| `0x08A39F4C` | Monster name lookup table base |
| `0x08801000-0x08802070` | Free memory region for code injection |

### Render Context Fields (at the struct pointed to by [$fp-0x60E8])

| Offset | Size | Description |
|--------|------|-------------|
| +0x120 | u16 | X position |
| +0x122 | u16 | Y position |
| +0x12E | u8 | Font size (MHP3rd-specific; MHFU uses function call instead) |

---

## 5. MHP3rd Monster Entity Struct Layout

Entity struct pointed to by entity_table[i] at 0x09DA9860.

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| +0x062 | u8 | Entity type ID | Identifies monster species. Used for name lookup. |
| +0x0D4 | s16 | Size | Size multiplier (percentage?) |
| +0x23C | s16 | Poison current | Current poison buildup/tolerance |
| +0x246 | s16 | HP current | Current health points |
| +0x24C | s16 | Sleep max | Sleep status threshold |
| +0x24E | s16 | Sleep current | Current sleep buildup |
| +0x252 | s16 | Poison max | Poison status threshold |
| +0x258 | s16 | Paralysis current | Current paralysis buildup |
| +0x25A | s16 | Paralysis max | Paralysis status threshold |
| +0x288 | s16 | HP max | Maximum health points |
| +0xB32 | s16 | Body part 1 HP current (type A) | Break/stagger HP |
| +0xB34 | s16 | Body part 1 HP max (type A) | |
| +0xB3A | s16 | Body part 1 HP current (type B) | |
| +0xB3C | s16 | Body part 1 HP max (type B) | |
| +0xB42 | s16 | Body part 2 HP current (type A) | |
| +0xB44 | s16 | Body part 2 HP max (type A) | |
| +0xB4A | s16 | Body part 2 HP current (type B) | |
| +0xB4C | s16 | Body part 2 HP max (type B) | |
| +0xB52 | s16 | Body part 3 HP current (type A) | |
| +0xB54 | s16 | Body part 3 HP max (type A) | |
| +0xB5A | s16 | Body part 3 HP current (type B) | |
| +0xB5C | s16 | Body part 3 HP max (type B) | |
| +0xB62 | s16 | Body part 4 HP current (type A) | |
| +0xB64 | s16 | Body part 4 HP max (type A) | |
| +0xB6A | s16 | Body part 4 HP current (type B) | |
| +0xB6C | s16 | Body part 4 HP max (type B) | |
| +0xBC0 | s16 | Stamina max | |
| +0xBC2 | s16 | Stamina current | |
| +0xC5C | s16 | Exhaust/stun current | |
| +0xC5E | s16 | Exhaust/stun max | |

### Comparison: MHFU Entity Struct

| Offset | Field | MHP3rd Equivalent |
|--------|-------|-------------------|
| +0x1E8 | Entity type ID (byte) | +0x062 |
| +0x274 | Size | +0x0D4 |
| +0x2E4 | HP current | +0x246 |
| +0x380 | ATK multiplier (float) | (not found in MHP3rd cheat) |
| +0x384 | DEF multiplier (float) | (not found in MHP3rd cheat) |
| +0x41E | HP max | +0x288 |
| +0x444 | Sleep tolerance | +0x24E (current), +0x24C (max) |
| +0x450 | Poison tolerance | +0x23C (current), +0x252 (max) |
| +0x456 | Paralysis tolerance | +0x258 (current), +0x25A (max) |
| +0x566 | Stun/KO tolerance | +0xC5C (current), +0xC5E (max) |

---

## 6. Architecture Comparison

### Key Differences

1. **Code injection region**:
   - MHFU uses high memory: 0x09FF7DFC (well above game data)
   - MHP3rd uses low memory: 0x08801000 (just above PSP base)

2. **Render context access**:
   - MHFU: Global pointer at fixed address `*(0x08A5E278)`
   - MHP3rd: Frame-pointer-relative `$fp - 0x60E8`

3. **Font control**:
   - MHFU: Two function calls (set_font_size + set_font_color)
   - MHP3rd: Direct byte write to context +0x12E for size, font size passed as parameter

4. **Text render function**:
   - MHFU: `0x08890E0C` - takes (ctx, fmt, varargs...)
   - MHP3rd: `0x088EAA64` - same signature but different address

5. **Entity table**:
   - MHFU: 7 entries at `0x09C0D3C0`, separate target-lock table at `0x09A4ADC8`
   - MHP3rd: 5 entries at `0x09DA9860`, no separate target-lock table

6. **Name resolution**:
   - MHFU: Two-level lookup (index table + pointer table)
   - MHP3rd: Single-level with bias (+382) then base+offset

7. **Entity struct**:
   - All field offsets are completely different between the two games
   - MHP3rd has separate current/max for status effects (paired s16)
   - MHFU stores status as single tolerance value
   - MHP3rd has body part HP data starting at +0xB32 (not present in MHFU's simple view)

8. **Toggle mechanism**:
   - MHFU: Patches the hook instruction itself (JAL vs J)
   - MHP3rd: Patches a branch instruction inside the code (NOP vs B-to-exit)

9. **Button encoding**:
   - MHFU buttons at 0x08B1C5DC: L+Select=0x0101, R+Select=0x0201
   - MHP3rd buttons at 0x08B3885C: L+Select=0x0110, R+Select=0x0140

---

## 7. Plan for New Version

The existing MHP3rd HP_Display cheat is already functional. To build an improved version (matching MHFU v3.1+ features), the following would be needed:

### Already Working
- Simple monster list with name + HP
- Detailed single-monster view with full stats
- Status effect display (poison, paralysis, sleep, exhaust)
- Body part HP display (6 parts)
- Button toggle (L+Select on, R+Select off)
- Display mode cycling (L+Select / R+Select to cycle monsters)
- Font size control (D-pad while holding select)
- Guard condition (only active in quest)

### Potential Improvements
1. **Target lock display**: MHFU shows the locked-on monster's HP separately at screen top. Would need to find MHP3rd's target-lock pointer (equivalent of 0x09A4ADC8).
2. **ATK/DEF multiplier display**: MHFU shows these as percentages from float fields. Need to find equivalent float fields in MHP3rd entity struct.
3. **Status immunity display**: MHFU has name_resolve that shows "無効" for immune statuses. The current MHP3rd version just shows raw values.
4. **Color coding**: MHFU configures font color per-section. MHP3rd could do the same via context byte writes.
5. **More body parts**: Current version shows 4 body parts. MHP3rd monsters can have more stagger zones.

### All Required Addresses (Summary)
All game-specific addresses needed are documented in sections 3 and 4 above. The existing cheat already uses all of them correctly. No additional address discovery is needed for the current feature set.
