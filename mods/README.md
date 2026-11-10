# Transmog mods for real PSP (mod loader 0.21)

Repackaged builds of two mods by [Kurogami2134](https://github.com/Kurogami2134) so that they run on real PSP hardware with the mhp3reload mod manager **0.21**:

- `transmog_psp` — "Transmog": change the look of a weapon or armor piece from the item box.
- `per_set_transmog_psp` — "Per Set Transmog": remembers the looks per saved equipment set.

The mod code is Kurogami's. Only the placement in memory and the way the code is loaded were changed (see "What was changed"). These files are not covered by this repository's license.

## Why

The original 0.21 Transmog mod places its code in low memory (`0x08800200`–`0x088009D0`, `0x09F00300`). That area is not safe on real hardware and is also used by other cheat codes. The current versions of both mods are built for mod loader 0.26, which did not work on the test PSP.

## Install

1. Copy `transmog_psp` and `per_set_transmog_psp` into the `MODS` folder of the 0.21 mod manager.
2. Remove or disable the original "Transmog" mod.
3. Enable "Transmog (PSP safe)" and, if wanted, "Per Set Transmog (PSP safe)", then apply.

"Per Set Transmog" needs "Transmog" and `file_replacer`.

## Usage

- In your house, open the item box and choose **Arrange Equipment**.
- Pick up the piece whose look you want (confirm button).
- Move to the piece that should get that look and press **Square** instead of confirm.
- Both pieces must be the same armor slot or the same weapon class. There is no message or sound.
- The look shows after the piece is equipped again.
- Applying a piece to itself restores its normal look.

With "Per Set Transmog", the looks of the six pieces are stored when you save an equipment set and put back when you equip that set.

## Online

Compatible with the original mods on mod loader 0.26. Tested between a real PSP (these builds, 0.21) and PPSSPP (original mods, 0.26): looks are shown in both directions. Players without the mod see the real equipment.

## Where the data is stored

- Look of an item: one otherwise unused byte in the item's equipment box entry, saved with the normal savegame.
- Looks per equipment set: `ms0:/P3RDML/TRANSMOG_SETSn.BIN` (`n` = save slot). Not part of the savegame.

## Limits

- Mod loader 0.21 only. On 0.26 use Kurogami's original mods.
- PSP version only. The HD files are the untouched originals (`per_set_transmog_psp/hd.bin` is in 0.26 format) and are not supported here.
- Memory used: `0x089E1100`–`0x089E15DC` and `0x089E1790`–`0x089E17D0` (Per Set Transmog), `0x089E1600`–`0x089E1788` (Transmog). Anything else placed there collides, for example a target camera build that uses `0x089E1100`–`0x089E15D0`.
- Do not combine with the transmog CWCheat codes from this repository. The codes only change what you see on your own screen and are applied on top of the mod, so you and other players would see different things (see `mod_with_codes_combination.txt`).

## What was changed

`transmog_psp`
- Armor and player model lookups are patched in place (no extra memory).
- The weapon routine and the item box menu code are the original instructions, moved to `0x089E1600`.

`per_set_transmog_psp`
- The original code block is unchanged, placed at `0x089E1100`.
- The original reads its sets file while the game is still loading. Here that happens the first time an equipment set is saved, equipped or reordered after entering the village.

## Source

`src/` contains the [armips](https://github.com/Kingcom/armips) sources. They rebuild to the exact files in this folder:

```
cd src/transmog_psp && armips transmog021.asm            # -> transmog.bin
cd src/per_set_transmog_psp && armips pst021.asm         # -> psp.bin
```

`src/per_set_transmog_psp/code.bin` is the code block taken unchanged from Kurogami's Per Set Transmog.
