#!/usr/bin/env python3
"""
MHP3rd Transmog Tool — Generate CWCheat codes for equipment visual overrides.

Reads transmog_data.json (built by build_data.py) and interactively guides
the user through selecting source/target equipment to generate CWCheat codes.

Usage: python transmog.py
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(SCRIPT_DIR, "transmog_data.json")
CHEAT_FILE = os.path.expanduser("~/Documents/PPSSPP/PSP/Cheats/ULJM05800.ini")
CWCHEAT_BASE = 0x08800000

SLOT_NAMES = ["head", "chest", "arms", "waist", "legs"]
SLOT_LABELS = {"head": "Head", "chest": "Chest", "arms": "Arms", "waist": "Waist", "legs": "Legs"}
PAGE_SIZE = 20

# ── Code Cave Constants ──────────────────────────────────────────────────────
# Weapon transmog uses an ASM code cave that intercepts model_id lookup at
# runtime. Function 0x088691FC loads equipment model IDs; we hook the
# `lhu v0, 0(v0)` instruction in both its wrapper1 (0x0886927C, for 80-byte
# weapon types + armor) and wrapper2 (0x088692A0, for 28-byte weapon types)
# paths to redirect into a code cave that checks type+model and substitutes.

CODE_CAVE_BASE = 0x08800200
HOOK1_ADDR = 0x0886927C  # wrapper1 path (types 9,10,15 + armor 0-4)
HOOK2_ADDR = 0x088692A0  # wrapper2 path (types 5-8,12-14,16-17)

# ── ANSI Formatting ───────────────────────────────────────────────────────

BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"


def key(s):
    return f"{YELLOW}{BOLD}{s}{RESET}"


def header(s):
    return f"{CYAN}{BOLD}{s}{RESET}"


def success(s):
    return f"{GREEN}{s}{RESET}"


def error(s):
    return f"{RED}{s}{RESET}"


def dim(s):
    return f"{DIM}{s}{RESET}"


def bold(s):
    return f"{BOLD}{s}{RESET}"


# ── Data Loading ────────────────────────────────────────────────────────────

def load_data():
    if not os.path.exists(DATA_FILE):
        print(error(f"Error: {DATA_FILE} not found. Run build_data.py first."))
        sys.exit(1)
    with open(DATA_FILE) as f:
        return json.load(f)


# ── Selection UI ────────────────────────────────────────────────────────────

def select_equipment(items, prompt, allow_invisible=False, preset_search=None):
    """Interactive equipment selection with search and pagination."""
    sorted_items = sorted(items, key=lambda x: x["name"].lower())
    sorted_items = [i for i in sorted_items if i["name"] != "Nothing Equipped"]

    search_term = preset_search
    filtered = None
    page = 0

    while True:
        print(f"\n{header(prompt)}")

        if search_term is not None and filtered is None:
            term_lower = search_term.lower()
            filtered = [i for i in sorted_items if term_lower in i["name"].lower()]
            page = 0

        if filtered is not None:
            if not filtered:
                print(f'No results for "{search_term}"')
                search_term = None
                filtered = None
                continue

            if allow_invisible:
                print(f"{key('[0]')} {MAGENTA}** Invisible **{RESET}")
            for idx, item in enumerate(filtered, 1):
                print(f"{key(f'[{idx}]')} {item['name']}")

            print(f'\n{dim(f"Showing {len(filtered)} results for")} "{bold(search_term)}"')
            print(f"{key('[s]')} New search  {key('[b]')} Browse all  {key('[q]')} Cancel")
            choice = input(f"\n{bold('Select:')} ").strip()

            if choice.lower() == "s":
                search_term = None
                filtered = None
                continue
            elif choice.lower() == "b":
                search_term = None
                filtered = None
                continue
            elif choice.lower() == "q":
                return "cancel"
            elif choice == "0" and allow_invisible:
                return None
            elif choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(filtered):
                    return filtered[idx - 1]
        else:
            total_pages = (len(sorted_items) + PAGE_SIZE - 1) // PAGE_SIZE
            start = page * PAGE_SIZE
            end = min(start + PAGE_SIZE, len(sorted_items))
            page_items = sorted_items[start:end]

            if allow_invisible:
                print(f"{key('[0]')} {MAGENTA}** Invisible **{RESET}")
            for idx, item in enumerate(page_items, start + 1):
                print(f"{key(f'[{idx}]')} {item['name']}")

            print(f"\n{dim(f'Page {page + 1}/{total_pages} ({len(sorted_items)} items)')}")
            nav = []
            if page > 0:
                nav.append(f"{key('[p]')} Prev")
            if page < total_pages - 1:
                nav.append(f"{key('[n]')} Next")
            nav.extend([f"{key('[s]')} Search", f"{key('[q]')} Cancel"])
            print(f"{' | '.join(nav)}")
            choice = input(f"\n{bold('Select:')} ").strip()

            if choice.lower() == "n" and page < total_pages - 1:
                page += 1
                continue
            elif choice.lower() == "p" and page > 0:
                page -= 1
                continue
            elif choice.lower() == "s":
                term = input(f"{bold('Search:')} ").strip()
                if term:
                    search_term = term
                    filtered = None
                continue
            elif choice.lower() == "q":
                return "cancel"
            elif choice == "0" and allow_invisible:
                return None
            elif choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(sorted_items):
                    return sorted_items[idx - 1]

        print(error("Invalid choice, try again."))


def prompt_search_or_enter(prompt_text):
    term = input(f"\n{prompt_text} {dim('(search or Enter to browse)')}: ").strip()
    return term if term else None


# ── CWCheat Generation ─────────────────────────────────────────────────────

def gen_armor_codes(data, slot, source_set, target_set, swap_gender=False):
    """Generate CWCheat lines for armor transmog.

    Overwrites model_m/model_f in all source entries with target values.
    """
    table_base = int(data["armor"][slot]["table_base"], 16)
    entry_size = data["armor_entry_size"]
    lines = []

    if target_set is None:
        # Invisible
        target_m, target_f = 0, 0
    else:
        target_m = target_set["model_m"]
        target_f = target_set["model_f"]

    if swap_gender:
        value = (target_m & 0xFFFF) << 16 | (target_f & 0xFFFF)
    else:
        value = (target_f & 0xFFFF) << 16 | (target_m & 0xFFFF)

    for eid in source_set["eids"]:
        entry_addr = table_base + eid * entry_size
        offset = entry_addr - CWCHEAT_BASE
        code = f"_L 0x2{offset:07X} 0x{value:08X}"
        lines.append(("", code))

    return lines


def gen_universal_invisible_codes(data, slot):
    """Generate codes to make ALL armor in a slot invisible."""
    table_base = int(data["armor"][slot]["table_base"], 16)
    entry_size = data["armor_entry_size"]
    lines = []

    for armor_set in data["armor"][slot]["sets"]:
        for v in armor_set["variants"]:
            if v["model_m"] == 0 and v["model_f"] == 0:
                continue
            for eid in v["eids"]:
            entry_addr = table_base + eid * entry_size
            offset = entry_addr - CWCHEAT_BASE
            code = f"_L 0x2{offset:07X} 0x00000000"
            lines.append(("", code))

    return lines


def gen_weapon_cave_codes(transmogs):
    """Generate multi-weapon code cave CWCheat codes.

    transmogs: list of (type_id, source_model, target_model) tuples.
    Returns list of CWCheat line strings.

    The code cave intercepts model_id lookup in function 0x088691FC.
    For each transmog entry, it checks: if equipment_type == type_id AND
    model_id == source_model, replace model_id with target_model.
    Multiple entries are chained — each check is 7 MIPS instructions (28 bytes).

    Layout:
      0x100: lhu v0, 0(v0)          ; original instruction
      Per weapon (28 bytes each):
        ori  $at, $zero, TYPE
        bne  $a1, $at, next_check   ; wrong type → try next weapon
        ori  $at, $zero, SRC_MODEL  ; (delay slot) load source model
        bne  $v0, $at, exit         ; wrong model → exit unchanged
        nop
        beq  $zero, $zero, exit     ; match → jump to exit
        ori  $v0, $zero, TGT_MODEL  ; (delay slot) set target model
      Exit:
        jr   $ra
        addiu $sp, $sp, 16          ; (delay slot)
    """
    if not transmogs:
        return []

    N = len(transmogs)
    base = CODE_CAVE_BASE
    exit_addr = base + 4 + N * 28

    lines = []

    # Original instruction: lhu v0, 0(v0)
    lines.append(f"_L 0x2{base - CWCHEAT_BASE:07X} 0x94420000")

    for i, (type_id, src_model, tgt_model) in enumerate(transmogs):
        ca = base + 4 + i * 28  # check block address

        # ori $at, $zero, type_id
        lines.append(f"_L 0x2{ca - CWCHEAT_BASE:07X} 0x{0x34010000 | type_id:08X}")

        # bne $a1, $at, next_check_or_exit
        target = (ca + 28) if i < N - 1 else exit_addr
        off = (target - (ca + 4) - 4) // 4
        lines.append(f"_L 0x2{ca + 4 - CWCHEAT_BASE:07X} 0x{0x14A10000 | (off & 0xFFFF):08X}")

        # ori $at, $zero, src_model (delay slot of bne above)
        lines.append(f"_L 0x2{ca + 8 - CWCHEAT_BASE:07X} 0x{0x34010000 | src_model:08X}")

        # bne $v0, $at, exit
        off = (exit_addr - (ca + 12) - 4) // 4
        lines.append(f"_L 0x2{ca + 12 - CWCHEAT_BASE:07X} 0x{0x14410000 | (off & 0xFFFF):08X}")

        # nop
        lines.append(f"_L 0x2{ca + 16 - CWCHEAT_BASE:07X} 0x00000000")

        # beq $zero, $zero, exit
        off = (exit_addr - (ca + 20) - 4) // 4
        lines.append(f"_L 0x2{ca + 20 - CWCHEAT_BASE:07X} 0x{0x10000000 | (off & 0xFFFF):08X}")

        # ori $v0, $zero, tgt_model (delay slot of beq)
        lines.append(f"_L 0x2{ca + 24 - CWCHEAT_BASE:07X} 0x{0x34020000 | tgt_model:08X}")

    # Exit: jr $ra
    lines.append(f"_L 0x2{exit_addr - CWCHEAT_BASE:07X} 0x03E00008")
    # addiu $sp, $sp, 16 (delay slot)
    lines.append(f"_L 0x2{exit_addr + 4 - CWCHEAT_BASE:07X} 0x27BD0010")

    # Hook1 (wrapper1): j CODE_CAVE_BASE
    jt = (base >> 2) & 0x03FFFFFF
    lines.append(f"_L 0x2{HOOK1_ADDR - CWCHEAT_BASE:07X} 0x{0x08000000 | jt:08X}")
    # Hook2 (wrapper2): j CODE_CAVE_BASE
    lines.append(f"_L 0x2{HOOK2_ADDR - CWCHEAT_BASE:07X} 0x{0x08000000 | jt:08X}")

    return lines


# ── Cheat Output ────────────────────────────────────────────────────────────

def format_cheat_block(title, lines, enabled=False):
    prefix = "_C1" if enabled else "_C0"
    result = [f"{prefix} {title}"]
    for line in lines:
        if isinstance(line, tuple):
            result.append(line[1])
        else:
            result.append(line)
    return "\n".join(result)


def output_codes(blocks):
    """Display and optionally save generated codes."""
    full_output = "\n\n".join(b for b in blocks if b)
    if not full_output:
        print(dim("\nNo codes generated."))
        return

    print(f"\n{header('Generated CWCheat Codes')}")
    print(f"{'─' * 50}")
    print()
    for line in full_output.splitlines():
        if line.startswith("_C"):
            print(f"{BOLD}{line}{RESET}")
        else:
            print(f"{DIM}{line}{RESET}")
    print()

    print(f"{bold('Save options:')}")
    print(f"{key('[1]')} Append to PPSSPP cheat file {dim(f'({CHEAT_FILE})')}")
    print(f"{key('[2]')} Save to custom file")
    print(f"{key('[3]')} Done {dim('(copy from above)')}")
    choice = input(f"\n{bold('Choice:')} ").strip()

    if choice == "1":
        os.makedirs(os.path.dirname(CHEAT_FILE), exist_ok=True)
        with open(CHEAT_FILE, "a") as f:
            f.write("\n\n" + full_output + "\n")
        print(success(f"Appended to {CHEAT_FILE}"))
    elif choice == "2":
        path = input(f"{bold('File path:')} ").strip()
        if path:
            with open(path, "w") as f:
                f.write(full_output + "\n")
            print(success(f"Saved to {path}"))
    else:
        print(dim("Codes not saved."))


# ── Flows ───────────────────────────────────────────────────────────────────

def _get_weapon_name(weapon):
    """Get display name from weapon data (handles both 'name' and 'names' keys)."""
    if "name" in weapon:
        return weapon["name"]
    names = weapon.get("names", [])
    return names[0] if names else "Unknown"


def _build_weapon_items(wdata):
    """Build selectable items list from weapon type data."""
    items = []
    for model_str, weapon in wdata["weapons"].items():
        name = _get_weapon_name(weapon)
        if name in ("Model 0", "No Equipment"):
            continue
        items.append({
            "name": name,
            "entries": weapon.get("entries", []),
            "model": model_str,
        })
    return items


def _select_weapon_transmog(data):
    """Select one weapon type + source + target. Returns tuple or None."""
    weapon_types = sorted(data["weapons"].keys(), key=lambda k: int(k))
    print(f"\n{bold('Select weapon type:')}")
    type_map = {}
    for i, wt in enumerate(weapon_types, 1):
        wdata = data["weapons"][wt]
        type_map[str(i)] = wt
        print(f"{key(f'[{i}]')} {wdata['type_name']}")

    choice = input(f"\n{bold('Type:')} ").strip()
    if choice not in type_map:
        print(error("Invalid choice."))
        return None

    weapon_type = type_map[choice]
    wdata = data["weapons"][weapon_type]
    type_name = wdata["type_name"]
    print(success(f"Type: {type_name}"))

    items = _build_weapon_items(wdata)

    search = prompt_search_or_enter("Source weapon (equipped)")
    source = select_equipment(items, "Select SOURCE weapon", preset_search=search)
    if source == "cancel" or source is None:
        return None
    print(success(f"Source: {source['name']}"))

    search = prompt_search_or_enter("Target weapon (visual)")
    target = select_equipment(items, "Select TARGET weapon visual", preset_search=search)
    if target == "cancel" or target is None:
        return None
    print(success(f"Target: {target['name']}"))

    return (int(weapon_type), int(source["model"]), int(target["model"]),
            source["name"], target["name"], type_name)


def weapon_flow(data, preset_search=None):
    """Weapon transmog selection flow with multi-weapon code cave support.

    All weapon transmogs share one code cave — only one combined cheat can
    be active. This flow lets the user configure multiple weapon transmogs
    and generates a single cheat block.
    """
    os.system("cls" if os.name == "nt" else "clear")
    print(f"\n{header('Weapon Transmog')}")
    print(f"{dim('All active weapon transmogs are combined into one cheat.')}")
    print(f"{dim('(They share a single code cave in memory.)')}")

    transmogs = []  # (type_id, src_model, tgt_model, src_name, tgt_name, type_name)

    while True:
        if transmogs:
            print(f"\n{bold('Current transmogs:')}")
            for i, (tid, sm, tm, sn, tn, tname) in enumerate(transmogs, 1):
                print(f"  {key(f'[{i}]')} {tname}: {sn} \u2192 {tn}")

        print()
        print(f"{key('[a]')} Add weapon transmog")
        if transmogs:
            print(f"{key('[r]')} Remove transmog")
            print(f"{key('[g]')} Generate code")
        print(f"{key('[q]')} Cancel")

        choice = input(f"\n{bold('Choice:')} ").strip().lower()

        if choice == "q":
            return
        elif choice == "a":
            result = _select_weapon_transmog(data)
            if result:
                transmogs.append(result)
        elif choice == "r" and transmogs:
            idx = input(f"{bold('Remove #:')} ").strip()
            if idx.isdigit() and 1 <= int(idx) <= len(transmogs):
                transmogs.pop(int(idx) - 1)
        elif choice == "g" and transmogs:
            break
        else:
            print(error("Invalid choice."))

    # Generate combined code cave cheat
    cave_entries = [(tid, sm, tm) for tid, sm, tm, sn, tn, tname in transmogs]
    lines = gen_weapon_cave_codes(cave_entries)

    if len(transmogs) == 1:
        _, _, _, sn, tn, tname = transmogs[0]
        title = f"{tname}: {sn} -> {tn}"
    else:
        parts = []
        for _, _, _, sn, tn, tname in transmogs:
            abbr = "".join(c for c in tname if c.isupper()) or tname[:3]
            parts.append(f"{abbr}:{sn}->{tn}")
        title = " | ".join(parts)
        if len(title) > 70:
            title = f"Weapon Transmog ({len(transmogs)} weapons)"

    block = format_cheat_block(title, lines)
    output_codes([block])


def armor_slot_flow(data, slot, preset_source_search=None, preset_search=None):
    """Single armor slot selection flow."""
    sets = data["armor"][slot]["sets"]
    label = SLOT_LABELS[slot]

    items = []
    for s in sets:
        for v in s["variants"]:
            if v["model_m"] == 0 and v["model_f"] == 0:
                continue
            name = (v["names"][0] if "names" in v else None) or s["names"][0]
            items.append({
                "name": name,
                "model_m": v["model_m"],
                "model_f": v["model_f"],
                "eids": v["eids"],
                "flags": v["flags"],
            })

    os.system("cls" if os.name == "nt" else "clear")
    print(f"\n{header(f'{label} Armor Transmog')}")

    # Select source
    search = preset_source_search or prompt_search_or_enter(f"Source {label.lower()} armor (equipped)")
    source = select_equipment(items, f"Select SOURCE {label.lower()} armor", preset_search=search)
    if source == "cancel":
        return None
    if source is None:
        print(error("Source cannot be invisible."))
        return None
    print(success(f"Source: {source['name']}"))

    # Select target (with invisible option)
    search = preset_search or prompt_search_or_enter(f"Target {label.lower()} visual")
    target = select_equipment(items, f"Select TARGET {label.lower()} visual",
                              allow_invisible=True, preset_search=search)
    if target == "cancel":
        return None

    is_invisible = target is None
    swap_gender = False
    if is_invisible:
        tgt_name = "Invisible"
        print(f"Target: {MAGENTA}** Invisible **{RESET}")
    else:
        tgt_name = target["name"]
        print(success(f"Target: {tgt_name}"))
        # Offer gender swap if models differ
        if target["model_m"] != target["model_f"]:
            print(f"\n{header('Gender:')}")
            print(f"{key('[1]')} Default")
            print(f"{key('[2]')} Opposite gender model")
            gc = input(f"\n{bold('Select:')} ").strip()
            swap_gender = gc == "2"

    lines = gen_armor_codes(data, slot, source, target, swap_gender=swap_gender)
    return lines, source["name"], tgt_name, is_invisible


def armor_flow(data):
    """Single armor slot selection flow with output."""
    os.system("cls" if os.name == "nt" else "clear")
    print(f"\n{bold('Select armor slot:')}")
    for i, slot in enumerate(SLOT_NAMES, 1):
        print(f"{key(f'[{i}]')} {SLOT_LABELS[slot]}")

    choice = input(f"\n{bold('Slot:')} ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= 5):
        print(error("Invalid choice."))
        return

    slot = SLOT_NAMES[int(choice) - 1]
    result = armor_slot_flow(data, slot)
    if result is None:
        return

    lines, src_name, tgt_name, is_invisible = result
    suffix = f" (invisible {SLOT_LABELS[slot].lower()})" if is_invisible else ""
    title = f"Armor Transmog: {src_name} -> {tgt_name}{suffix}"
    block = format_cheat_block(title, lines)
    output_codes([block])


def armor_set_flow(data):
    """Armor set transmog flow (all 5 slots)."""
    print(f"\n{header('Armor Set Transmog')}")
    print("Select all 5 armor pieces.")
    print(f"{dim('Persistent search filters across selections.')}\n")

    persistent_source_search = input(f"Source search filter {dim('(Enter to skip)')}: ").strip() or None
    persistent_search = input(f"Target search filter {dim('(Enter to skip)')}: ").strip() or None

    all_lines = []
    summaries = []

    for slot in SLOT_NAMES:
        result = armor_slot_flow(data, slot,
                                 preset_source_search=persistent_source_search,
                                 preset_search=persistent_search)
        if result is None:
            print(dim(f"Skipping {SLOT_LABELS[slot]}."))
            continue
        lines, src_name, tgt_name, is_invisible = result
        all_lines.extend(lines)
        summaries.append((slot, src_name, tgt_name, is_invisible))

    if not all_lines:
        print(dim("\nNo codes generated."))
        return

    target_names = set(tgt for _, _, tgt, inv in summaries if not inv)
    if len(target_names) == 1:
        tgt_display = target_names.pop()
    elif not target_names:
        tgt_display = "Invisible"
    else:
        tgt_display = "Custom"

    source_names = set(src for _, src, _, _ in summaries)
    src_display = source_names.pop() if len(source_names) == 1 else "Mixed"

    title = f"Armor Set Transmog: {src_display} -> {tgt_display}"
    block = format_cheat_block(title, all_lines)
    output_codes([block])


def universal_invisible_flow(data):
    """Make ALL armor in a slot invisible."""
    os.system("cls" if os.name == "nt" else "clear")
    print(f"\n{header('Universal Invisible Slot')}")
    print(f"{dim('Makes ALL armor in a slot invisible.')}\n")

    print(f"{bold('Select slot:')}")
    for i, slot in enumerate(SLOT_NAMES, 1):
        print(f"{key(f'[{i}]')} {SLOT_LABELS[slot]}")

    choice = input(f"\n{bold('Slot:')} ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= 5):
        print(error("Invalid choice."))
        return

    slot = SLOT_NAMES[int(choice) - 1]
    lines = gen_universal_invisible_codes(data, slot)
    if not lines:
        print(dim("No entries to patch."))
        return

    title = f"Universal Invisible {SLOT_LABELS[slot]} ({len(lines)} entries)"
    block = format_cheat_block(title, lines)
    output_codes([block])


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    data = load_data()

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print(f"{CYAN}{BOLD}{'─' * 34}{RESET}")
        print(f"{CYAN}{BOLD}MHP3rd Transmog Tool{RESET}")
        print(f"{CYAN}{BOLD}{'─' * 34}{RESET}")
        print()
        print(f"{key('[1]')} Weapon Transmog")
        print(f"{key('[2]')} Armor Transmog {dim('(single slot)')}")
        print(f"{key('[3]')} Armor Transmog {dim('(set)')}")
        print(f"{key('[4]')} Universal Invisible Slot")
        print()
        print(f"{key('[q]')} Quit")

        choice = input(f"\n{bold('Choice:')} ").strip().lower()

        if choice == "1":
            weapon_flow(data)
        elif choice == "2":
            armor_flow(data)
        elif choice == "3":
            armor_set_flow(data)
        elif choice == "4":
            universal_invisible_flow(data)
        elif choice == "q":
            break
        else:
            print(error("Invalid choice."))

        if choice in ("1", "2", "3", "4"):
            input(f"\n{dim('Press Enter to return to menu...')}")


if __name__ == "__main__":
    main()
