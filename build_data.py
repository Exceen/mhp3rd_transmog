#!/usr/bin/env python3
"""
MHP3rd Transmog Data Builder

Extracts armor/weapon data tables from a PPSSPP save state and builds
transmog_data.json for use with transmog.py.

Requires: zstandard (pip install zstandard)
"""

import json
import os
import re
import struct
import sys

try:
    import zstandard
except ImportError:
    print("Error: zstandard module required. Install with: pip install zstandard")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_STATE_DIR = os.path.expanduser("~/Documents/PPSSPP/PSP/PPSSPP_STATE")
EQUIPMENT_LIST_DIR = os.path.expanduser(
    "~/Documents/PPSSPP/PSP/GAME/P3rdMLMan/DATA/en/EQUIPMENT_LIST"
)
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "transmog_data.json")

# ── Memory Table Addresses ──────────────────────────────────────────────────

CWCHEAT_BASE = 0x08800000

# Armor tables: 40-byte entries, model_m(s16) at +0, model_f(s16) at +2
# Slot mapping verified by tracing jump table at 0x08966598 and model loading
# code at 0x08868538-0x08868710 (type2: 0=chest, 1=arms, 2=waist, 3=legs, 4=head)
ARMOR_TABLES = {
    "chest": {"base": 0x08980144, "entries": 233, "player_offset": 0x1C},
    "arms":  {"base": 0x0897DFFC, "entries": 213, "player_offset": 0x26},
    "waist": {"base": 0x08984DAC, "entries": 214, "player_offset": 0x30},
    "legs":  {"base": 0x08986F1C, "entries": 220, "player_offset": 0x3A},
    "head":  {"base": 0x089825AC, "entries": 256, "player_offset": 0x44},
}
ARMOR_ENTRY_SIZE = 40

# Armor file ID bases (for model_id → name mapping)
# model_id = file_id - base
ARMOR_FILE_BASES = {
    "head":  {"f": 0x0263, "m": 0x04ED},
    "chest": {"f": 0x006F, "m": 0x02F9},
    "arms":  {"f": 0x00EC, "m": 0x0376},
    "waist": {"f": 0x0169, "m": 0x03F3},
    "legs":  {"f": 0x01E6, "m": 0x0470},
}

# INI file mapping
ARMOR_INI = {
    "head": "HEAD.ini",
    "chest": "BODY.ini",
    "arms": "ARMS.ini",
    "waist": "WAIST.ini",
    "legs": "LEGS.ini",
}

# Weapon tables — keyed by EQUIPMENT TYPE BYTE (from save data / Ram Research PDF)
# Table bases verified by reading jump table handlers at 0x08966184 indexed by type byte.
# Entry sizes verified from sll multiply patterns in each handler.
WEAPON_TABLES = {
    5:  {"base": 0x08992168, "entry_size": 28, "name": "Great Sword"},
    6:  {"base": 0x0898FA78, "entry_size": 28, "name": "Sword & Shield"},
    7:  {"base": 0x0898E71C, "entry_size": 28, "name": "Hammer"},
    8:  {"base": 0x08990D64, "entry_size": 28, "name": "Lance"},
    9:  {"base": 0x0898AB2C, "entry_size": 80, "name": "Heavy Bowgun"},
    11: {"base": 0x0898C01C, "entry_size": 80, "name": "Light Bowgun"},
    12: {"base": 0x08991800, "entry_size": 28, "name": "Long Sword"},
    13: {"base": 0x0898D5D4, "entry_size": 28, "name": "Switch Axe"},
    14: {"base": 0x089904DC, "entry_size": 28, "name": "Gunlance"},
    15: {"base": 0x089891DC, "entry_size": 80, "name": "Bow"},
    16: {"base": 0x0898F164, "entry_size": 28, "name": "Dual Blades"},
    17: {"base": 0x0898DDB4, "entry_size": 28, "name": "Hunting Horn"},
}

# Weapon file list — maps section headers to equipment type bytes
# Source: https://github.com/Kurogami2134/MHP3rd-Game-FIle-List/blob/main/weapons.md
WEAPON_FILE_LIST = os.path.join(SCRIPT_DIR, "weapons_filelist.md")
WEAPON_FILELIST_SECTIONS = {
    "Great Sword": 5,
    "Sword and Shield": 6,
    "Hammer": 7,
    "Lance": 8,
    "Heavy Bowgun": 9,
    "Light Bowgun": 11,
    "Long Sword": 12,
    "Switch Axe": 13,
    "Gunlance": 14,
    "Bow": 15,
    "Dual Blades": 16,
    "Hunting Horn": 17,
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def addr_to_off(addr):
    """Convert PSP address to save state file offset."""
    return addr - 0x08000000 + 0x48


def decompress_save_state(path):
    """Decompress a PPSSPP .ppst save state."""
    with open(path, "rb") as f:
        f.read(0xB0)  # skip header
        compressed = f.read()
    dctx = zstandard.ZstdDecompressor()
    return dctx.decompress(compressed, max_output_size=64 * 1024 * 1024)


def parse_ini_entries(ini_path):
    """Parse equipment list INI file, returns list of (name, file_id_hex, gender) tuples."""
    with open(ini_path) as f:
        content = f.read()

    entries = []
    for m in re.finditer(r'files\d*="(.+)"', content):
        for item in m.group(1).split(";"):
            item = item.strip()
            if not item:
                continue
            match = re.match(r'^(.+?)\s+([FM])([0-9A-Fa-f]{4})$', item)
            if match:
                name = match.group(1)
                gender = match.group(2)
                file_id = int(match.group(3), 16)
                entries.append((name, file_id, gender))
    return entries


def build_model_name_map(ini_path, f_base, m_base):
    """Build model_id → name mapping from INI file and file ID bases."""
    entries = parse_ini_entries(ini_path)
    model_names = {}

    for name, file_id, gender in entries:
        if gender == "F":
            model_id = (file_id - f_base) + 1
        elif gender == "M":
            model_id = (file_id - m_base) + 1
        else:
            continue

        if model_id < 1 or model_id > 500:
            continue

        if model_id not in model_names:
            model_names[model_id] = name

    return model_names


def parse_weapon_file_list(filepath):
    """Parse the weapon file list markdown into per-type model name mappings.

    Returns: {type_byte: {model_id: [weapon_names]}}
    where model_id = file_number - base_file_number (handles gaps in file numbering).
    """
    result = {}
    current_type = None
    base_file_num = None

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("## "):
                section_name = line[3:].strip()
                current_type = WEAPON_FILELIST_SECTIONS.get(section_name)
                if current_type is not None:
                    result[current_type] = {}
                    base_file_num = None
                continue

            if current_type is None:
                continue
            if not line.startswith("|") or line.startswith("|File") or line.startswith("|-"):
                continue

            cols = [c.strip() for c in line.split("|")]
            # cols: ['', file, file_id, hd_file, hd_file_id, weapons, '']
            if len(cols) < 6:
                continue

            # Extract file number (e.g., "1467.pak" → 1467)
            file_col = cols[1]
            match = re.match(r'(\d+)\.pak', file_col)
            if not match:
                continue
            file_num = int(match.group(1))

            if base_file_num is None:
                base_file_num = file_num

            model_id = file_num - base_file_num
            weapons_col = cols[5]
            names = [n.strip() for n in weapons_col.split("<br>") if n.strip()]
            result[current_type][model_id] = names

    return result


# ── Main Build ──────────────────────────────────────────────────────────────

def find_latest_save_state():
    """Find the most recent MHP3rd (ULJM05800) save state."""
    import glob
    pattern = os.path.join(SAVE_STATE_DIR, "ULJM05800*.ppst")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def get_dominant_flag(entries_raw, eids):
    """Get the most common flag value for a group of entries."""
    from collections import Counter
    flags = Counter(entries_raw[eid]["flag"] for eid in eids)
    return flags.most_common(1)[0][0]


def get_model_name(model_m, model_f, model_names):
    """Get name for a model pair."""
    if model_m == 0 and model_f == 0:
        return "Nothing Equipped"
    elif model_m == 0:
        return model_names.get(model_f, f"Model F{model_f}")
    elif model_f == 0:
        return model_names.get(model_m, f"Model M{model_m}")
    else:
        name = model_names.get(model_m) or model_names.get(model_f)
        if not name:
            if model_m == model_f:
                return f"Model {model_m}"
            else:
                return f"Model M{model_m}/F{model_f}"
        return name


def build_armor_data(data, slot):
    """Extract armor table data for one slot.

    Output format matches MHFU transmog: each set has 'names' (array) and
    'variants' (array of {model_m, model_f, eids, names}).
    BM and GN versions of the same armor are grouped into one set with
    separate variants.
    """
    info = ARMOR_TABLES[slot]
    base = info["base"]
    num_entries = info["entries"]

    # Build model name map
    ini_file = ARMOR_INI.get(slot)
    model_names = {}
    if ini_file:
        ini_path = os.path.join(EQUIPMENT_LIST_DIR, ini_file)
        if os.path.exists(ini_path):
            bases = ARMOR_FILE_BASES[slot]
            model_names = build_model_name_map(ini_path, bases["f"], bases["m"])

    # Read entries and group by (model_m, model_f)
    model_groups = {}  # (model_m, model_f) → list of entry indices
    entries_raw = []

    for i in range(num_entries):
        off = addr_to_off(base) + i * ARMOR_ENTRY_SIZE
        model_m = struct.unpack_from("<h", data, off)[0]
        model_f = struct.unpack_from("<h", data, off + 2)[0]
        flag = data[off + 4]
        entries_raw.append({"eid": i, "model_m": model_m, "model_f": model_f, "flag": flag})

        key = (model_m, model_f)
        if key not in model_groups:
            model_groups[key] = []
        model_groups[key].append(i)

    # Build model groups with flag info
    # Also collect per-entry flags for pigment support
    entry_flags = {e["eid"]: e["flag"] for e in entries_raw}

    variants_list = []
    for (model_m, model_f), eids in sorted(model_groups.items()):
        name = get_model_name(model_m, model_f, model_names)
        flag = get_dominant_flag(entries_raw, eids)
        flags = [entry_flags[eid] for eid in eids]
        variants_list.append({
            "name": name,
            "model_m": model_m,
            "model_f": model_f,
            "eids": eids,
            "flags": flags,
            "flag": flag,
        })

    # Index by model_m for fast lookup
    by_model_m = {v["model_m"]: (i, v) for i, v in enumerate(variants_list)}

    # Group BM+GN variants into sets
    # Strategy: pair model N with model N+1 when they have different flags
    # (BM and GN flags differ, e.g. 0x07 vs 0x1B for chest, 0x0F vs 0x1F for head)
    sets = []
    used = set()

    for i, v in enumerate(variants_list):
        if i in used:
            continue

        # Skip "Nothing Equipped"
        if v["model_m"] == 0 and v["model_f"] == 0:
            sets.append({
                "names": ["Nothing Equipped"],
                "variants": [{"model_m": 0, "model_f": 0, "eids": v["eids"],
                              "flags": v["flags"]}],
            })
            used.add(i)
            continue

        # Try to pair with model_m+1 if it exists and has a different flag
        next_model = v["model_m"] + 1
        if next_model in by_model_m:
            j, v2 = by_model_m[next_model]
            if j not in used and v["flag"] != v2["flag"]:
                # Paired: first variant is lower flag (BM), second is higher (GN)
                # In MHP3rd, BM flag < GN flag (0x07<0x1B, 0x0F<0x1F)
                if v["flag"] < v2["flag"]:
                    first, second = v, v2
                else:
                    first, second = v2, v

                names = [first["name"], second["name"]]
                variants = [
                    {"model_m": first["model_m"], "model_f": first["model_f"],
                     "eids": first["eids"], "flags": first["flags"],
                     "names": [first["name"]]},
                    {"model_m": second["model_m"], "model_f": second["model_f"],
                     "eids": second["eids"], "flags": second["flags"],
                     "names": [second["name"]]},
                ]
                sets.append({"names": names, "variants": variants})
                used.add(i)
                used.add(j)
                continue

        # Single variant (Both class, or no partner found)
        sets.append({
            "names": [v["name"]],
            "variants": [{"model_m": v["model_m"], "model_f": v["model_f"],
                          "eids": v["eids"], "flags": v["flags"]}],
        })
        used.add(i)

    return {
        "table_base": f"0x{base:08X}",
        "entries": num_entries,
        "sets": sets,
    }


def get_weapon_table_max_entries():
    """Compute max entry count per weapon table based on gaps between tables."""
    sorted_tables = sorted(WEAPON_TABLES.items(), key=lambda x: x[1]["base"])
    limits = {}
    for i, (tid, info) in enumerate(sorted_tables):
        if i + 1 < len(sorted_tables):
            next_base = sorted_tables[i + 1][1]["base"]
            limits[tid] = (next_base - info["base"]) // info["entry_size"]
        else:
            limits[tid] = 200  # last table, use generous limit
    return limits




def build_weapon_data(data, type_id, max_entries, filelist_models):
    """Extract weapon table data for one type.

    filelist_models: {model_index: [weapon_names]} from the file list (ground truth).
    Names and grouping come from the file list. Entries (eids) come from the data table
    grouped by model_id (which equals file list model_index).
    """
    info = WEAPON_TABLES[type_id]
    base = info["base"]
    entry_size = info["entry_size"]
    type_name = info["name"]

    # Count entries: stop at model_id > 500 or table boundary
    off_base = addr_to_off(base)
    num_entries = 0
    for i in range(max_entries):
        off = off_base + i * entry_size
        if off + entry_size > len(data):
            break
        model_id = struct.unpack_from("<H", data, off)[0]
        if model_id > 500:
            break
        num_entries = i + 1

    # Group entries by model_id from data table
    model_entries = {}  # model_id → [eid, ...]
    for i in range(num_entries):
        off = off_base + i * entry_size
        model_id = struct.unpack_from("<H", data, off)[0]
        if model_id not in model_entries:
            model_entries[model_id] = []
        model_entries[model_id].append(i)

    # Build weapon items using file list names, data table entries
    weapons = {}
    # Include all models from file list (authoritative source)
    all_model_ids = set(model_entries.keys()) | set(filelist_models.keys())
    for model_id in sorted(all_model_ids):
        names = filelist_models.get(model_id, [f"Model {model_id}"])
        entries = model_entries.get(model_id, [])
        weapons[str(model_id)] = {
            "names": names,
            "entries": entries,
        }

    return {
        "type_id": type_id,
        "type_name": type_name,
        "table_base": f"0x{base:08X}",
        "entry_size": entry_size,
        "model_offset": 0,
        "total_entries": num_entries,
        "weapons": weapons,
    }


def main():
    # Find save state
    if len(sys.argv) > 1:
        state_path = sys.argv[1]
    else:
        state_path = find_latest_save_state()

    if not state_path or not os.path.exists(state_path):
        print(f"Error: No MHP3rd save state found in {SAVE_STATE_DIR}")
        print("Usage: python build_data.py [path/to/savestate.ppst]")
        sys.exit(1)

    print(f"Using save state: {state_path}")
    print("Decompressing...")
    data = decompress_save_state(state_path)
    print(f"Decompressed: {len(data)} bytes")

    result = {
        "game": "MHP3rd",
        "game_id": "ULJM05800",
        "cwcheat_base": f"0x{CWCHEAT_BASE:08X}",
        "armor_entry_size": ARMOR_ENTRY_SIZE,
        "armor": {},
        "weapons": {},
    }

    # Build armor data
    for slot in ["head", "chest", "arms", "waist", "legs"]:
        print(f"Building {slot} armor data...")
        result["armor"][slot] = build_armor_data(data, slot)
        n_sets = len(result["armor"][slot]["sets"])
        n_entries = result["armor"][slot]["entries"]
        print(f"  {n_entries} entries, {n_sets} unique models")

    # Parse weapon file list (authoritative source for names/grouping)
    if os.path.exists(WEAPON_FILE_LIST):
        print(f"Parsing weapon file list: {WEAPON_FILE_LIST}")
        filelist = parse_weapon_file_list(WEAPON_FILE_LIST)
    else:
        print(f"WARNING: Weapon file list not found: {WEAPON_FILE_LIST}")
        print("  Weapon names will fall back to 'Model N'")
        filelist = {}

    # Build weapon data
    max_entries = get_weapon_table_max_entries()
    for type_id in sorted(WEAPON_TABLES.keys()):
        type_name = WEAPON_TABLES[type_id]["name"]
        print(f"Building {type_name} weapon data (type {type_id})...")
        fl_models = filelist.get(type_id, {})
        result["weapons"][str(type_id)] = build_weapon_data(data, type_id, max_entries[type_id], fl_models)
        n_weapons = len(result["weapons"][str(type_id)]["weapons"])
        n_entries = result["weapons"][str(type_id)]["total_entries"]
        print(f"  {n_entries} entries, {n_weapons} unique models")

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nWrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
