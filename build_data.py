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

# Weapon tables
# 28-byte entries: model_id(u16) at +0
# 80-byte entries: model_id(u16) at +0
WEAPON_TABLES = {
    5:  {"base": 0x08992168, "entry_size": 28, "name": "Great Sword"},
    6:  {"base": 0x0898FA78, "entry_size": 28, "name": "Sword & Shield"},
    7:  {"base": 0x0898E71C, "entry_size": 28, "name": "Lance"},
    8:  {"base": 0x08990D64, "entry_size": 28, "name": "Hammer"},
    9:  {"base": 0x0898AB2C, "entry_size": 80, "name": "Light Bowgun"},
    10: {"base": 0x0898C01C, "entry_size": 80, "name": "Heavy Bowgun"},
    12: {"base": 0x08991800, "entry_size": 28, "name": "Long Sword"},
    13: {"base": 0x0898D5D4, "entry_size": 28, "name": "Dual Blades"},
    14: {"base": 0x089904DC, "entry_size": 28, "name": "Gunlance"},
    15: {"base": 0x089891DC, "entry_size": 80, "name": "Switch Axe"},
    16: {"base": 0x0898F164, "entry_size": 28, "name": "Hunting Horn"},
    17: {"base": 0x0898DDB4, "entry_size": 28, "name": "Bow"},
}

# Weapon INI mapping (type_id → INI filename) — used as fallback for model names
WEAPON_INI = {
    5: "GS.ini",
    6: "SNS.ini",
    7: "LNC.ini",
    8: "HMR.ini",
    9: "LBG.ini",
    10: "HBG.ini",
    12: "LS.ini",
    13: "DB.ini",
    14: "GL.ini",
    15: "SAXE.ini",
    16: "HH.ini",
    17: "BOW.ini",
}

# Weapon name string tables in memory (null-terminated strings, one per table entry)
WEAPON_NAME_TABLES = {
    5:  0x08A5D05F,   # Great Sword
    6:  0x08A5EB66,   # Sword & Shield
    7:  0x08A61E8B,   # Lance
    8:  0x08A60498,   # Hammer
    9:  0x08A64C53,   # Light Bowgun
    10: 0x08A6386D,   # Heavy Bowgun
    12: 0x08A65F53,   # Long Sword
    13: 0x08A6B266,   # Dual Blades
    14: 0x08A6873E,   # Gunlance
    15: 0x08A67662,   # Switch Axe
    16: 0x08A6C6E4,   # Hunting Horn
    17: 0x08A69B1B,   # Bow
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
    # Combine all files/files2/files3/... lines
    # Use greedy match to handle quoted weapon names like Reaver "Cruelty"
    for m in re.finditer(r'files\d*="(.+)"', content):
        for item in m.group(1).split(";"):
            item = item.strip()
            if not item:
                continue
            # Format: "Name FXXXX" or "Name MXXXX"
            # Last 5 chars are gender+hex (F/M + 4 hex digits)
            # But some names have spaces, so we split from right
            match = re.match(r'^(.+?)\s+([FM])([0-9A-Fa-f]{4})$', item)
            if match:
                name = match.group(1)
                gender = match.group(2)
                file_id = int(match.group(3), 16)
                entries.append((name, file_id, gender))
            else:
                # Fallback: try 4 hex chars at end
                match2 = re.match(r'^(.+?)([0-9A-Fa-f]{4})$', item)
                if match2:
                    name = match2.group(1).rstrip()
                    file_id = int(match2.group(2), 16)
                    entries.append((name, file_id, None))
    return entries


def build_model_name_map(ini_path, f_base, m_base):
    """Build model_id → name mapping from INI file and file ID bases.

    model_id 0 = invisible/nothing. model_id 1+ maps to files:
    file_id = base + (model_id - 1), so model_id = (file_id - base) + 1.
    """
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


def build_weapon_model_names(ini_path):
    """Build model_id → name mapping for weapons from INI file.

    Weapon INI entries are indexed by position (model_id = position index).
    """
    entries = parse_ini_entries(ini_path)
    model_names = {}

    # For weapons, INI entries are just "Name XXXX" without F/M prefix
    # Re-parse with simpler logic
    with open(ini_path) as f:
        content = f.read()

    all_items = []
    for m in re.finditer(r'files\d*="(.+)"', content):
        for item in m.group(1).split(";"):
            item = item.strip()
            if item:
                all_items.append(item)

    for idx, item in enumerate(all_items):
        # Remove hex ID at the end
        match = re.match(r'^(.+?)\s*[0-9A-Fa-f]{4}$', item)
        if match:
            name = match.group(1).rstrip()
        else:
            name = item
        # model_id maps directly to INI index:
        # file_id = model_id + base_offset, INI index 0 = file base = model_id 0
        model_names[idx] = name

    return model_names


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
    variants_list = []
    for (model_m, model_f), eids in sorted(model_groups.items()):
        name = get_model_name(model_m, model_f, model_names)
        flag = get_dominant_flag(entries_raw, eids)
        variants_list.append({
            "name": name,
            "model_m": model_m,
            "model_f": model_f,
            "eids": eids,
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
                "variants": [{"model_m": 0, "model_f": 0, "eids": v["eids"]}],
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
                     "eids": first["eids"], "names": [first["name"]]},
                    {"model_m": second["model_m"], "model_f": second["model_f"],
                     "eids": second["eids"], "names": [second["name"]]},
                ]
                sets.append({"names": names, "variants": variants})
                used.add(i)
                used.add(j)
                continue

        # Single variant (Both class, or no partner found)
        sets.append({
            "names": [v["name"]],
            "variants": [{"model_m": v["model_m"], "model_f": v["model_f"],
                          "eids": v["eids"]}],
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


def read_weapon_names(data, type_id, num_entries):
    """Read weapon names from the in-memory name string table."""
    name_addr = WEAPON_NAME_TABLES.get(type_id)
    if not name_addr:
        return {}
    off = addr_to_off(name_addr)
    names = {}
    for i in range(num_entries):
        end = data.find(b"\x00", off)
        raw = data[off:end]
        try:
            names[i] = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            names[i] = ""
        off = end + 1
    return names


def build_weapon_data(data, type_id, max_entries):
    """Extract weapon table data for one type."""
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

    # Read per-entry weapon names from memory
    entry_names = read_weapon_names(data, type_id, num_entries)

    # Build model name map from INI as fallback
    ini_file = WEAPON_INI.get(type_id)
    model_names_ini = {}
    if ini_file:
        ini_path = os.path.join(EQUIPMENT_LIST_DIR, ini_file)
        if os.path.exists(ini_path):
            model_names_ini = build_weapon_model_names(ini_path)

    # Group by model_id, collecting all weapon names per model
    model_groups = {}  # model_id → {"entries": [...], "names": [...]}
    for i in range(num_entries):
        off = off_base + i * entry_size
        model_id = struct.unpack_from("<H", data, off)[0]
        if model_id not in model_groups:
            model_groups[model_id] = {"entries": [], "names": []}
        model_groups[model_id]["entries"].append(i)
        name = entry_names.get(i, "")
        if name and name not in model_groups[model_id]["names"]:
            model_groups[model_id]["names"].append(name)

    # Build weapon items
    weapons = {}
    for model_id, group in sorted(model_groups.items()):
        names = group["names"]
        if not names:
            # Fallback to INI name
            ini_name = model_names_ini.get(model_id, f"Model {model_id}")
            names = [ini_name]
        weapons[str(model_id)] = {
            "names": names,
            "entries": group["entries"],
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

    # Build weapon data
    max_entries = get_weapon_table_max_entries()
    for type_id in sorted(WEAPON_TABLES.keys()):
        type_name = WEAPON_TABLES[type_id]["name"]
        print(f"Building {type_name} weapon data (type {type_id})...")
        result["weapons"][str(type_id)] = build_weapon_data(data, type_id, max_entries[type_id])
        n_weapons = len(result["weapons"][str(type_id)]["weapons"])
        n_entries = result["weapons"][str(type_id)]["total_entries"]
        print(f"  {n_entries} entries, {n_weapons} unique models")

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nWrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
