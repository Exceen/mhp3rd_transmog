#!/usr/bin/env python3
"""
Rebuild weapon data in transmog_data.json from the complete weapon file list.

Uses the correct type IDs from the game's equipment type byte:
  5=GS, 6=SnS, 7=Hammer, 8=Lance, 9=HBG, 11=LBG,
  12=LS, 13=SA, 14=GL, 15=Bow, 16=DB, 17=HH
"""

import json
import copy

INPUT_PATH = "/Users/Exceen/Downloads/mhp3rd_transmog/docs/transmog_data.json"
OUTPUT_PATHS = [
    "/Users/Exceen/Downloads/mhp3rd_transmog/docs/transmog_data.json",
    "/Users/Exceen/Downloads/mhp3rd_transmog/transmog_data.json",
]

# Complete weapon file list data.
# Format: (type_id, type_name, file_base_hex, entries)
# Each entry: (file_id_hex, [weapon_names])  or None to skip
# "No Equipment" and "Unused" entries are marked for skipping.

WEAPON_DATA = []

def define_weapons():
    """Build the complete weapon data from the file list."""
    weapons = {}

    # Helper: parse a weapon type definition
    def add_type(type_id, type_name, file_base, entries):
        """
        entries: list of (file_id, names_str_or_None)
        file_id is int, names_str is comma-separated weapon names.
        None means skip this entry.
        """
        weps = {}
        for file_id, names_str in entries:
            model_id = file_id - file_base
            if names_str is None:
                continue  # Skip No Equipment / Unused
            names = [n.strip() for n in names_str.split(",")]
            weps[str(model_id)] = {"names": names}
        weapons[str(type_id)] = {
            "type_name": type_name,
            "weapons": weps,
        }

    # Great Sword (type 5, base 0x05BA)
    add_type(5, "Great Sword", 0x05BA, [
        # 0x05BA: No Equipment - skip
        (0x05BB, "Jawblade, Giant Jawblade"),
        (0x05BC, "Ravager Blade, Ravager Blade+"),
        (0x05BD, "Carbalite Sword, Carbalite Sword+"),
        (0x05BE, "Buster Sword, Buster Sword+, Buster Blade"),
        (0x05BF, "Bone Blade, Bone Blade+, Bone Slasher"),
        (0x05C0, "Golem Blade, Golem Blade+, Blade of Talos"),
        (0x05C1, "Rugged Great Sword, Chieftain's Grt Swd, High Chief's Grt Swd"),
        (0x05C2, "Carapace Sword, Carapace Blade, Barroth Smasher"),
        (0x05C3, "Ludroth Bone Sword"),
        (0x05C4, "Tiger Agito, Tiger Agito+, Tigrex Great Sword"),
        (0x05C5, "Siegmund, High Siegmund"),
        (0x05C6, "Valkyrie Blade, Sieglinde, High Sieglinde"),
        (0x05C7, "Red Wing, Rathalos Firesword, Rathalos Flamesword"),
        (0x05C8, "Berserker Sword, Anguish"),
        (0x05C9, "Quarrel Hornsword, Quarrel Hornsword+, Diablos Hornsword"),
        (0x05CA, "Brazenwall, Brazenwall+, Crimsonwall"),
        (0x05CB, "Vulcanis, Vulcanvil, Vulcamagnon"),
        (0x05CC, "Autumn Rain Bangasa, Rain Killer Bangasa"),
        (0x05CD, "Rusted Great Sword, Tarnished Grt Sword, Worn Great Sword, Weathered Grt Sword"),
        (0x05CE, "Ancient Blade, Elder Monument"),
        (0x05CF, "Epitaph Blade"),
        (0x05D0, "Alatreon Greatsword, Alatreon Revolution"),
        (0x05D1, "Wyvern Jawblade"),
        (0x05D2, "Cataclysm Sword, Cataclysm Sword+, Cataclysm Blade"),
        (0x05D3, "True Cutter Sword"),
        (0x05D4, "Hidden Blade, Dark of Night"),
        (0x05D5, "Akantor Doomgiver"),
        (0x05D6, "Ukanlos Destructor"),
        (0x05D7, "Old Yukumo Grt Sword, Yukumo Great Sword, Yukumo Great Sword+, Yukumo Great Blade, True Yukumo Grt Swd, True Yukumo Grt Swd+, Cloudcleaver Grt Swd"),
        (0x05D8, "Usurper's Storm, Despot's Blackstorm"),
        (0x05D9, "Evil Gathering Cloud"),
        (0x05DA, "Type 41 Wyvernator, Type 41 Wyvernator+, Remalgalypse"),
        (0x05DB, "Icicle Fang, Icicle Fang+, Paladire"),
        (0x05DC, "Aurora Blade, Northern Lights"),
        (0x05DD, "Rathalos Gleamsword"),
        (0x05DE, "Black Agito, Black Rex Grt Sword"),
        (0x05DF, "Galespike, Simoom Sandbarb"),
        (0x05E0, "Wyvern's Perch, Rougish Deathcap"),
        (0x05E1, "Houma no Tsurugi, Tenma no Tsurugi"),
    ])

    # Sword and Shield (type 6, base 0x05E2)
    # Note: file 0x05F6 is missing from the list (model_id 20 doesn't exist)
    add_type(6, "Sword and Shield", 0x05E2, [
        # 0x05E2: No Equipment - skip
        (0x05E3, "Warrior's Sword, Odyssey"),
        (0x05E4, "Hunter's Dagger, Hunter's Dagger+, Assassin's Dagger"),
        (0x05E5, "Soldier's Dagger"),
        (0x05E6, "Hydra Knife, Hydra Knife+, Deadly Knife"),
        (0x05E7, "Bone Kris, Bone Kris+"),
        (0x05E8, "Ludroth's Nail"),
        (0x05E9, "Bone Tomahawk, Bone Tomahawk+, Qurupeco Chopper"),
        (0x05EA, "Golden Falchion"),
        (0x05EB, "Shadow Saber, Shadow Saber+, Toxic Fang"),
        (0x05EC, "Icicle Spike, Icicle Spike+, Nardebosche"),
        (0x05ED, "Carapace Mace, Carapace Mace+, Barroth Club"),
        (0x05EE, "Secta Nulo, Secta Unu, Secta Nulo(W), Secta Unu(W), Secta Nulo(Y), Secta Unu(Y), Secta Nulo(G), Secta Unu(G), Secta Du(G)"),
        (0x05EF, "Blood Tabar, Plague Tabar"),
        (0x05F0, "Jhen Kodachi, Calm Sands"),
        (0x05F1, "Gigas Club, Gigas Club+, Gigas Crusher"),
        (0x05F2, "Djinn, Blazing Falchion"),
        (0x05F3, "Chak Chak, Chak Chak+, Wagga Wagga"),
        (0x05F4, "Cat? Punch, Cat? Punch+, Nyan Nyan Punch"),
        (0x05F5, "Tusk Gear, Fossil Gear, Skull's Wrath"),
        # 0x05F6: missing from file list - skip
        (0x05F7, "Dirty Baron, Dirty Baron+, Dirty Marquis"),
        (0x05F8, "Rusted Sword, Tarnished Sword, Worn Sword, Weathered Sword"),
        (0x05F9, "Eternal Strife, Eternal Hate"),
        (0x05FA, "Alatreon Sword, Alatreon Star"),
        (0x05FB, "Royal Claw, Royal Claw+, Royal Ludroth Claw"),
        (0x05FC, "Divine Exodus"),
        (0x05FD, "Rex Talon, Tigrex Sword"),
        (0x05FE, "Hidden Edge, Flash in the Night"),
        (0x05FF, "Ukanlos Soul Hatchet"),
        (0x0600, "Doomed Soul"),
        (0x0601, "Old Yukumo Saber, Yukumo Saber, Yukumo Saber+, Yukumo Hatchet, True Yukumo Saber, True Yukumo Saber+, Divine Dance Saber"),
        (0x0602, "Usurper's Firebolt, Despot's Crookbolt"),
        (0x0603, "Evil Jade Storm"),
        (0x0604, "Baumfaller, Dendrotomy"),
        (0x0605, "Hypnos Knife, Hypnos Knife+, Morpheus Knife"),
        (0x0606, "Amethyst Claw, Harmethyst"),
        (0x0607, "Spiked Saber, Clawed Saber"),
        (0x0608, "Black Talon, Black Rex Sword"),
    ])

    # Hammer (type 7, base 0x0609)
    add_type(7, "Hammer", 0x0609, [
        # 0x0609: No Equipment - skip
        (0x060A, "Kurogane, Iron Devil"),
        (0x060B, "War Hammer, War Hammer+, War Mace"),
        (0x060C, "Iron Striker, Iron Striker+, Iron Impact"),
        (0x060D, "Hard Bone Hammer, Hard Bone Hammer+"),
        (0x060E, "Bone Bludgeon, Bone Bludgeon+"),
        (0x060F, "Ludroth Bone Mace"),
        (0x0610, "Hummingbird, Pua Kala, Pharmakon"),
        (0x0611, "Red Bludgeon, Huracan Hammer"),
        (0x0612, "Frozen Core, Frozen Core+, Cocytus"),
        (0x0613, "Brazenclout, Crimsonclout, Gigas Hammer"),
        (0x0614, "Carapace Hammer, Carapace Hammer+, Barroth Hammer"),
        (0x0615, "Devil's Due, Devil's Crush"),
        (0x0616, "Fang Hammer \"Echo\", Fang Hammer \"Ruin\", Jhen Mohran Hammer"),
        (0x0617, "Plume Flint, Plume Flint+, Peco Flint"),
        (0x0618, "Gaiasp, Gaiarch, Great Gaiarch"),
        (0x0619, "Egg Hammer, Gargwa Egg Hammer"),
        (0x061A, "Rusted Hammer, Tarnished Hammer, Worn Hammer, Weathered Hammer"),
        (0x061B, "Breath Core Hammer, Lava Core Hammer"),
        (0x061C, "Pulsating Core"),
        (0x061D, "Alatreon Hammer, Alatreon Metamorph"),
        (0x061E, "Ludroth Splashammer, Ludroth Splashammer+, Vodyanoy Hammer"),
        (0x061F, "Gunhammer, Gunhammer+, Deadeye Revolver"),
        (0x0620, "Striped Striker, Tigrex Hammer"),
        (0x0621, "Hidden Breaker, Hidden Breaker+, Night Eternal"),
        (0x0622, "Ukanlos Avalanche"),
        (0x0623, "Bull Hammer, Bull Head Hammer, Bull Tusk Hammer"),
        (0x0624, "Old Yukumo Mallet, Yukumo Mallet, Yukumo Mallet+, Yukumo Impact, True Yukumo Mallet, True Yukumo Mallet+, Spirit Mallet"),
        (0x0625, "Usurper's Thunder, Despot's Crackle"),
        (0x0626, "Evil Mystic Cloud"),
        (0x0627, "Jupiter's Sphere, Jupiter's Sphere+, Duramboros Fellmace"),
        (0x0628, "Binding Bludgeon, Binding Bludgeon+, Armored Gogue"),
        (0x0629, "Peco Lectro, Lightning Peco"),
        (0x062A, "Ice Crusher, Ice Obliterator"),
        (0x062B, "Meltroknuckle, Uragantic Hammer"),
        (0x062C, "Virnar Breaker, Midnight Aeternum"),
        (0x062D, "Leonid Starcrusher"),
        (0x062E, "Pumpking, Pumpkingdom, Pumpking Spirit Maul"),
        (0x062F, "Demon's Visage"),
    ])

    # Lance (type 8, base 0x0630)
    add_type(8, "Lance", 0x0630, [
        # 0x0630: No Equipment - skip
        (0x0631, "Warrior's Spear, Millennium"),
        (0x0632, "Thane Lance, Thane Lance+, Knight Lance"),
        (0x0633, "Rampart, Rampart+"),
        (0x0634, "Babel, Babel+, Elder Babel Spear"),
        (0x0635, "Hard Bone Lance, Hard Bone Lance+"),
        (0x0636, "Plohasta, Rhenohasta"),
        (0x0637, "Ludroth Bone Spear"),
        (0x0638, "Tusk Lance, Tusk Lance+, Sabertooth"),
        (0x0639, "Ukanlos Calamity"),
        (0x063A, "Drill Lance, Mega Drill Lance, Giga Drill Lance"),
        (0x063B, "Rugged Lance, Rugged Lance+, Barroth Carver"),
        (0x063C, "Spiral Heat, Spiral Heat+, Agnaktor Firelance"),
        (0x063D, "Diablos Lance, Diablos Lance+, Diablos Spear"),
        (0x063E, "Shadow Javelin, Shadow Javelin+, Toxic Javelin"),
        (0x063F, "Blue Crater, Smalt Crater, Doom Crown"),
        (0x0640, "Wild Boar Lance, Wild Boar Lance+, Bulldrome Spear"),
        (0x0641, "Grief Lance, Fiendish Tower"),
        (0x0642, "Rusted Lance, Tarnished Lance, Worn Spear, Weathered Spear"),
        (0x0643, "Undertaker, High Undertaker"),
        (0x0644, "Skyscraper"),
        (0x0645, "Alatreon Lance, Alatreon Gleam"),
        (0x0646, "Spiral Lance, Spiral Lance+, Spiral Slash"),
        (0x0647, "Brain Fox Lance, Hundred Fox Spear"),
        (0x0648, "Azure Crest, Azure Crest+, Great Azure"),
        (0x0649, "Sharq Byte, Sharq Attaq"),
        (0x064A, "Tiger Stinger, Tiger Stinger+, Tigrex Lance"),
        (0x064B, "Hidden Stinger, Night Rains Black"),
        (0x064C, "Red Tail, Hellfire, Spear of Prominence"),
        (0x064D, "Black Tempest"),
        (0x064E, "Old Yukumo Lance, Yukumo Lance, Yukumo Lance+, Yukumo Stinger, True Yukumo Lance, True Yukumo Lance+, Divine Lance"),
        (0x064F, "Usurper's Coming, Despot's Cacophony"),
        (0x0650, "Evil Cloudpiercer"),
        (0x0651, "Boros Spear, Temblor Illboros"),
        (0x0652, "Bella Nocuus, Bel Nefastro"),
        (0x0653, "Black Tiger Stinger, Black Tigrex Lance"),
        (0x0654, "Spiral Water, Agnaktor Aqualance"),
        (0x0655, "War Lance, War Lance \"Victory\""),
        (0x0656, "Plegis Needle, Plegis Needle+, Mighty Plegis"),
        (0x0657, "Longhorn Spear, Longhorn Spear+, Longtusk Spear"),
    ])

    # Heavy Bowgun (type 9, base 0x0658)
    add_type(9, "Heavy Bowgun", 0x0658, [
        # 0x0658: Unused - skip
        (0x0659, "Bone Blaster, Bone Shooter+, Bone Buster"),
        (0x065A, "Tropeco Gun, Tropeco Flambogun, Pecopious Gun"),
        (0x065B, "Dual Threat, Dual Threat+, Diablazooka"),
        (0x065C, "Agnaboom, Agnablaster, Agna Hellblazer"),
        (0x065D, "Chaos Wing"),
        (0x065E, "Jhen Cannon, Jhen Dracannon, Prosperity Dracannon"),
        (0x065F, "Aquamatic \"Needler\", Aquamatic \"Firelash\", Aquamatic \"Ashmaker\""),
        (0x0660, "Queen's Longfire, Queen's Farflier, Queen's Scionfire, Queen's Deityfire"),
        (0x0661, "Gigant Launcher, Gigant Cannon"),
        (0x0662, "Tigrex Howl, Tigrex Howl+, Tigrex Skull"),
        (0x0663, "Hidden Gambit, Baleful Night"),
        (0x0664, "Ukanlos Roar"),
        (0x0665, "Carbalite Cannon, Meteor Cannon"),
        (0x0666, "Old Yukumo Ballista, Yukumo Ballista, Yukumo Ballista+, Yukumo Heavy Cannon, Yukumo Cannon"),
        (0x0667, "Usurper's Tremor, Despot's Paroxysm"),
        (0x0668, "Evil Solstice Shower"),
        (0x0669, "Carrozza Bazooka, Queen's Carrozza, Cendrillon"),
        (0x066A, "Spheniscine Slayer, Spheniscine Enslaver, Spheniscine Ruler, Spheniscine Overlord"),
        (0x066B, "Type 46 Gunflage I, Type 46 Gunflage II, Type 46 Gunflage III, Nibelflage Prototype"),
        (0x066C, "Arzuros Gun, Arzuros Gun+, Arzuros Rumblegun, Arzuros Fishergun"),
        (0x066D, "Akantor Destroyer"),
        (0x066E, "Wishing Star, Meteorite, Great Meteor"),
        (0x066F, "Pecopious Thunder, Paco Pico Peco"),
        (0x0670, "Virnar Heavy Rifle, Sinister Midnight"),
        (0x0671, "Nero's Blazooka"),
        (0x0672, "Avel Agnagun"),
    ])

    # Light Bowgun (type 11, base 0x0673)
    # Note: file 0x0678 is missing (model_id 5 doesn't exist)
    add_type(11, "Light Bowgun", 0x0673, [
        # 0x0673: Unused - skip
        (0x0674, "Cross Bowgun, Cross Bowgun+, Cross Blitz"),
        (0x0675, "Hunter's Rifle, Sniper Shot"),
        (0x0676, "Royal Launcher, Royal Turrent, Royal Cataract, Royal Inundation, Royal Noah"),
        (0x0677, "Jaggid Fire, Jaggid Fire+, Bandit Fire, Bandit's Rage"),
        # 0x0678: Unused - skip
        (0x0679, "Rathling Gun, Rathling Gun+, Rathling Doombringer, Rathling Phoenix"),
        (0x067A, "Blizzard Cannon, Blizzard Volley, Tabula Blizzara"),
        (0x067B, "Poison Stinger, Poison Stinger+, Poison Aftermath, Immortal Shackle"),
        (0x067C, "Barro Barrel, Barro Barrel+, Barrozooka"),
        (0x067D, "Devil's Grin, Devil's Madness"),
        (0x067E, "Demon's Isle, God's Isle, Demon's Island, God's Island"),
        (0x067F, "Tigrex Tank, Tigrex Wargun"),
        (0x0680, "Hidden Eye, Hidden Eye+, Night Owl"),
        (0x0681, "Ukanlos Growl"),
        (0x0682, "Valkyrie Fire, Valkyrie Flame, Valkyrie Blaze"),
        (0x0683, "Blossomayhem"),
        (0x0684, "Old Yukumo Crossbow, Yukumo Crossbow, Yukumo Crossbow+, Yukumo Rifle, Yukumo Bullet Rain"),
        (0x0685, "Usurper's Crime, Despot's Wildfire"),
        (0x0686, "Evil Flash Flood"),
        (0x0687, "Durambarrel, Durambarrel+, Taurambarrel, Aldebaran Dreadgun"),
        (0x0688, "Aurora Flare, Avalauncher"),
        (0x0689, "Bloodthirsty Binder, Crimson Seeker"),
        (0x068A, "Black Tigrex Tank, Black Tigrex Panzer"),
        (0x068B, "Gourd Shot, Teasel Shot, Crookneck Shot"),
        (0x068C, "Kettleblower, Kettleblower Deluxe"),
        # 0x068D: Unused - skip
    ])

    # Long Sword (type 12, base 0x068E)
    add_type(12, "Long Sword", 0x068E, [
        # 0x068E: No Equipment - skip
        (0x068F, "Reaver \"Cruelty\", Reaver \"Calamity\""),
        (0x0690, "Wyvern Blade \"Fire\", Wyvern Blade \"Flame\", Wyvern Blade \"Flare\""),
        (0x0691, "Hidden Saber, Hidden Saber+, Deepest Night"),
        (0x0692, "Ananta Boneblade, Ananta Boneblade+, Shadowbinder"),
        (0x0693, "Barbarian Blade, Barbarian Blade+, Barbarian \"Sharq\""),
        (0x0694, "Guan Dao, Yan Yue Dao"),
        (0x0695, "Dark Claw, Dark Claw \"Demise\""),
        (0x0696, "Lightning Works"),
        (0x0697, "Tessaiga, Tessaiga D"),
        (0x0698, "Dancing Flames, Dancing Hellfire"),
        (0x0699, "Wyvern Blade \"Pale\""),
        (0x069A, "Tigrex Slasher, Tigrex Slasher+, Tigrex Annihilator"),
        (0x069B, "Rimeblade, Rimeblossom, Rime & Treason"),
        (0x069C, "Old Yukumo Blade, Yukumo Blade, Yukumo Blade+, Yukumo Longsword, True Yukumo Blade, True Yukumo Blade+, Spirit-Strike Blade"),
        (0x069D, "Usurper's Boltslicer, Despot's Boltbreaker"),
        (0x069E, "Evil Flooding Rain"),
        (0x069F, "Mountain Reaper, Mountain Archreaper, Wild Heights"),
        (0x06A0, "Arzuros Naginata, Arzuros Naginata+, Arzuros Strikequill"),
        (0x06A1, "Wroggi Sword, Wroggi Sword+, Nightshade's Bite"),
        (0x06A2, "Bleeding Cross, Bleeding Cross+, Mephitic Katana"),
        (0x06A3, "Diapason, Diapason+, Crimsonfork"),
        (0x06A4, "Drowning Shaft, Drowning Shaft+, Douser Bardiche"),
        (0x06A5, "Windeater, Soundeater, Zephyr"),
        (0x06A6, "Canine Katana, Lupine Katana, Guaruga Boneblade, Shadowblade"),
        (0x06A7, "Enfeebling Glaive, Dispatcher Glaive"),
        (0x06A8, "Crimson Cross, Lost Eden"),
        (0x06A9, "Chrome Mazurka, Chrome Waltz"),
        (0x06AA, "Virnar Saber, Depths of Midnight"),
        (0x06AB, "Hairtail Hairblade, Hairtail Hairblade+, Fresh Hairblade"),
        (0x06AC, "Chainslaughter, Chainslaughter+, Rumbalarum"),
        (0x06AD, "Supreme King Sword"),
        (0x06AE, "Akantor Widowmaker"),
        (0x06AF, "Ukanlos Slicer"),
        (0x06B0, "Iron Katana, Iron Grace, Iron Gospel"),
    ])

    # Switch Axe (type 13, base 0x06B1)
    add_type(13, "Switch Axe", 0x06B1, [
        # 0x06B1: No Equipment - skip
        (0x06B2, "Bone Axe, Bone Axe+, Bone Hacker, Bone Hacker+, Daedalus"),
        (0x06B3, "Assault Axe, Assault Axe+, Blitzkrieg, Bastion Blitz"),
        (0x06B4, "Fire Tempest, Fire Tempest+, Flame Tempest"),
        (0x06B5, "Demonbind, Demonbind+, Grand Demonbind"),
        (0x06B6, "Rough Edge, Tough Break, Soul Breaker"),
        (0x06B7, "Old Yukumo Switchaxe, Yukumo Switchaxe, Yukumo Switchaxe+, Yukumo Axe, True Yukumo Axe, True Yukumo Axe+, Founder's Switchaxe"),
        (0x06B8, "Grim Cat, Grim Cat+, Grimmig Katze"),
        (0x06B9, "Amber Slash, Amber Slash+, Amber Hoarfrost"),
        (0x06BA, "Binding Roller, Binding Roller+, Vermilingua"),
        (0x06BB, "Dark Switch Axe, Black Harvest"),
        (0x06BC, "Pirate J Axe"),
        (0x06BD, "Usurper's Downpour, Despot's Cloudburst"),
        (0x06BE, "Evil White Rain"),
        (0x06BF, "Heavy Divider, Heavy Divider+, Grunhart"),
        (0x06C0, "Arzuros Axe, Arzuros Axe+, Arzuros Revelax"),
        (0x06C1, "Hidden Axe, Hidden Axe+, Night's Crescent"),
        (0x06C2, "Akantor Subjugator"),
        (0x06C3, "Dragonmaiden Axe, Dragonmaiden Axe+, Gridr's Landmaker, Gridr's Landforger"),
        (0x06C4, "Pecospander, Pecospander+, Qurupexspander"),
        (0x06C5, "Wild Axe, Wild Axe+, Ground Dasher"),
        (0x06C6, "Axe Semper Tyrannis, Axe Semper Tyrannis+, Grand Chaos"),
        (0x06C7, "Sparqlepeco, Peco Volt"),
        (0x06C8, "Azurite Slash Axe, Gale Azurite"),
        (0x06C9, "Axe of Thanatos, Axe of Demons"),
        (0x06CA, "Liquid Storm, Aqua Tempest"),
    ])

    # Gunlance (type 14, base 0x06CB)
    add_type(14, "Gunlance", 0x06CB, [
        # 0x06CB: No Equipment - skip
        (0x06CC, "Rex Blast, Rex Blast+, Tigrex Gunlance"),
        (0x06CD, "Hidden Gunlance, Hidden Gunlance+, Fading Night"),
        (0x06CE, "Akantor Decimator"),
        (0x06CF, "Ukanlos Hail"),
        (0x06D0, "Striker's Gunlance, Defender's Gunlance, Imperial Guardlance"),
        (0x06D1, "Eisenritter, Eisenritter+, Solbite Burst"),
        (0x06D2, "Ancient Gyrelance, Ancient Gyresmite"),
        (0x06D3, "Bone Gunlance, Great Bone Gunlance, Wyvern Bone Gunlance"),
        (0x06D4, "Silver Rook, Chariot Gun"),
        (0x06D5, "Old Yukumo Gunlance, Yukumo Gunlance, Yukumo Gunlance+, Yukumo Burst, True Yukumo Burst, True Yukumo Burst+, Ascended Artillery"),
        (0x06D6, "Usurper's Roar, Despot's Phlogiston"),
        (0x06D7, "Evil Auspicious Rain"),
        (0x06D8, "Type 62 Stormlance, Type 62 Stormlance+, Assault Stormlance"),
        (0x06D9, "Jaggid Gunlance, Jaggid Gunlance+"),
        (0x06DA, "Princess Panoply, Princess Panoply+, Ortlinde"),
        (0x06DB, "Peco Teepee, Peco Teepee+, Dreamy Teepee"),
        (0x06DC, "Flamethrower, Flamethrower+, Agna Magma"),
        (0x06DD, "Worn Gunlance, Weathered Gunlance"),
        (0x06DE, "Obelisk"),
        (0x06DF, "Shattershot, Shatter Ace, Shatter God"),
        (0x06E0, "Lagomberator, Lagomberator+, Lagomberatrix"),
        (0x06E1, "Fang Breaker, Fangdemonium, Jhen Mortalis"),
        (0x06E2, "Red Rook, Red Rook+"),
        (0x06E3, "Thunder Feather, Thunderbird"),
        (0x06E4, "Virnar Gunlance, End of Night"),
        (0x06E5, "Queen's Panoply, Shining Ishtar"),
        (0x06E6, "Waterthrower, Agna Aqua"),
        (0x06E7, "Felyoshka, Felicitous Felyoshka"),
        (0x06E8, "Bamboo Scarecrow, Bamboo Avianward, Bamboo Dragonsbane"),
        (0x06E9, "Platinum Crown"),
        (0x06EA, "Gold Crown, Gold Crown+"),
        (0x06EB, "Silver Crown, Silver Crown+"),
    ])

    # Bow (type 15, base 0x06EC)
    add_type(15, "Bow", 0x06EC, [
        # 0x06EC: Unused - skip
        (0x06ED, "Tiger Arrow, Tigrex Whisker"),
        (0x06EE, "Hidden Bow I, Hidden Bow II, Night Flight"),
        (0x06EF, "Akantor Wrathmaker"),
        (0x06F0, "Ukanlos Frostbreath"),
        (0x06F1, "Hunter's Bow I, Hunter's Bow II, Hunter's Bow III"),
        (0x06F2, "Hunter's Stoutbow I, Hunter's Stoutbow II"),
        (0x06F3, "Queen Blaster I, Queen Blaster II, Queen Blaster III"),
        (0x06F4, "Diablos Hornbow I, Diablos Hornbow II"),
        (0x06F5, "Cera Coilbender"),
        (0x06F6, "Old Yukumo Bow, Yukumo Bow, Yukumo Bow+, True Yukumo Bow, Army Vanquisher Bow"),
        (0x06F7, "Usurper's Rumble I, Usurper's Rumble II, Despot's Earlybolt"),
        (0x06F8, "Evil Night Tempest"),
        (0x06F9, "Type 64 Multibow I, Type 64 Multibow II, Type 64 Multibow III, Scorpion Zinger"),
        (0x06FA, "Peckish Peco, Famished Peco, Insatiable Peco, Heartbreaker"),
        (0x06FB, "Ice Crest I, Ice Crest II, Edelweiss"),
        (0x06FC, "Brazencord I, Brazencord II, Brazencord III, Gigacles"),
        (0x06FD, "Sponge Gear I, Sponge Gear II, Sponge Gear III"),
        (0x06FE, "Worldseer's Bow, Worldseer's Proof, Worldseer's Bounty"),
        (0x06FF, "Arca Raptora, Arca Chaotica, Arca Insantia, Amnis"),
        (0x0700, "Wroggi Revolver I, Wroggi Revolver II, Wroggi Revolver III, Dirty Revolver"),
        (0x0701, "Arko Nulo, Arko Unu, Arko Nulo(R), Arko Nulo(W), Arko Nulo(Y), Arko Unu(R), Arko Unu(W), Arko Unu(Y), Arko Du(R), Arko Du(W), Arko Du(Y)"),
        (0x0702, "Amethyst Gear I, Amethyst Gear II, Amir al Bahr"),
        (0x0703, "Lithe Saberbow, Fallenfriede"),
        (0x0704, "Virnar Bow, Midnight Farflight"),
        (0x0705, "Selene Moonbroken"),
        (0x0706, "Kelbi Stingshot, Kelbi Strongshot"),
        (0x0707, "Bamboo Taketori, Bamboo Okina, Bamboo Kaguya"),
        # 0x0708: Unused - skip
    ])

    # Dual Blades (type 16, base 0x0709)
    add_type(16, "Dual Blades", 0x0709, [
        # 0x0709: No Equipment - skip
        (0x070A, "Rex Slicers, Tigrex Claws"),
        (0x070B, "Hidden Gemini, Hidden Gemini+, Night Wings"),
        (0x070C, "Akantor Blades"),
        (0x070D, "Ukanlos Rippers"),
        (0x070E, "Dual Hatchets, Dual Hatchets+"),
        (0x070F, "Twin Chainsaws, Twin Chainsaws+, Guillotines"),
        (0x0710, "Sworn Rapiers, Holy Sabers"),
        (0x0711, "Matched Slicers, Matched Slicers+, Dual Slicers"),
        (0x0712, "Hurricane, Cyclone"),
        (0x0713, "Bone Scythes, Bone Scythes+"),
        (0x0714, "Worn Blade, Weathered Blades"),
        (0x0715, "Enduring Schism"),
        (0x0716, "Brother Flames, Brother Blazes, Wyvern Lovers"),
        (0x0717, "Wyvern Strife"),
        (0x0718, "Old Yukumo Dual, Yukumo Duals, Yukumo Duals+, Yukumo Slicers, True Yukumo Duals, True Yukumo Duals+, Worship Dance Duals"),
        (0x0719, "Usurper's Fulgur, Despot's Blitz"),
        (0x071A, "Evil Monsoon"),
        (0x071B, "Type 51 Macerators, Type 51 Macerators+, Deathsnarfs"),
        (0x071C, "Jaggid Shotels, Jaggid Shotels+, Leader's Shotels"),
        (0x071D, "Bloodwings, Bloodwings+, Venom Wings"),
        (0x071E, "Wrath & Rancor, Wrathful Predation"),
        (0x071F, "Flamestorm, Salamanders"),
        (0x0720, "Snow Slicers, Snow Slicers+, Snow Sisters"),
        (0x0721, "Diablos Bashers, Diablos Bashers+, Diablos Mashers"),
        (0x0722, "Boltgeist, Double Boltwings"),
        (0x0723, "Virnar Slicers, Midnight Blackwings"),
        (0x0724, "Aqua Stream, Undine"),
        (0x0725, "Ludroth Pair, Ludroth Pair+, Double Droth"),
        (0x0726, "Plain Dumplings, White Dumplings, Ivory Dumplings, Ice Dumplings, Frost Dumplings, Fire Dumplings, Inferno Dumplings, Thunder Dumplings, Lightning Dumplings, Poison Dumplings, Venom Dumplings"),
        (0x0727, "Korunu Waaga, Wandering Rowaaga, Korunu Waaga+"),
        (0x0728, "Pirate J Knives, Hi Pirate J Knives"),
    ])

    # Hunting Horn (type 17, base 0x0729)
    add_type(17, "Hunting Horn", 0x0729, [
        # 0x0729: No Equipment - skip
        (0x072A, "Striped Gong, Striped Dragonga, Tigrex Horn"),
        (0x072B, "Hidden Harmonic, Cry in the Night"),
        (0x072C, "Akantor Deathknell"),
        (0x072D, "Ukanlos Howler"),
        (0x072E, "Metal Bagpipe, Metal Bagpipe+, Great Bagpipe"),
        (0x072F, "Gold Chordmaker"),
        (0x0730, "Hard Bone Horn, Hard Bone Horn+, Heavy Bone Horn"),
        (0x0731, "Old Yukumo Whistle, Yukumo Whistle, Yukumo Whistle+, Yukumo Horn, True Yukumo Whistle, True Yukumo Whistle+, Chidori Whistle"),
        (0x0732, "Usurper's Growl, Despot's Thunderclap"),
        (0x0733, "Evil Autumn Typhoon"),
        (0x0734, "Type 63 Warmonica, Type 63 Warmonica+, Snarfonix"),
        (0x0735, "Zurogong Primo, Zurogong Secundo, Zurogong Tertio"),
        (0x0736, "Black Coffin, Shadow Coffin, Darkest Coffin"),
        (0x0737, "Sandpipe, Sandcrier, Sandscreecher"),
        (0x0738, "Brazengaita, Brazengaita+, Gigas Gaita"),
        (0x0739, "Droth Drone, Droth Drone+, Droth Roar"),
        (0x073A, "Bariguiro, Bariguiro+, Algiguiro"),
        (0x073B, "Agnakdion, Agnakdion+, Brandoneon"),
        (0x073C, "Worn Horn, Weathered Horn"),
        (0x073D, "Avenir's Music Box"),
        (0x073E, "Vicello Nulo, Vicello Unu, Vicello Nulo(W), Vicello Unu(W), Vicello Nulo(Y), Vicello Unu(Y), Vicello Nulo(G), Vicello Unu(G), Vicello Du(G)"),
        (0x073F, "Qurupeco Horn, Qurupeco Trumpet, Qurupeco Honker"),
        (0x0740, "Valkyrie Chordmaker, Valkyrie Chordmaker+, Queen's Chordmaker"),
        (0x0741, "Ice Kazoo, Glacial Kazoo"),
        (0x0742, "Bloodstopper, Bloodcurtler"),
        (0x0743, "Cindervone, Scaldrovone"),
        (0x0744, "Black Dragonga, Black Tigrex Horn"),
        (0x0745, "Magia Charm, Magia Charmbell, Magia Charm+"),
        (0x0746, "Swell Shell, Swell Shell+, Vertex Shell"),
        (0x0747, "Blitzworks, Giga Blitzworks"),
        (0x0748, "Heavy Bagpipe, Heavy Bagpipe+, Fortissimo"),
    ])

    return weapons


def main():
    # Read existing data
    with open(INPUT_PATH, "r") as f:
        data = json.load(f)

    # Build new weapon data
    new_weapons = define_weapons()

    # Replace weapons section
    data["weapons"] = new_weapons

    # Remove unused fields that were from the old table-based approach
    # (these would be at weapon type level: table_base, entry_size, model_offset, total_entries, type_id)
    # Also remove per-weapon entry fields like "entries"
    for type_id, type_data in data["weapons"].items():
        for key in ["table_base", "entry_size", "model_offset", "total_entries", "type_id"]:
            type_data.pop(key, None)
        for model_id, wep in type_data.get("weapons", {}).items():
            for key in ["entries"]:
                wep.pop(key, None)

    # Write to both output paths
    for path in OUTPUT_PATHS:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Written: {path}")

    # Print summary
    total_models = 0
    total_weapons = 0
    for type_id in sorted(data["weapons"].keys(), key=int):
        t = data["weapons"][type_id]
        n_models = len(t["weapons"])
        n_weps = sum(len(w["names"]) for w in t["weapons"].values())
        total_models += n_models
        total_weapons += n_weps
        print(f"  Type {type_id:>2} ({t['type_name']:>16}): {n_models:>3} models, {n_weps:>3} weapons")
    print(f"  TOTAL: {total_models} models, {total_weapons} weapons")


if __name__ == "__main__":
    main()
