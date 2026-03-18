#!/usr/bin/env python3
"""Analyze MHP3rd EBOOT.BIN - handles ~PSP encrypted format and save states."""

import struct
import os
import sys
import zstandard

EBOOT_PATH = "/Users/Exceen/Downloads/mhp3rd_modding/eboot_extract/EBOOT.BIN"
SAVE_STATE_DIR = "/Users/Exceen/Documents/PPSSPP/PSP/PPSSPP_STATE/"
GAME_ID = "NPJB40001"  # MHP3rd Japanese

def parse_psp_header(data):
    """Parse ~PSP encrypted EBOOT header."""
    magic = data[0:4]
    assert magic == b'~PSP', f"Not a ~PSP file: {magic}"

    print("=== ~PSP Encrypted EBOOT Header ===")
    print(f"Magic: {magic}")
    print(f"File size: {len(data)} bytes (0x{len(data):X})")
    print()

    # ~PSP header layout (common fields):
    # 0x04-0x05: attribute (version)
    # 0x0A-0x1F: module name (null-terminated)
    # 0x24: version
    # 0x28: data size (or similar)
    # 0x2C: total file size
    # 0x30: entry point offset or boot info
    # 0x34: data offset or size
    # 0x38: decompressed size
    # 0x44: text_addr (module load address)

    module_name = data[0x0A:0x1F].split(b'\x00')[0].decode('ascii', errors='replace')
    print(f"Module name: {module_name}")

    fields = {
        0x04: "attr/version",
        0x24: "version2",
        0x28: "data_size",
        0x2C: "file_size",
        0x30: "entry/boot",
        0x34: "data_offset",
        0x38: "decomp_size",
        0x3C: "field_3C",
        0x40: "field_40",
        0x44: "text_addr",
        0x48: "field_48",
        0x50: "field_50",
    }

    for off, name in sorted(fields.items()):
        if off + 4 <= len(data):
            val = struct.unpack_from('<I', data, off)[0]
            print(f"  0x{off:02X} ({name:14s}): 0x{val:08X} ({val})")

    text_addr = struct.unpack_from('<I', data, 0x44)[0]
    print()
    print(f"*** EBOOT_BASE (text_addr from ~PSP header) = 0x{text_addr:08X} ***")
    print()
    return text_addr


def find_save_state():
    """Find a MHP3rd save state to extract decrypted memory."""
    if not os.path.isdir(SAVE_STATE_DIR):
        return None
    for f in sorted(os.listdir(SAVE_STATE_DIR)):
        if f.startswith(GAME_ID) and f.endswith('.ppst'):
            return os.path.join(SAVE_STATE_DIR, f)
    return None


def analyze_decrypted_memory(save_state_path, text_addr):
    """Extract and analyze decrypted ELF from save state memory dump."""
    print(f"=== Analyzing save state: {os.path.basename(save_state_path)} ===")
    print()

    with open(save_state_path, 'rb') as f:
        raw = f.read()

    # PPSSPP save state: 0xB0 header, then zstd compressed
    header = raw[:0xB0]
    compressed = raw[0xB0:]

    dctx = zstandard.ZstdDecompressor()
    try:
        mem = dctx.decompress(compressed, max_output_size=256 * 1024 * 1024)
    except Exception as e:
        print(f"  Decompression failed: {e}")
        return

    print(f"  Save state decompressed: {len(mem)} bytes (0x{len(mem):X})")

    # Memory offset: PSP_addr - 0x08000000 + 0x48
    # But we need to find where the ELF/code actually lives
    # text_addr is typically 0x08804000 for MHP3rd
    # In save state memory: offset = text_addr - 0x08000000 + 0x48

    base_offset = text_addr - 0x08000000 + 0x48
    print(f"  text_addr 0x{text_addr:08X} -> save state offset 0x{base_offset:X}")

    if base_offset >= len(mem):
        print(f"  ERROR: offset beyond save state size")
        return

    # Check for valid code at that offset (MIPS instructions shouldn't be all zeros)
    sample = mem[base_offset:base_offset+32]
    print(f"  First 32 bytes at text_addr: {sample.hex()}")

    # Look for ELF header in memory (PPSSPP might store it)
    # The ELF header might be at 0x08804000 or nearby
    # Let's also check 0x08800000
    for check_addr in [0x08800000, text_addr - 0x1000, text_addr]:
        off = check_addr - 0x08000000 + 0x48
        if 0 <= off < len(mem) - 4:
            magic = mem[off:off+4]
            if magic == b'\x7fELF':
                print(f"  ELF header found at PSP addr 0x{check_addr:08X} (save state offset 0x{off:X})")

    # Now scan for the code region to find its extent
    # We'll look at the decrypted EBOOT code region in memory
    # Estimate EBOOT code+data size from the ~PSP header decomp_size field

    # First, let's find the actual ELF in memory by scanning
    print()
    print("=== Scanning for ELF header in save state ===")
    elf_offset = None
    for i in range(0, min(len(mem), 0x2000000), 4):  # scan first 32MB
        if mem[i:i+4] == b'\x7fELF':
            psp_addr = i - 0x48 + 0x08000000
            print(f"  ELF magic at save state offset 0x{i:X} -> PSP addr 0x{psp_addr:08X}")
            elf_offset = i
            break

    if elf_offset is None:
        print("  No ELF header found in save state (PPSSPP may not preserve it)")
        print("  Will analyze code region directly from text_addr")
        print()
        analyze_code_region(mem, text_addr, base_offset)
        return

    # Parse ELF from memory
    print()
    analyze_elf_from_memory(mem, elf_offset, text_addr)


def analyze_elf_from_memory(mem, elf_offset, text_addr):
    """Parse ELF header found in save state memory."""
    data = mem[elf_offset:]

    ei_class = data[4]
    ei_data = data[5]
    e_machine = struct.unpack_from('<H', data, 18)[0]
    e_entry = struct.unpack_from('<I', data, 24)[0]
    e_phoff = struct.unpack_from('<I', data, 28)[0]
    e_phnum = struct.unpack_from('<H', data, 44)[0]
    e_phentsize = struct.unpack_from('<H', data, 42)[0]

    print(f"=== ELF Header (from save state memory) ===")
    print(f"Class: {'32-bit' if ei_class == 1 else '64-bit'}, Endian: {'LE' if ei_data == 1 else 'BE'}, Machine: 0x{e_machine:X}")
    print(f"Entry point: 0x{e_entry:08X}")
    print(f"Program headers: {e_phnum} at offset 0x{e_phoff:X}")
    print()

    print(f"{'#':>2} {'Type':<10} {'VAddr':>10} {'FileOff':>10} {'FileSz':>10} {'MemSz':>10} {'Flags':>6}")
    print("-" * 65)

    load_segments = []
    for i in range(min(e_phnum, 16)):
        off = e_phoff + i * e_phentsize
        if off + 32 > len(data):
            break
        p_type = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<I', data, off + 4)[0]
        p_vaddr = struct.unpack_from('<I', data, off + 8)[0]
        p_filesz = struct.unpack_from('<I', data, off + 16)[0]
        p_memsz = struct.unpack_from('<I', data, off + 20)[0]
        p_flags = struct.unpack_from('<I', data, off + 24)[0]

        PT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 6: "PHDR", 0x70000001: "MIPS_REG"}
        type_name = PT_TYPES.get(p_type, f"0x{p_type:X}")
        flags_str = ("R" if p_flags & 4 else "") + ("W" if p_flags & 2 else "") + ("X" if p_flags & 1 else "")

        print(f"{i:>2} {type_name:<10} 0x{p_vaddr:08X} 0x{p_offset:08X} 0x{p_filesz:08X} 0x{p_memsz:08X} {flags_str:>6}")

        if p_type == 1:
            load_segments.append((p_vaddr, p_offset, p_filesz, p_memsz, flags_str))

    if load_segments:
        first_vaddr = load_segments[0][0]
        print(f"\n*** EBOOT_BASE = 0x{first_vaddr:08X} ***\n")

        # Calculate code region in memory for zero-scan
        last_seg = load_segments[-1]
        code_end_vaddr = last_seg[0] + last_seg[2]  # vaddr + filesz
        code_end_memsz = last_seg[0] + last_seg[3]    # vaddr + memsz
        total_code_size = code_end_vaddr - first_vaddr
        print(f"Code+data region: 0x{first_vaddr:08X} - 0x{code_end_vaddr:08X} ({total_code_size} bytes, 0x{total_code_size:X})")
        print(f"With BSS: up to 0x{code_end_memsz:08X}")


def analyze_code_region(mem, text_addr, base_offset):
    """Analyze the code region for zero runs when no ELF header is available."""
    # The ~PSP header decomp_size (0x38) = 0x01461EB0 is the full decompressed size.
    # Scan the full decompressed region.
    scan_size = 0x01461EB0  # from ~PSP header field 0x38 (decomp_size)
    print(f"Scanning {scan_size} bytes (0x{scan_size:X}, ~{scan_size/1024/1024:.1f}MB) from text_addr 0x{text_addr:08X}")
    print()

    end_offset = base_offset + scan_size
    if end_offset > len(mem):
        scan_size = len(mem) - base_offset
        end_offset = len(mem)
        print(f"  (clamped to {scan_size} bytes)")

    region = mem[base_offset:end_offset]
    scan_for_zero_runs(region, text_addr, scan_size)


def scan_for_zero_runs(region, base_vaddr, region_size):
    """Scan a memory region for runs of zero bytes."""
    MIN_RUN = 512
    runs = []
    run_start = None
    in_run = False

    for i in range(len(region)):
        if region[i] == 0:
            if not in_run:
                run_start = i
                in_run = True
        else:
            if in_run:
                run_len = i - run_start
                if run_len >= MIN_RUN:
                    runs.append((run_start, run_len))
                in_run = False

    if in_run:
        run_len = len(region) - run_start
        if run_len >= MIN_RUN:
            runs.append((run_start, run_len))

    print(f"=== Zero-byte runs >= {MIN_RUN} bytes in code/data region ===")
    if not runs:
        print("  No runs found.")
        return

    print(f"  Found {len(runs)} runs:")
    print(f"  {'#':>3} {'VA Start':>12} {'VA End':>12} {'Length':>10} {'Position'}")
    print("  " + "-" * 60)

    for idx, (roff, rlen) in enumerate(runs):
        va = base_vaddr + roff
        va_end = va + rlen
        pct = roff / len(region) * 100
        notes = ""
        if roff + rlen >= len(region):
            notes = " <-- AT END"
        elif pct > 90:
            notes = " <-- near end"
        if rlen >= 2048:
            notes += " [>= 2KB OK]"

        print(f"  {idx:>3} 0x{va:08X}   0x{va_end:08X}   {rlen:>8} (0x{rlen:X})  {pct:.1f}%{notes}")

    print()
    # Best candidates
    candidates = sorted([(roff, rlen) for roff, rlen in runs if rlen >= 2048],
                        key=lambda x: x[0], reverse=True)
    print(f"=== Best candidates for ~2KB code cave (sorted by position, near end preferred) ===")
    if not candidates:
        print("  No runs >= 2KB. Largest runs:")
        for roff, rlen in sorted(runs, key=lambda x: x[1], reverse=True)[:5]:
            va = base_vaddr + roff
            print(f"    VA 0x{va:08X}, {rlen} bytes")
    else:
        for roff, rlen in candidates[:10]:
            va = base_vaddr + roff
            # Align VA up to 4-byte boundary for MIPS
            aligned_va = (va + 3) & ~3
            lost = aligned_va - va
            usable = rlen - lost
            pct = roff / len(region) * 100
            print(f"  VA 0x{va:08X} (aligned: 0x{aligned_va:08X}), {rlen} bytes (0x{rlen:X}), usable aligned: {usable}, at {pct:.1f}%")


def main():
    # --- Step 1: Parse ~PSP header ---
    with open(EBOOT_PATH, "rb") as f:
        eboot_data = f.read()

    print(f"=== MHP3rd EBOOT.BIN Analysis ===")
    print(f"File: {EBOOT_PATH}")
    print(f"File size: {len(eboot_data)} bytes (0x{len(eboot_data):X})")
    print()

    magic = eboot_data[0:4]
    if magic == b'\x7fELF':
        print("File is a raw ELF (not encrypted)")
        analyze_raw_elf(eboot_data)
        return
    elif magic == b'~PSP':
        text_addr = parse_psp_header(eboot_data)
    else:
        print(f"Unknown format: {magic.hex()}")
        sys.exit(1)

    # --- Step 2: Try to get decrypted memory from save state ---
    save_state = find_save_state()
    if save_state:
        analyze_decrypted_memory(save_state, text_addr)
    else:
        print(f"No save state found for {GAME_ID}")
        print("To analyze the decrypted EBOOT, create a save state in PPSSPP while running MHP3rd")


def analyze_raw_elf(data):
    """Analyze a raw ELF file directly."""
    ei_class = data[4]
    ei_data = data[5]
    e_machine = struct.unpack_from('<H', data, 18)[0]
    e_entry = struct.unpack_from('<I', data, 24)[0]
    e_phoff = struct.unpack_from('<I', data, 28)[0]
    e_phnum = struct.unpack_from('<H', data, 44)[0]
    e_phentsize = struct.unpack_from('<H', data, 42)[0]

    print(f"ELF: {'32-bit' if ei_class == 1 else '64-bit'}, {'LE' if ei_data == 1 else 'BE'}, machine=0x{e_machine:X}")
    print(f"Entry: 0x{e_entry:08X}, {e_phnum} program headers")
    print()

    load_segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<I', data, off + 4)[0]
        p_vaddr = struct.unpack_from('<I', data, off + 8)[0]
        p_filesz = struct.unpack_from('<I', data, off + 16)[0]
        p_memsz = struct.unpack_from('<I', data, off + 20)[0]
        p_flags = struct.unpack_from('<I', data, off + 24)[0]

        PT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 6: "PHDR"}
        type_name = PT_TYPES.get(p_type, f"0x{p_type:X}")
        flags_str = ("R" if p_flags & 4 else "") + ("W" if p_flags & 2 else "") + ("X" if p_flags & 1 else "")
        print(f"  [{i}] {type_name:<10} VA=0x{p_vaddr:08X} off=0x{p_offset:08X} fsz=0x{p_filesz:08X} msz=0x{p_memsz:08X} {flags_str}")

        if p_type == 1:
            load_segments.append((p_vaddr, p_offset, p_filesz, p_memsz))

    if load_segments:
        print(f"\n*** EBOOT_BASE = 0x{load_segments[0][0]:08X} ***\n")
        # Scan the file itself for zero runs
        scan_for_zero_runs(data, 0, len(data))


if __name__ == "__main__":
    main()
