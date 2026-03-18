#!/usr/bin/env python3
"""Patch a texture PNG into a MHP3rd PAC file's TMH entry."""

import struct
import sys
from io import BytesIO
from PIL import Image

# TMH/GIM constants
WIDTH_BLOCK = 16
HEIGHT_BLOCK = 8

INDEX_FORMAT = [(4, 4), (5, 8)]  # CLUT4, CLUT8

PALETTE_TYPES = {
    'RGBA5650': 0,
    'RGBA5551': 1,
    'RGBA4444': 2,
    'RGBA8888': 3,
}


def png_to_indexed(png_path):
    """Load PNG, quantize to 256 colors, return (width, height, indices, colors_rgba_float)."""
    img = Image.open(png_path).convert('RGBA')
    width, height = img.size
    pixels = list(img.getdata())  # list of (R,G,B,A) tuples, 0-255

    # Build palette (preserve order of first appearance)
    colors = []
    color_map = {}
    indices = []

    # TMH stores top-to-bottom (no flip needed)
    for r, g, b, a in pixels:
            key = (r, g, b, a)
            if key not in color_map:
                if len(colors) >= 256:
                    raise ValueError(f"Image has more than 256 unique colors. Quantize first.")
                color_map[key] = len(colors)
                colors.append((r / 255.0, g / 255.0, b / 255.0, a / 255.0))
            indices.append(color_map[key])

    return width, height, indices, colors


def determine_data_type(indices):
    """4 = CLUT4 (<=16 colors), 5 = CLUT8 (<=256 colors)."""
    max_idx = max(indices)
    if max_idx < 16:
        return 4
    elif max_idx < 256:
        return 5
    else:
        raise ValueError("Too many colors")


def determine_palette_type(colors):
    """Determine best palette encoding from alpha values."""
    alphas = set(c[3] for c in colors)
    if alphas == {1.0}:
        return 'RGBA5650'
    if alphas <= {0.0, 1.0}:
        return 'RGBA5551'
    unique_alpha = len(set(c[3] for c in colors))
    if unique_alpha > 16:
        return 'RGBA8888'
    return 'RGBA4444'


def swizzle_pixels(indices, width, height, data_type):
    """Block-swizzle pixel indices for GIM format."""
    modifier = 2 if data_type == 4 else 1
    l_width_block = min(WIDTH_BLOCK * modifier, width)

    data = []
    for block_v in range(max(1, height // HEIGHT_BLOCK)):
        for block_h in range(max(1, width // l_width_block)):
            for pixel_v in range(HEIGHT_BLOCK):
                for pixel_h in range(l_width_block):
                    offset = (block_v * HEIGHT_BLOCK + pixel_v) * width + (block_h * l_width_block + pixel_h)
                    data.append(indices[offset])

    if data_type == 4:
        data = [x | (y << 4) for x, y in zip(data[::2], data[1::2])]

    return bytes(data)


def encode_palette(colors, pal_type):
    """Encode palette colors to binary."""
    entries = []
    if pal_type == 'RGBA5650':
        for r, g, b, a in colors:
            val = int(r * 31) | (int(g * 63) << 5) | (int(b * 31) << 11)
            entries.append(struct.pack('<H', val))
    elif pal_type == 'RGBA5551':
        for r, g, b, a in colors:
            val = int(r * 31) | (int(g * 31) << 5) | (int(b * 31) << 10) | (int(a) << 15)
            entries.append(struct.pack('<H', val))
    elif pal_type == 'RGBA4444':
        for r, g, b, a in colors:
            val = int(r * 15) | (int(g * 15) << 4) | (int(b * 15) << 8) | (int(a * 15) << 12)
            entries.append(struct.pack('<H', val))
    elif pal_type == 'RGBA8888':
        for r, g, b, a in colors:
            val = int(r * 255) | (int(g * 255) << 8) | (int(b * 255) << 16) | (int(a * 255) << 24)
            entries.append(struct.pack('<I', val))
    return b''.join(entries)


def build_tmh(png_path, force_palette_type=None):
    """Build a TMH binary from a PNG file."""
    width, height, indices, colors = png_to_indexed(png_path)
    data_type = determine_data_type(indices)
    pal_type = force_palette_type or determine_palette_type(colors)

    # Pad palette to 16 or 256 entries
    pad_count = 16 if data_type == 4 else 256
    while len(colors) < pad_count:
        colors.append((0.0, 0.0, 0.0, 1.0))

    # Swizzle pixel data
    pixel_data = swizzle_pixels(indices, width, height, data_type)

    # Image data section (0x10 header + pixel data)
    data_size = len(pixel_data) + 0x10

    # Palette section
    color_size = 4 if pal_type == 'RGBA8888' else 2
    pal_data = encode_palette(colors, pal_type)
    pal_size = pad_count * color_size + 0x10

    # GIM total size
    gim_size = data_size + pal_size + 0x10

    fd = BytesIO()
    # TMH header
    fd.write(b'.TMH0.14')
    fd.write(struct.pack('<I4x', 1))  # 1 image

    # GIM header
    flags = [0, 1, 1]
    fd.write(struct.pack('<4i', gim_size, *flags))

    # Image data header
    fd.write(struct.pack('<3i', data_size, 1, data_type))
    fd.write(struct.pack('<2H', width, height))

    # Pixel data
    fd.write(pixel_data)

    # Palette header
    fd.write(struct.pack('<4I', pal_size, 2, PALETTE_TYPES[pal_type], len(colors)))

    # Palette data
    fd.write(pal_data)

    return fd.getvalue()


def patch_pac(pac_path, tmh_data, output_path):
    """Replace the TMH entry (entry with .TMH magic) in a PAC file."""
    with open(pac_path, 'rb') as f:
        pac = f.read()

    count = struct.unpack_from('<I', pac, 0)[0]

    # Find TMH entry
    tmh_idx = None
    entries = []
    for i in range(count):
        offset, length = struct.unpack_from('<II', pac, 4 + i * 8)
        entries.append((offset, length))
        if pac[offset:offset + 4] == b'.TMH':
            tmh_idx = i

    if tmh_idx is None:
        raise ValueError("No TMH entry found in PAC")

    # Rebuild PAC with new TMH
    header_size = 4 + count * 8
    header_size += (16 - (header_size % 16)) % 16

    fd = BytesIO()
    fd.write(struct.pack('<I', count))
    fd.seek(header_size)

    new_entries = []
    for i in range(count):
        # Align to 16 bytes
        pos = fd.tell()
        pad = (16 - (pos % 16)) % 16
        if pad:
            fd.write(b'\x00' * pad)

        offset = fd.tell()
        if i == tmh_idx:
            fd.write(tmh_data)
            new_entries.append((offset, len(tmh_data)))
        else:
            orig_offset, orig_length = entries[i]
            fd.write(pac[orig_offset:orig_offset + orig_length])
            new_entries.append((offset, orig_length))

    # Write index table
    fd.seek(4)
    for offset, length in new_entries:
        fd.write(struct.pack('<II', offset, length))

    with open(output_path, 'wb') as f:
        f.write(fd.getvalue())

    print(f"Wrote {output_path} ({fd.tell()} bytes)")
    print(f"  TMH entry {tmh_idx}: {len(tmh_data)} bytes (was {entries[tmh_idx][1]} bytes)")


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <original.pac> <replacement.png> <output.pac> [palette_type]")
        print(f"  palette_type: RGBA5650, RGBA5551, RGBA4444, RGBA8888 (default: auto)")
        sys.exit(1)

    pac_path = sys.argv[1]
    png_path = sys.argv[2]
    output_path = sys.argv[3]
    pal_type = sys.argv[4] if len(sys.argv) > 4 else None

    tmh = build_tmh(png_path, pal_type)
    patch_pac(pac_path, tmh, output_path)
