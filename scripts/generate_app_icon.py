"""Generate professional Windows (.ico), PNG, and macOS (.icns) application icons for Red Mercury."""
import io
import os
import struct
from PIL import Image, ImageDraw


def create_redmercury_icon(size=1024):
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    pad = int(size * 0.05)
    r = int(size * 0.22)
    for i in range(pad, size - pad):
        factor = (i - pad) / max(1, (size - 2 * pad))
        r_col = int(15 * (1 - factor) + 9 * factor)
        g_col = int(23 * (1 - factor) + 13 * factor)
        b_col = int(42 * (1 - factor) + 22 * factor)
        draw.line([(pad, i), (size - pad, i)], fill=(r_col, g_col, b_col, 255))

    mask = Image.new("L", (size, size), 0)
    mask_draw = ImageDraw.Draw(mask)
    mask_draw.rounded_rectangle([pad, pad, size - pad, size - pad], radius=r, fill=255)

    bg_image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg_image.paste(image, (0, 0), mask)
    image = bg_image
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle([pad, pad, size - pad, size - pad], radius=r, outline=(51, 65, 85, 255), width=max(2, int(size * 0.015)))

    cx, cy = size // 2, int(size * 0.48)
    w = int(size * 0.58)
    h = int(size * 0.65)

    top = cy - h // 2
    bottom = cy + h // 2
    left = cx - w // 2
    right = cx + w // 2

    shield_points = [
        (cx, top),
        (right, top + int(h * 0.15)),
        (right, cy + int(h * 0.05)),
        (cx, bottom),
        (left, cy + int(h * 0.05)),
        (left, top + int(h * 0.15)),
    ]

    shield_mask = Image.new("L", (size, size), 0)
    s_draw = ImageDraw.Draw(shield_mask)
    s_draw.polygon(shield_points, fill=255)

    shield_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    s_draw_fill = ImageDraw.Draw(shield_img)
    for y in range(top, bottom + 1):
        f = (y - top) / max(1, (bottom - top))
        cr = int(56 * (1 - f) + 79 * f)
        cg = int(189 * (1 - f) + 70 * f)
        cb = int(248 * (1 - f) + 229 * f)
        s_draw_fill.line([(left, y), (right, y)], fill=(cr, cg, cb, 255))

    image.paste(shield_img, (0, 0), shield_mask)

    inner_pad = int(size * 0.04)
    inner_points = [
        (cx, top + inner_pad),
        (right - inner_pad, top + int(h * 0.15) + int(inner_pad * 0.7)),
        (right - inner_pad, cy + int(h * 0.03)),
        (cx, bottom - inner_pad),
        (left + inner_pad, cy + int(h * 0.03)),
        (left + inner_pad, top + int(h * 0.15) + int(inner_pad * 0.7)),
    ]
    draw.polygon(inner_points, outline=(255, 255, 255, 140), width=max(1, int(size * 0.012)))

    chk_w = max(3, int(size * 0.035))
    p1 = (cx - int(w * 0.18), cy + int(h * 0.02))
    p2 = (cx - int(w * 0.03), cy + int(h * 0.15))
    p3 = (cx + int(w * 0.22), cy - int(h * 0.12))
    draw.line([p1, p2, p3], fill=(255, 255, 255, 255), width=chk_w, joint="curve")

    return image


def write_icns(base_img: Image.Image, icns_path: str) -> None:
    """Write an Apple ICNS container with PNG-encoded icon chunks (128..1024 px)."""
    chunk_specs = [
        (b"ic07", 128),
        (b"ic08", 256),
        (b"ic09", 512),
        (b"ic10", 1024),
    ]
    chunks = []
    for ostype, dim in chunk_specs:
        resized = base_img.resize((dim, dim), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        chunks.append(ostype + struct.pack(">I", 8 + len(png_bytes)) + png_bytes)

    body = b"".join(chunks)
    header = b"icns" + struct.pack(">I", 8 + len(body))
    with open(icns_path, "wb") as f:
        f.write(header + body)


def main():
    build_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build")
    os.makedirs(build_dir, exist_ok=True)

    img_1024 = create_redmercury_icon(1024)
    img_512 = img_1024.resize((512, 512), Image.Resampling.LANCZOS)

    png_path = os.path.join(build_dir, "icon.png")
    img_512.save(png_path, "PNG")
    print(f"Generated PNG icon: {png_path}")

    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_images = [img_1024.resize(s, Image.Resampling.LANCZOS) for s in ico_sizes]
    ico_path = os.path.join(build_dir, "icon.ico")
    ico_images[-1].save(ico_path, format="ICO", sizes=ico_sizes)
    print(f"Generated Windows ICO icon: {ico_path}")

    icns_path = os.path.join(build_dir, "icon.icns")
    write_icns(img_1024, icns_path)
    print(f"Generated macOS ICNS icon: {icns_path}")


if __name__ == "__main__":
    main()
