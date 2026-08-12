"""Auto-generate icons — run once before extension pack"""
from pathlib import Path

ICON_DIR = Path(__file__).parent / "extension" / "icons"
ICON_DIR.mkdir(parents=True, exist_ok=True)

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image, ImageDraw

def make_icon(size: int) -> "Image.Image":
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Dark background circle
    pad = 2
    draw.ellipse([pad, pad, size-pad, size-pad], fill=(8, 12, 20, 255))
    # Gradient blue-purple filled circle
    inner_pad = size // 8
    draw.ellipse([inner_pad, inner_pad, size-inner_pad, size-inner_pad],
                 fill=(59, 130, 246, 230))
    # Shield shape (simplified as rounded rectangle)
    sp  = size // 4
    ep  = size - sp
    mid = size // 2
    draw.rounded_rectangle([sp, sp, ep, ep], radius=size//6, fill=(139, 92, 246, 200))
    # Shield letter S or check
    if size >= 48:
        lw   = max(2, size // 12)
        cx   = mid
        cy   = mid
        half = size // 6
        # Simple vertical bar (shield mark)
        draw.rectangle([cx - lw//2, cy - half, cx + lw//2, cy + half],
                       fill=(255, 255, 255, 255))
        draw.rectangle([cx - half, cy - lw//2, cx + half, cy + lw//2],
                       fill=(255, 255, 255, 255))
    return img

for sz in (16, 48, 128):
    img = make_icon(sz)
    out = ICON_DIR / f"icon{sz}.png"
    img.save(out, "PNG")
    print(f"✓ {out}")

print("Done. Extension icons ready.")
