"""
generate_icons.py
==================
Generates the 3 required PNG icons for the Chrome extension.
Run this once before packing the extension.

Output:
  extension/icons/icon16.png
  extension/icons/icon48.png
  extension/icons/icon128.png

Requires: Pillow (pip install Pillow)
"""

import sys
from pathlib import Path

ICON_DIR = Path(__file__).parent / "extension" / "icons"
ICON_DIR.mkdir(parents=True, exist_ok=True)

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Installing Pillow…")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image, ImageDraw


def make_shield_icon(size: int) -> Image.Image:
    """Draw a blue shield icon for ABTD."""
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = size // 8
    mid = size // 2

    # Shield background
    shield_color = (59, 130, 246, 255)    # Blue
    draw.ellipse([pad, pad, size-pad, size-pad], fill=shield_color)

    # Inner shield highlight
    inner_pad = size // 4
    draw.ellipse([inner_pad, inner_pad, size-inner_pad, size-inner_pad],
                 fill=(139, 92, 246, 200))

    # Checkmark / shield symbol
    tick_color = (255, 255, 255, 255)
    lw = max(1, size // 16)

    # Simple "S" for shield
    x1 = mid - size//6
    x2 = mid + size//6
    y1 = mid - size//8
    y2 = mid + size//8

    draw.rectangle([x1, y1, x2, y2], fill=tick_color)

    return img


for size in (16, 48, 128):
    icon = make_shield_icon(size)
    icon.save(ICON_DIR / f"icon{size}.png")
    print(f"✓ icon{size}.png created")

print(f"\n✅ Icons saved to: {ICON_DIR}")
print("Next: python run.py")
