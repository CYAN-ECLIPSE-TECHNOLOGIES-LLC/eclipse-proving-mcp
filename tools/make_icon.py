#!/usr/bin/env python3
# Eclipse Proving MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Generate icon-512.png — brand §6: eclipse motif on navy; the
# glyph is a target reticle with a check — a board, proven.

"""Generate icon-512.png — eclipse ring on navy (#0d1b2a) with a
proving reticle: concentric target circles, cross ticks, and a
check mark at the center (the assertion that passed). PIL only;
deterministic."""
import math

from PIL import Image, ImageDraw

S = 512
NAVY = (13, 27, 42, 255)
STOPS = [(15, 246, 247), (0, 212, 255), (123, 44, 191)]


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)


def grad(t):
    return lerp(STOPS[0], STOPS[1], t * 2) if t < 0.5 else \
        lerp(STOPS[1], STOPS[2], (t - 0.5) * 2)


def main():
    img = Image.new("RGBA", (S, S), NAVY)
    d = ImageDraw.Draw(img)
    ring = [54, 54, 458, 458]
    for i in range(72):
        t = i / 72
        d.arc(ring, start=i * 5, end=i * 5 + 6, fill=grad(t), width=13)
    d.ellipse([126, 126, 386, 386], fill=NAVY)
    cx, cy = 256, 256
    # Reticle circles.
    for r, w in ((104, 9), (64, 7)):
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  outline=(254, 254, 254, 255), width=w)
    # Cross ticks at the four bearings.
    for ang in (0, 90, 180, 270):
        a = math.radians(ang)
        x1 = cx + 112 * math.cos(a)
        y1 = cy + 112 * math.sin(a)
        x2 = cx + 140 * math.cos(a)
        y2 = cy + 140 * math.sin(a)
        d.line([x1, y1, x2, y2], fill=grad(0.35), width=10)
    # The check — the assertion that passed, at the center.
    d.line([cx - 38, cy + 2, cx - 12, cy + 28], fill=grad(0.55),
           width=15)
    d.line([cx - 12, cy + 28, cx + 42, cy - 30], fill=grad(0.55),
           width=15)
    img.save("icon-512.png")
    print("wrote icon-512.png", img.size, img.mode)


if __name__ == "__main__":
    main()


# Eclipse Proving MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
