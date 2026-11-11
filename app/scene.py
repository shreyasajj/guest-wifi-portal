"""The 'Dusk' landscape: a small inline SVG rendered once at import time.

Colours come from CSS custom properties, so the same markup is night in dark mode
and dawn in light mode.
"""
from __future__ import annotations

from functools import lru_cache

_TREES = [(30, 70), (85, 95), (140, 60), (205, 42), (300, 78), (350, 40), (610, 52), (655, 82),
          (720, 44), (980, 64), (1035, 96), (1095, 58), (1160, 80)]


def _rng(seed: int):
    s = seed
    while True:
        s = (s * 16807) % 2147483647
        yield s / 2147483647


@lru_cache
def scene_svg(uid: str = "s", moon_x: int = 620, moon_y: int = 225) -> str:
    """Moon position in the 1200x800 viewBox. The default sits high and near the centre, so a portrait
    phone (which crops the sides) shows it whole above the card. A moon above y=400 rises behind the far
    ridge; lower ones sit in front of it, as in the short admin header, which passes its own position."""
    r = _rng(7)
    stars = "".join(
        f'<circle cx="{next(r) * 1200:.0f}" cy="{next(r) * 330:.0f}" r="{next(r) * 1.8 + .5:.1f}" '
        f'opacity="{next(r) * .6 + .3:.2f}"/>'
        for _ in range(70)
    )
    trees = []
    for x, h in _TREES:
        w = h * 0.32
        trees.append(f'<polygon points="{x},{560 - h} {x - w:.0f},562 {x + w:.0f},562"/>')
        trees.append(f'<polygon points="{x},{560 - h * .62:.0f} {x - w * 1.25:.0f},562 {x + w * 1.25:.0f},562"/>')
        trees.append(f'<polygon opacity=".22" points="{x},{560 + h * .8:.0f} {x - w:.0f},560 {x + w:.0f},560"/>')
    moon = (f'<circle class="moon" cx="{moon_x}" cy="{moon_y}" r="150" opacity=".07"/>'
            f'<circle class="moon" cx="{moon_x}" cy="{moon_y}" r="108" opacity=".1"/>'
            f'<circle class="moon" cx="{moon_x}" cy="{moon_y}" r="62"/>')
    far = ('<polygon class="m1" points="0,420 120,360 230,400 360,300 470,370 560,330 690,250 820,340 930,300 '
           '1050,360 1200,290 1200,560 0,560"/>')
    near = ('<polygon class="m2" points="0,470 90,430 180,460 260,400 330,452 420,470 540,420 640,470 760,380 '
            '860,430 960,400 1080,450 1200,410 1200,560 0,560"/>'
            '<polygon class="m3" points="0,522 140,502 260,532 400,506 520,536 700,512 840,532 1000,502 '
            '1200,526 1200,560 0,560"/>')
    hills = (moon + far if moon_y < 400 else far + moon) + near
    u = uid
    return f"""<svg class="scene-svg" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">
<defs>
<linearGradient id="{u}-sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="sky1"/><stop offset=".72" class="sky2"/></linearGradient>
<linearGradient id="{u}-lake" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="lake1"/><stop offset="1" class="lake2"/></linearGradient>
<linearGradient id="{u}-mist" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset=".55" stop-color="#fff" stop-opacity=".38"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>
<clipPath id="{u}-water"><rect y="560" width="1200" height="240"/></clipPath>
</defs>
<rect width="1200" height="800" fill="url(#{u}-sky)"/>
<g class="stars">{stars}</g>
<g id="{u}-hills">{hills}</g>
<rect y="560" width="1200" height="240" fill="url(#{u}-lake)"/>
<g clip-path="url(#{u}-water)" opacity=".32"><use href="#{u}-hills" transform="translate(0,1120) scale(1,-1)"/></g>
<g class="trees">{''.join(trees)}</g>
<rect y="490" width="1200" height="140" fill="url(#{u}-mist)"/>
<g fill="#fff" opacity=".35"><rect x="250" y="612" width="220" height="2" rx="1"/><rect x="300" y="640" width="120" height="2" rx="1"/><rect x="760" y="700" width="260" height="2" rx="1"/><rect x="120" y="740" width="160" height="2" rx="1"/></g>
</svg>"""
