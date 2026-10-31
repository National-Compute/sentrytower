#!/usr/bin/env python3
"""Make the art of the README: the hero, the detection chart and the cost chart, each in a light and a dark version.

Usage:
    uv run --no-project --with fonttools --with brotli --with uharfbuzz \\
        python scripts/make_readme_art.py --font PATH/TO/geist.woff2 --mono-font PATH/TO/geist-mono.woff2 \\
        [--hero swarm|scan|skyline|rampart] [--out docs/assets] [--all-heroes DIR]

--font and --mono-font are Geist and Geist Mono with the weight axis (the
variable fonts). The script writes to --out:

- hero-light.svg, hero-dark.svg: the hero of --hero.
  swarm: seven Junos in formation on a lit floor, under the name.
  scan: Juno holds the lantern over the code; the finding of the line.
  skyline: seven Junos on a ridge at dawn (dusk in the dark version).
  rampart: Juno in the crown of the keep, six sentries on the wall.
- results-light.svg, results-dark.svg: the detection of each pair of the
  open-harness benchmark and of the confirmation test, with 90% intervals.
- cost-light.svg, cost-dark.svg: the detection against the mean cost of a
  run, with the Pareto frontier.

--all-heroes DIR also writes every hero (hero-<name>-<light|dark>.svg) to DIR.

The text is Geist, drawn as outlines (each glyph once, then reused), so the
images need no font. The art follows the SentryTower brand: the agent
colours, the avatar art of Juno, light from the upper left, no pure black.
"""

from __future__ import annotations

import argparse
import csv
import io
import math
from dataclasses import dataclass
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[1]

# The agent colours of the brand: light, base, dark.
AGENTS = {
    "cobalt": ("#a9b5ff", "#5068f4", "#2c3fc0"),
    "moss": ("#b4e0bd", "#5e9f6f", "#376f47"),
    "coral": ("#ffc6b4", "#ec7a5d", "#bf4f35"),
    "plum": ("#dcc6ff", "#9b6ee2", "#6c44b3"),
    "sand": ("#fbe6c2", "#e0b578", "#ad8146"),
}
# The body of Juno in its 120 x 120 viewBox (brand, section 2).
BODY = (
    "M22 88C22 97.5 29 104 38.5 104L81.5 104C91 104 98 97.5 98 88L93.5 26.5C93.5 22.6 90.5 20 86.8 20L83.7 20C80 20 77 22.6 77 "
    "26.5L77 28.5C77 31.6 75 33.4 72.5 33.4C70 33.4 68 31.6 68 28.5L68 26.5C68 22.6 65 20 61.5 20L58.5 20C55 20 52 22.6 52 26.5L52 "
    "28.5C52 31.6 50 33.4 47.5 33.4C45 33.4 43 31.6 43 28.5L43 26.5C43 22.6 40 20 36.3 20L33.2 20C29.5 20 26.5 22.6 26.5 26.5Z"
)
TAGLINE = "A swarm of AI sentries that audits your code like an attacker."


def n(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


# ------------------------------------------------------------------- type


class Font:
    """A variable font as SVG outlines, shaped with HarfBuzz. Each glyph is defined once in <defs> (``defs``)."""

    def __init__(self, path: Path, tag: str) -> None:
        font = TTFont(str(path))
        font.flavor = None
        buffer = io.BytesIO()
        font.save(buffer)
        self.face = hb.Face(buffer.getvalue())
        self.upem = self.face.upem
        self.tag = tag
        self.fonts: dict[int, hb.Font] = {}
        self.glyphs: dict[tuple[int, int], str] = {}

    def begin(self) -> None:
        self.glyphs = {}

    def defs(self) -> str:
        out = []
        for (weight, glyph), key in sorted(self.glyphs.items()):
            pen = SVGPathPen(None, ntos=lambda value: str(round(value)))
            self._font(weight).draw_glyph_with_pen(glyph, TransformPen(pen, (1, 0, 0, -1, 0, 0)))
            out.append(f'<path id="{key}" d="{pen.getCommands()}"/>')
        return "".join(out)

    def _font(self, weight: int) -> hb.Font:
        if weight not in self.fonts:
            font = hb.Font(self.face)
            font.set_variations({"wght": weight})
            self.fonts[weight] = font
        return self.fonts[weight]

    def _shape(self, text: str, weight: int) -> tuple[list, list]:
        buffer = hb.Buffer()
        buffer.add_str(text)
        buffer.guess_segment_properties()
        hb.shape(self._font(weight), buffer, {})
        return buffer.glyph_infos, buffer.glyph_positions

    def width(self, text: str, size: float, weight: int = 400, tracking: float = 0.0) -> float:
        infos, positions = self._shape(text, weight)
        return sum(item.x_advance for item in positions) * size / self.upem + tracking * max(0, len(infos) - 1)

    def text(
        self,
        text: str,
        x: float,
        y: float,
        size: float,
        *,
        weight: int = 400,
        fill: str = "#23222a",
        tracking: float = 0.0,
        anchor: str = "start",
        opacity: float | None = None,
    ) -> str:
        """One line of text at the baseline ``y``. ``fill`` may be a gradient in font units (y from -1000 to 0 at the baseline)."""
        infos, positions = self._shape(text, weight)
        scale = size / self.upem
        total = self.width(text, size, weight, tracking)
        left = x - (total / 2 if anchor == "middle" else total if anchor == "end" else 0.0)
        uses, advance = [], 0.0
        for index, (info, position) in enumerate(zip(infos, positions, strict=True)):
            key = self.glyphs.setdefault((weight, info.codepoint), f"{self.tag}{weight}-{info.codepoint}")
            units = advance + position.x_offset + tracking * index / scale
            uses.append(f'<use href="#{key}" x="{round(units)}"/>' if units else f'<use href="#{key}"/>')
            advance += position.x_advance
        extra = f' opacity="{opacity}"' if opacity is not None else ""
        return f'<g transform="translate({n(left)} {n(y)}) scale({scale:.5f})" fill="{fill}"{extra}>{"".join(uses)}</g>'


@dataclass
class Type:
    sans: Font
    mono: Font

    def begin(self) -> None:
        self.sans.begin()
        self.mono.begin()

    def defs(self) -> str:
        return self.sans.defs() + self.mono.defs()


# ------------------------------------------------------------------ Juno


def juno(
    key: str, colour: str, cx: float, feet: float, size: float, *, look: float = 0.0, lantern: bool = False, pike: bool = False
) -> str:
    """Juno (or a teammate) in the avatar art of the brand: centred on ``cx``, the base of the body at ``feet``."""
    light, base, dark = AGENTS[colour]
    x, y = cx - size / 2, feet - size * 104 / 120
    eyes = f"translate({n(look)} {0.4 if look else 0})"
    parts = [
        f'<svg viewBox="0 0 120 120" x="{n(x)}" y="{n(y)}" width="{n(size)}" height="{n(size)}" overflow="visible">',
        f'<defs><radialGradient id="{key}-b" cx="32%" cy="24%" r="92%"><stop offset="0" stop-color="{light}"/>'
        f'<stop offset="0.52" stop-color="{base}"/><stop offset="1" stop-color="{dark}"/></radialGradient>'
        f'<linearGradient id="{key}-s" x1="0" y1="0" x2="0" y2="1"><stop offset="0.5" stop-color="#16161a" stop-opacity="0"/>'
        f'<stop offset="1" stop-color="#16161a" stop-opacity="0.18"/></linearGradient>'
        f'<filter id="{key}-f" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="2.6"/></filter></defs>',
        f'<path d="{BODY}" fill="url(#{key}-b)"/><path d="{BODY}" fill="url(#{key}-s)"/>',
        f'<ellipse cx="43" cy="41" rx="11.5" ry="5" fill="#ffffff" opacity="0.34" filter="url(#{key}-f)"/>',
        '<circle cx="41" cy="73" r="4.8" fill="#ff7b7b" opacity="0.24"/><circle cx="79" cy="73" r="4.8" fill="#ff7b7b" opacity="0.24"/>',
        f'<g transform="{eyes}"><ellipse cx="49" cy="63" rx="4.3" ry="5.5" fill="#17171c"/>'
        '<ellipse cx="71" cy="63" rx="4.3" ry="5.5" fill="#17171c"/>'
        '<circle cx="50.5" cy="61" r="1.4" fill="#ffffff"/><circle cx="72.5" cy="61" r="1.4" fill="#ffffff"/></g>',
        '<path d="M55.2 73.6Q60 77.6 64.8 73.6" fill="none" stroke="#17171c" stroke-width="2.3px" stroke-linecap="round" opacity="0.86"/>',
    ]
    if lantern:
        # The lantern of the first audit (brand, props).
        parts.append(
            f'<defs><radialGradient id="{key}-g"><stop offset="0" stop-color="#ffcf86" stop-opacity="0.9"/>'
            f'<stop offset="1" stop-color="#ffcf86" stop-opacity="0"/></radialGradient></defs>'
            f'<g transform="translate(-0.87 -15.49)"><circle cx="111" cy="80" r="22" fill="url(#{key}-g)"/>'
            '<path d="M107 69.5Q111 63 115 69.5" fill="none" stroke="#5f544d" stroke-width="1.4px" stroke-linecap="round"/>'
            '<path d="M105.5 72H116.5L114.5 69.5H107.5Z" fill="#5f544d"/><rect x="106.5" y="72" width="9" height="14" rx="2" fill="#fff1cc"/>'
            '<ellipse cx="111" cy="80" rx="2.2" ry="3.6" fill="#ffa94a"/><rect x="105.5" y="85.5" width="11" height="3" rx="1.2" fill="#5f544d"/></g>'
        )
    if pike:
        # The pike and pennant of a sentry (brand, props), the pennant in the colour of the teammate.
        parts.append(
            '<svg x="97.71" y="-5.71" width="27.43" height="109.71" viewBox="0 0 20 80" overflow="visible">'
            '<path d="M4.6 6 L7 0 L9.4 6 Z" fill="#d9d6cf" stroke="#6e6a63" stroke-width="0.6px"/>'
            '<rect x="5.6" y="5.5" width="2.8" height="74.5" rx="1.4" fill="#8a6a48"/>'
            f'<path d="M8.4 8 L19.2 12.5 L8.4 17 Z" fill="{base}" stroke="{dark}" stroke-width="0.7px" stroke-linejoin="round"/>'
            f'<path d="M8.4 8 L19.2 12.5 L8.4 10.8 Z" fill="{light}" opacity="0.7"/></svg>'
        )
    parts.append("</svg>")
    return "".join(parts)


GRAIN = (
    '<filter id="grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency="0.9" '
    'numOctaves="2" stitchTiles="stitch"/><feColorMatrix type="saturate" values="0"/></filter>'
)


def grain(width: int, height: int, opacity: float) -> str:
    """A fine film grain over the image: it breaks the bands of the large gradients."""
    return f'<rect width="{width}" height="{height}" filter="url(#grain)" opacity="{opacity}"/>'


def floor_light(cx: float, feet: float, size: float, colour: str, opacity: float) -> str:
    """The light of a Juno on the floor, in its colour."""
    return (
        f'<ellipse cx="{n(cx)}" cy="{n(feet)}" rx="{n(size * 0.62)}" ry="{n(size * 0.11)}" fill="{colour}" opacity="{opacity}" '
        f'filter="url(#soft)"/>'
    )


def shadow(cx: float, feet: float, size: float, colour: str, opacity: float) -> str:
    return (
        f'<ellipse cx="{n(cx)}" cy="{n(feet + size * 0.012)}" rx="{n(size * 0.33)}" ry="{n(size * 0.05)}" fill="{colour}" '
        f'opacity="{opacity}" filter="url(#soft)"/>'
    )


def radial(key: str, colour: str, opacity: float) -> str:
    return (
        f'<radialGradient id="{key}"><stop offset="0" stop-color="{colour}" stop-opacity="{opacity}"/>'
        f'<stop offset="0.55" stop-color="{colour}" stop-opacity="{opacity * 0.35:.3f}"/>'
        f'<stop offset="1" stop-color="{colour}" stop-opacity="0"/></radialGradient>'
    )


def linear(key: str, stops: list[tuple[float, str, float]], *, x2: float = 0, y2: float = 1, units: str = "") -> str:
    body = "".join(f'<stop offset="{offset}" stop-color="{colour}" stop-opacity="{opacity}"/>' for offset, colour, opacity in stops)
    return f'<linearGradient id="{key}" x1="0" y1="0" x2="{n(x2)}" y2="{n(y2)}"{units}>{body}</linearGradient>'


def svg(width: int, height: int, label: str, defs: list[str], body: list[str]) -> str:
    return (
        "\n".join(
            [
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{label}">',
                f"<title>{label}</title>",
                "<defs>",
                '<filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="6"/></filter>',
                '<filter id="blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="18"/></filter>',
                GRAIN,
                *defs,
                "</defs>",
                *body,
                "</svg>",
            ]
        )
        + "\n"
    )


def wordmark_fill(key: str, top: str, bottom: str) -> str:
    """A vertical gradient for text: from the cap height to the baseline, in the font units of ``Font.text``."""
    return (
        f'<linearGradient id="{key}" gradientUnits="userSpaceOnUse" x1="0" y1="-760" x2="0" y2="40">'
        f'<stop offset="0" stop-color="{top}"/><stop offset="1" stop-color="{bottom}"/></linearGradient>'
    )


def pill(kind: Type, text: str, cx: float, top: float, *, fg: str, bg: str, border: str, anchor: str = "middle") -> str:
    size, tracking = 12.5, 2.2
    width = kind.mono.width(text, size, 500, tracking) + 34
    left = cx - width / 2 if anchor == "middle" else cx
    return f'<rect x="{n(left)}" y="{n(top)}" width="{n(width)}" height="30" rx="15" fill="{bg}" stroke="{border}"/>' + kind.mono.text(
        text, left + 17, top + 19.5, size, weight=500, fill=fg, tracking=tracking
    )


# ------------------------------------------------------------- the heroes


def palette(dark: bool) -> dict[str, str]:
    if dark:
        return {
            "ink": "#f3f2fb",
            "ink2": "#c9c7e6",
            "muted": "#a3a1c4",
            "pill_bg": "#ffffff0f",
            "pill_border": "#ffffff26",
            "pill_fg": "#d5d3f2",
            "shadow": "#05040c",
        }
    return {
        "ink": "#16161a",
        "ink2": "#2a2933",
        "muted": "#54545d",
        "pill_bg": "#ffffffb3",
        "pill_border": "#d9d6e8",
        "pill_fg": "#4a4760",
        "shadow": "#3b2f28",
    }


def hero_swarm(kind: Type, dark: bool) -> str:
    """Seven Junos in formation on a lit floor, under the name."""
    width, height = 1280, 560
    p = palette(dark)
    kind.begin()
    horizon, vanish = 352.0, 640.0
    defs = [
        linear(
            "sky",
            [(0, "#0b0a1a", 1), (0.62, "#16132e", 1), (0.7, "#1d1838", 1), (1, "#0c0b19", 1)]
            if dark
            else [(0, "#fbfaf8", 1), (0.6, "#f2f1fb", 1), (0.7, "#eceefb", 1), (1, "#f7f6f2", 1)],
        ),
        radial("glow-cobalt", "#5068f4", 0.55 if dark else 0.26),
        radial("glow-plum", "#9b6ee2", 0.32 if dark else 0.16),
        radial("glow-coral", "#ec7a5d", 0.22 if dark else 0.12),
        linear(
            "horizon-line",
            [(0, "#a9b5ff", 0), (0.5, "#c9d0ff" if dark else "#7d8ef8", 0.9 if dark else 0.5), (1, "#a9b5ff", 0)],
            x2=1,
            y2=0,
        ),
        linear("floor-fade", [(0, "#ffffff", 0.15), (0.3, "#ffffff", 0.6), (1, "#ffffff", 1)]),
        f'<mask id="floor-mask" maskUnits="userSpaceOnUse" x="0" y="{n(horizon)}" width="{width}" height="{n(height - horizon)}">'
        f'<rect x="0" y="{n(horizon)}" width="{width}" height="{n(height - horizon)}" fill="url(#floor-fade)"/></mask>',
        wordmark_fill("wm", "#ffffff", "#c6c9f3") if dark else wordmark_fill("wm", "#1b1b22", "#3d3c55"),
    ]
    body = [f'<rect width="{width}" height="{height}" fill="url(#sky)"/>']
    body += [
        f'<ellipse cx="{n(vanish)}" cy="{n(horizon + 10)}" rx="580" ry="300" fill="url(#glow-cobalt)"/>',
        f'<ellipse cx="400" cy="{n(horizon)}" rx="400" ry="240" fill="url(#glow-plum)"/>',
        f'<ellipse cx="900" cy="{n(horizon + 10)}" rx="380" ry="220" fill="url(#glow-coral)"/>',
    ]
    # The floor: a perspective grid toward the vanishing point on the horizon.
    lines = []
    for index in range(-9, 10):
        bottom_x = vanish + index * 118
        lines.append(f"M{n(vanish + index * 4)} {n(horizon)}L{n(bottom_x)} {height}")
    depth = 5.0
    while horizon + depth < height:
        lines.append(f"M0 {n(horizon + depth)}H{width}")
        depth *= 1.5
    grid = "#9aa4ff" if dark else "#5068f4"
    body += [
        f'<g mask="url(#floor-mask)"><path d="{"".join(lines)}" stroke="{grid}" stroke-width="1" opacity="{0.42 if dark else 0.2}" fill="none"/></g>',
        f'<rect x="0" y="{n(horizon - 1)}" width="{width}" height="2" fill="url(#horizon-line)"/>',
    ]
    # The formation: back to front.
    formation = [
        ("coral", 128, 462, 108),
        ("coral", 1152, 462, 108),
        ("moss", 262, 482, 146),
        ("moss", 1018, 482, 146),
        ("plum", 430, 508, 196),
        ("sand", 850, 508, 196),
        ("cobalt", 640, 540, 268),
    ]
    for colour, cx, feet, size in formation:
        body.append(floor_light(cx, feet, size, AGENTS[colour][1], 0.5 if dark else 0.26))
        body.append(shadow(cx, feet, size, p["shadow"], 0.7 if dark else 0.34))
    for index, (colour, cx, feet, size) in enumerate(formation):
        body.append(juno(f"s{index}", colour, cx, feet, size))
    if dark:
        body.append(grain(width, height, 0.05))
    body += [
        pill(kind, "AN INDEPENDENT SECURITY HARNESS", width / 2, 40, fg=p["pill_fg"], bg=p["pill_bg"], border=p["pill_border"]),
        kind.sans.text("SentryTower", width / 2, 172, 112, weight=640, tracking=-4.6, fill="url(#wm)", anchor="middle"),
        kind.sans.text(TAGLINE, width / 2, 222, 25, weight=420, fill=p["muted"], anchor="middle"),
    ]
    defs.append(kind.defs())
    return svg(width, height, "SentryTower: a swarm of AI sentries that audits your code like an attacker", defs, body)


# The code of the recorded audit: DVWA, vulnerabilities/sqli/source/low.php (lines 3 to 11, as in the file).
CODE = [
    (
        3,
        [
            ("kw", "if"),
            ("p", "( "),
            ("fn", "isset"),
            ("p", "( "),
            ("var", "$_REQUEST"),
            ("p", "[ "),
            ("str", "'Submit'"),
            ("p", " ] ) ) {"),
        ],
    ),
    (4, [("cm", "    // Get input")]),
    (5, [("p", "    "), ("var", "$id"), ("p", " = "), ("var", "$_REQUEST"), ("p", "[ "), ("str", "'id'"), ("p", " ];")]),
    (6, []),
    (7, [("p", "    "), ("kw", "switch"), ("p", " ("), ("var", "$_DVWA"), ("p", "["), ("str", "'SQLI_DB'"), ("p", "]) {")]),
    (8, [("p", "        "), ("kw", "case"), ("p", " MYSQL:")]),
    (9, [("cm", "            // Check database")]),
    (10, [("p", "            "), ("var", "$query"), ("p", "  = "), ("str", '"SELECT first_name, last_name')]),
    (0, [("p", "                "), ("str", "FROM users WHERE user_id = '"), ("var", "$id"), ("str", "';\""), ("p", ";")]),
    (
        11,
        [("p", "            "), ("var", "$result"), ("p", " = "), ("fn", "mysqli_query"), ("p", "( …, "), ("var", "$query"), ("p", " );")],
    ),
]


def hero_scan(kind: Type, dark: bool) -> str:
    """Juno holds the lantern over the code; the finding of the line (the SQL injection of the recorded audit)."""
    width, height = 1280, 600
    p = palette(dark)
    kind.begin()
    syntax = (
        {"kw": "#c6b2ff", "fn": "#b4e0bd", "var": "#a9b5ff", "str": "#f6cbb8", "cm": "#6d6b8f", "p": "#c9c7e6", "num": "#77759a"}
        if dark
        else {"kw": "#6c44b3", "fn": "#376f47", "var": "#2c3fc0", "str": "#ad5a3c", "cm": "#8b8a96", "p": "#3a3946", "num": "#a3a2ad"}
    )
    card_bg, card_border = ("#12142a", "#2b2e52") if dark else ("#ffffff", "#e6e3dc")
    defs = [
        linear("bg", [(0, "#0d0c1c", 1), (1, "#141228", 1)] if dark else [(0, "#fbfaf8", 1), (1, "#f3f1ec", 1)]),
        radial("glow-cobalt", "#5068f4", 0.42 if dark else 0.16),
        radial("glow-warm", "#ffbd8e", 0.30),
        linear("beam", [(0, "#ffcf86" if dark else "#ffb35a", 0.5 if dark else 0.42), (1, "#ffcf86", 0)], x2=1, y2=-0.35),
        linear("card-shade", [(0, "#ffffff", 0.05 if dark else 0), (1, "#ffffff", 0)]),
        wordmark_fill("wm", "#ffffff", "#c6c9f3") if dark else wordmark_fill("wm", "#1b1b22", "#3d3c55"),
    ]
    body = [
        f'<rect width="{width}" height="{height}" fill="url(#bg)"/>',
        '<ellipse cx="930" cy="300" rx="520" ry="360" fill="url(#glow-cobalt)"/>',
    ]
    # Left: the name, the promise and the three numbers of the pre-registered benchmark.
    body += [
        kind.sans.text("SentryTower", 76, 222, 92, weight=640, tracking=-3.6, fill="url(#wm)"),
        kind.sans.text("A swarm of AI sentries that reads", 80, 272, 24, weight=420, fill=p["muted"]),
        kind.sans.text("your code like an attacker.", 80, 304, 24, weight=420, fill=p["muted"]),
    ]
    stats = [("29.1%", "detection on", "fresh advisories"), ("7/7", "open harnesses", "outscored"), ("$0.30", "average cost", "per audit")]
    for index, (number, first, second) in enumerate(stats):
        x = 80.0 + index * 168
        if index:
            body.append(f'<path d="M{n(x - 22)} 344V420" stroke="{p["pill_border"]}" stroke-width="1"/>')
        body += [
            kind.sans.text(number, x - 1, 380, 38, weight=620, tracking=-1.0, fill=p["ink"]),
            kind.sans.text(first, x, 403, 13.5, weight=440, fill=p["muted"]),
            kind.sans.text(second, x, 420, 13.5, weight=440, fill=p["muted"]),
        ]
    body.append(
        kind.sans.text(
            "Pre-registered benchmark · same model, budget and sandbox for every harness",
            80,
            458,
            12.5,
            weight=430,
            fill=p["muted"],
            opacity=0.8,
        )
    )
    # Right: the code card.
    left, top, card_w, card_h = 640.0, 88.0, 572.0, 404.0
    body += [
        f'<rect x="{n(left + 8)}" y="{n(top + 22)}" width="{n(card_w)}" height="{n(card_h)}" rx="18" fill="{p["shadow"]}" '
        f'opacity="{0.6 if dark else 0.16}" filter="url(#blur)"/>',
        f'<rect x="{n(left)}" y="{n(top)}" width="{n(card_w)}" height="{n(card_h)}" rx="18" fill="{card_bg}" stroke="{card_border}"/>',
        f'<rect x="{n(left)}" y="{n(top)}" width="{n(card_w)}" height="{n(card_h)}" rx="18" fill="url(#card-shade)"/>',
        f'<path d="M{n(left)} {n(top + 46)}H{n(left + card_w)}" stroke="{card_border}"/>',
    ]
    for index, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        body.append(
            f'<circle cx="{n(left + 24 + index * 18)}" cy="{n(top + 23)}" r="5.5" fill="{colour}" opacity="{0.85 if dark else 1}"/>'
        )
    body.append(kind.mono.text("vulnerabilities/sqli/source/low.php", left + 86, top + 28, 12.5, weight=450, fill=p["muted"]))
    line_height, code_left, code_top = 27.0, left + 64, top + 82
    sink_rows = (7, 8)  # the rows of line 10 (the query with the input) in CODE
    for row in sink_rows:
        y = code_top + row * line_height - 19
        body.append(
            f'<rect x="{n(left + 1)}" y="{n(y)}" width="{n(card_w - 2)}" height="{n(line_height)}" fill="#ec7a5d" '
            f'opacity="{0.17 if dark else 0.12}"/>'
        )
    body.append(
        f'<rect x="{n(left + 1)}" y="{n(code_top + 7 * line_height - 19)}" width="3.5" height="{n(2 * line_height)}" fill="#ec7a5d"/>'
    )
    for row, (number, tokens) in enumerate(CODE):
        y = code_top + row * line_height
        if number:
            body.append(kind.mono.text(str(number), left + 40, y, 13, fill=syntax["num"], anchor="end"))
        x = code_left
        for style, text in tokens:
            body.append(kind.mono.text(text, x, y, 14, weight=430, fill=syntax[style]))
            x += kind.mono.width(text, 14, 430)
    # The source of the input: a wavy underline under $_REQUEST[ 'id' ] of line 5.
    start = code_left + kind.mono.width("    $id = ", 14, 430)
    end = start + kind.mono.width("$_REQUEST[ 'id' ]", 14, 430)
    wave_y = code_top + 2 * line_height + 6
    wave = f"M{n(start)} {n(wave_y)}" + "".join(f"q{n(3)} {n(-3 if i % 2 == 0 else 3)} {n(6)} 0" for i in range(int((end - start) / 6)))
    body.append(f'<path d="{wave}" fill="none" stroke="#ec7a5d" stroke-width="1.6" stroke-linecap="round"/>')
    # The lantern: Juno lights the code from the lower left.
    juno_x, juno_feet, juno_size = 646.0, 566.0, 170.0
    lamp_x = juno_x - juno_size / 2 + (111 - 0.87) / 120 * juno_size
    lamp_y = juno_feet - juno_size * 104 / 120 + (80 - 15.49) / 120 * juno_size
    beam = (
        f"M{n(lamp_x)} {n(lamp_y - 6)}L{n(left + card_w - 20)} {n(code_top + 6 * line_height - 34)}"
        f"L{n(left + card_w - 20)} {n(code_top + 9 * line_height + 4)}Z"
    )
    body += [
        f'<path d="{beam}" fill="url(#beam)" opacity="{0.55 if dark else 0.6}"/>',
        f'<ellipse cx="{n(lamp_x)}" cy="{n(lamp_y)}" rx="120" ry="120" fill="url(#glow-warm)"/>',
        shadow(juno_x, juno_feet, juno_size, p["shadow"], 0.55 if dark else 0.22),
        juno("lantern", "cobalt", juno_x, juno_feet, juno_size, lantern=True),
    ]
    # Two sentries on the top edge of the card look at the line.
    for index, (colour, cx) in enumerate((("moss", 1082.0), ("plum", 1150.0))):
        body.append(juno(f"top{index}", colour, cx, top + 3, 74, look=-3.2, pike=index == 1))
    # The finding.
    fx, fy, fw, fh = 868.0, 452.0, 360.0, 104.0
    body += [
        f'<rect x="{n(fx + 6)}" y="{n(fy + 16)}" width="{n(fw)}" height="{n(fh)}" rx="14" fill="{p["shadow"]}" '
        f'opacity="{0.6 if dark else 0.18}" filter="url(#blur)"/>',
        f'<rect x="{n(fx)}" y="{n(fy)}" width="{n(fw)}" height="{n(fh)}" rx="14" fill="{"#1b1d38" if dark else "#ffffff"}" '
        f'stroke="{"#3a3e6a" if dark else "#e6e3dc"}"/>',
        f'<rect x="{n(fx + 18)}" y="{n(fy + 18)}" width="76" height="22" rx="6" fill="#ec7a5d"/>',
        kind.mono.text("CRITICAL", fx + 25, fy + 33.5, 11.5, weight=650, fill="#ffffff", tracking=1.2),
        kind.mono.text("CWE-89", fx + 106, fy + 33.5, 12, weight=500, fill=p["muted"]),
        kind.sans.text("SQL injection in the SQLi module", fx + 18, fy + 66, 17, weight=600, fill=p["ink"]),
        kind.mono.text("vulnerabilities/sqli/source/low.php:5", fx + 18, fy + 88, 12, weight=450, fill=p["muted"]),
    ]
    if dark:
        body.append(grain(width, height, 0.045))
    defs.append(kind.defs())
    return svg(width, height, "SentryTower: Juno holds the lantern over the code and finds the SQL injection", defs, body)


def ridge(x: float) -> float:
    """The height of the ridge where the Junos stand."""
    return 500 - 30 * math.cos((x - 640) / 640 * math.pi * 0.9)


def cloud(cx: float, cy: float, scale: float, colour: str, opacity: float) -> str:
    """A soft cloud of the brand: round tops on a flat base."""
    parts = [(0, 0, 26), (-30, 8, 18), (30, 6, 20), (56, 12, 13), (-54, 13, 12)]
    circles = "".join(f'<circle cx="{n(cx + dx * scale)}" cy="{n(cy + dy * scale)}" r="{n(r * scale)}"/>' for dx, dy, r in parts)
    base = (
        f'<rect x="{n(cx - 66 * scale)}" y="{n(cy + 12 * scale)}" width="{n(132 * scale)}" height="{n(13 * scale)}" rx="{n(6 * scale)}"/>'
    )
    return f'<g fill="{colour}" opacity="{opacity}">{circles}{base}</g>'


def tufts(points: list[tuple[float, float]], colour: str) -> str:
    """Small tufts of grass along the ridge."""
    out = []
    for x, y in points:
        out.append(
            f"M{n(x - 5)} {n(y)}Q{n(x - 4)} {n(y - 7)} {n(x - 6)} {n(y - 12)}M{n(x)} {n(y)}Q{n(x + 1)} {n(y - 9)} {n(x)} "
            f"{n(y - 15)}M{n(x + 5)} {n(y)}Q{n(x + 5)} {n(y - 7)} {n(x + 8)} {n(y - 11)}"
        )
    return f'<path d="{"".join(out)}" stroke="{colour}" stroke-width="2.2" stroke-linecap="round" fill="none"/>'


def hero_skyline(kind: Type, dark: bool) -> str:
    """Seven Junos on a ridge at dawn (dusk in the dark version), under the name."""
    width, height = 1280, 560
    kind.begin()
    if dark:
        sky = [(0, "#121326", 1), (0.45, "#262340", 1), (0.8, "#463753", 1), (1, "#5a4359", 1)]
        layers = [("#3d3a57", "#34304b"), ("#34304b", "#2b2840"), ("#2c2a40", "#242236")]
        hill = [(0, "#2f3b31", 1), (1, "#1f271f", 1)]
        celestial = ("#eef1f8", 1150.0, 92.0, 30.0, "#a9b5da")
        cloud_colour, haze_colour, rim, tuft = "#625c7c", "#5a4359", "#4a5c44", "#3f5039"
    else:
        sky = [(0, "#a9afdb", 1), (0.42, "#d9bfd4", 1), (0.78, "#f6cbb8", 1), (1, "#ffdab2", 1)]
        layers = [("#cfc3d8", "#c2b7cf"), ("#bdb4cf", "#aea6c4"), ("#aaa1c2", "#9b93b6")]
        hill = [(0, "#adc092", 1), (1, "#86a06c", 1)]
        celestial = ("#fff3dc", 640.0, 404.0, 58.0, "#ffbd8e")
        cloud_colour, haze_colour, rim, tuft = "#ffffff", "#ffe5d2", "#c9d9ad", "#7f9862"
    defs = [
        linear("sky", sky),
        linear("hill", hill),
        radial("sun-glow", celestial[4], 0.75 if not dark else 0.45),
        linear("haze", [(0, haze_colour, 0), (1, haze_colour, 0.6)]),
        *[linear(f"layer{index}", [(0, top, 1), (1, bottom, 1)]) for index, (top, bottom) in enumerate(layers)],
        wordmark_fill("wm", "#ffffff", "#d4d1ee") if dark else wordmark_fill("wm", "#1b1b22", "#3d3446"),
    ]
    body = [f'<rect width="{width}" height="{height}" fill="url(#sky)"/>']
    colour, cx, cy, radius, _ = celestial
    body += [
        f'<circle cx="{n(cx)}" cy="{n(cy)}" r="{n(radius * 5)}" fill="url(#sun-glow)"/>',
        f'<circle cx="{n(cx)}" cy="{n(cy)}" r="{n(radius)}" fill="{colour}"/>',
        cloud(170, 236, 1.0, cloud_colour, 0.55 if not dark else 0.35),
        cloud(1105, 214, 0.8, cloud_colour, 0.5 if not dark else 0.3),
        cloud(1010, 120, 0.55, cloud_colour, 0.4 if not dark else 0.22),
    ]
    ranges = [
        [
            (0, 372),
            (120, 330),
            (250, 360),
            (390, 298),
            (520, 348),
            (640, 318),
            (770, 344),
            (900, 292),
            (1040, 356),
            (1160, 314),
            (1280, 350),
        ],
        [(0, 404), (150, 356), (300, 396), (460, 346), (600, 394), (720, 372), (860, 400), (1000, 348), (1150, 390), (1280, 368)],
        [(0, 436), (180, 396), (360, 430), (520, 408), (640, 428), (790, 404), (950, 434), (1110, 394), (1280, 424)],
    ]
    for index, points in enumerate(ranges):
        path = f"M0 {height}L" + "L".join(f"{n(x)} {n(y)}" for x, y in points) + f"L{width} {height}Z"
        body.append(f'<path d="{path}" fill="url(#layer{index})"/>')
    body.append(f'<rect x="0" y="300" width="{width}" height="{height - 300}" fill="url(#haze)"/>')
    ridge_path = f"M0 {height}L" + "L".join(f"{x} {n(ridge(x))}" for x in range(0, width + 1, 16)) + f"L{width} {height}Z"
    rim_path = "M" + "L".join(f"{x} {n(ridge(x))}" for x in range(0, width + 1, 16))
    body += [
        f'<path d="{ridge_path}" fill="url(#hill)"/>',
        f'<path d="{rim_path}" stroke="{rim}" stroke-width="3" fill="none" opacity="0.85"/>',
        tufts([(x, ridge(x) + 18) for x in (60, 222, 372, 540, 742, 912, 1062, 1222)], tuft),
    ]
    line_up = [
        ("coral", 150, 96),
        ("moss", 290, 128),
        ("plum", 446, 172),
        ("cobalt", 640, 232),
        ("sand", 834, 172),
        ("moss", 990, 128),
        ("coral", 1130, 96),
    ]
    for _, x, size in line_up:
        body.append(shadow(x, ridge(x) + size * 0.02, size, "#3b2f28" if not dark else "#05040c", 0.26 if not dark else 0.6))
    for index, (shade, x, size) in enumerate(line_up):
        body.append(juno(f"k{index}", shade, x, ridge(x) + size * 0.03, size, pike=index in (0, 6)))
    if dark:
        body.append(grain(width, height, 0.05))
    body += [
        pill(
            kind,
            "AN INDEPENDENT SECURITY HARNESS",
            width / 2,
            34,
            fg="#4a4258" if not dark else "#d5d3f2",
            bg="#ffffff66" if not dark else "#ffffff12",
            border="#ffffff99" if not dark else "#ffffff26",
        ),
        kind.sans.text("SentryTower", width / 2, 160, 108, weight=640, tracking=-4.4, fill="url(#wm)", anchor="middle"),
        kind.sans.text(TAGLINE, width / 2, 208, 25, weight=430, fill="#433b4f" if not dark else "#c6c3e2", anchor="middle"),
    ]
    defs.append(kind.defs())
    return svg(width, height, "SentryTower: seven Junos on a ridge, a swarm of AI sentries that audits your code", defs, body)


def merlons(x0: float, x1: float, top: float, width: float, height: float, step: float, cap: str, side: str) -> str:
    parts, x = [], x0
    while x < x1:
        parts.append(
            f'<rect x="{n(x)}" y="{n(top)}" width="{n(width)}" height="{n(height)}" rx="2.5" fill="{cap}"/>'
            f'<rect x="{n(x + width * 0.66)}" y="{n(top)}" width="{n(width * 0.34)}" height="{n(height)}" fill="{side}"/>'
        )
        x += step
    return "".join(parts)


def beacon(x: float, y: float, *, dark: bool) -> str:
    """A beacon on the wall (brand, props): an iron brazier with a fire, its foot at (x, y)."""
    return (
        f'<g transform="translate({n(x)} {n(y)})"><circle cx="0" cy="-30" r="{44 if dark else 30}" fill="url(#fire-glow)"/>'
        '<rect x="-1.8" y="-14" width="3.6" height="14" rx="1" fill="#5f544d"/>'
        '<path d="M-11 -20H11L7.5 -13H-7.5Z" fill="#5f544d"/>'
        '<path d="M0 -44C5 -35 11 -29 9 -22C8 -19 4 -18 0 -18C-4 -18 -8 -19 -9 -22C-11 -29 -5 -35 0 -44Z" fill="url(#flame)"/>'
        '<path d="M0 -33C2.5 -28.5 5 -25.5 4 -22C3.4 -20.5 1.8 -19.8 0 -19.8C-1.8 -19.8 -3.4 -20.5 -4 -22C-5 -25.5 -2.5 -28.5 0 -33Z" '
        'fill="#fff1cc"/></g>'
    )


def banner_flag(kind: Type, x: float, y: float) -> str:
    """The team flag on the pole at (x, y): cobalt cloth, the merlon emblem and the name."""
    cloth = (
        f"M{n(x)} {n(y)}C{n(x + 40)} {n(y - 6)} {n(x + 80)} {n(y + 6)} {n(x + 122)} {n(y - 2)}"
        f"L{n(x + 122)} {n(y + 32)}C{n(x + 80)} {n(y + 40)} {n(x + 40)} {n(y + 28)} {n(x)} {n(y + 34)}Z"
    )
    emblem = (
        f'<path d="{BODY}" transform="translate({n(x + 9)} {n(y + 9.5)}) scale(0.18) translate(-22 -20)" fill="#eff2ff" opacity="0.94"/>'
    )
    return f'<path d="{cloth}" fill="#3a50d5" stroke="#2935ba" stroke-width="0.8"/>{emblem}' + kind.sans.text(
        "SentryTower", x + 27, y + 21.5, 12.5, weight=640, fill="#eff2ff"
    )


def hero_rampart(kind: Type, dark: bool) -> str:
    """The keep, simplified: Juno in the crown in front of the flag tower, six sentries on the wall, under the name."""
    width, height = 1280, 560
    kind.begin()
    if dark:
        sky = [(0, "#101126", 1), (0.62, "#221d39", 1), (1, "#392a43", 1)]
        far, hill = "#2a263d", [(0, "#27312a", 1), (1, "#1d241f", 1)]
        stone, side, cap, cap_side, joint = ("#7a6f79", "#5f5560"), ("#5d535e", "#4a414c"), "#8a7f89", "#6a5f69", "#2f282f"
    else:
        sky = [(0, "#dfe3f6", 1), (0.6, "#f0e1e8", 1), (1, "#fbe7d9", 1)]
        far, hill = "#d6cfe1", [(0, "#c3d2ab", 1), (1, "#a9bd8e", 1)]
        stone, side, cap, cap_side, joint = ("#ece4d9", "#d8ccbe"), ("#cdbfb0", "#b9aa9a"), "#f3ede4", "#d1c4b6", "#a3907f"
    wall_top, crown_top = 470.0, 404.0
    gate_left, gate_right = 556.0, 724.0
    tower_left, tower_right, tower_top = 690.0, 740.0, 300.0
    defs = [
        linear("sky", sky),
        linear("hill", hill),
        linear("st", [(0, stone[0], 1), (1, stone[1], 1)]),
        linear("sts", [(0, side[0], 1), (1, side[1], 1)]),
        linear("wood", [(0, "#b08d6b" if not dark else "#6f5444", 1), (1, "#8f6e51" if not dark else "#57412f", 1)]),
        linear("win", [(0, "#ffe2a6", 1), (1, "#ffb35a", 1)]),
        linear("flame", [(0, "#ffd27a", 1), (0.55, "#ff9d4a", 1), (1, "#f0703a", 1)]),
        radial("fire-glow", "#ffc370", 0.9 if dark else 0.55),
        radial("sun-glow", "#ffbd8e" if not dark else "#a9b5da", 0.65 if not dark else 0.4),
        wordmark_fill("wm", "#ffffff", "#d4d1ee") if dark else wordmark_fill("wm", "#1b1b22", "#3d3446"),
    ]
    body = [f'<rect width="{width}" height="{height}" fill="url(#sky)"/>']
    if dark:
        body += ['<circle cx="1120" cy="104" r="150" fill="url(#sun-glow)"/>', '<circle cx="1120" cy="104" r="28" fill="#eef1f8"/>']
    else:
        body += [f'<circle cx="{n((gate_left + gate_right) / 2)}" cy="430" r="330" fill="url(#sun-glow)"/>']
    body += [
        cloud(190, 260, 0.95, "#ffffff" if not dark else "#5f5978", 0.6 if not dark else 0.3),
        cloud(1090, 250, 0.8, "#ffffff" if not dark else "#5f5978", 0.55 if not dark else 0.28),
        f'<path d="M0 {height}L0 420C160 380 260 400 380 372C520 340 600 392 760 368C900 346 1000 392 1140 360C1210 346 1250 352 1280 356'
        f'L1280 {height}Z" fill="{far}"/>',
        f'<path d="M0 {height}L0 452C200 432 420 460 640 444C860 428 1080 458 1280 440L1280 {height}Z" fill="url(#hill)"/>',
    ]
    # The flag tower, behind Juno.
    body += [
        f'<rect x="{n(tower_left)}" y="{n(tower_top)}" width="{n(tower_right - tower_left)}" height="{n(crown_top - tower_top)}" fill="url(#st)"/>',
        f'<rect x="{n(tower_right - 15)}" y="{n(tower_top)}" width="15" height="{n(crown_top - tower_top)}" fill="url(#sts)"/>',
        merlons(tower_left - 4, tower_right, tower_top - 16, 14, 16, 21, cap, cap_side),
        f'<rect x="{n(tower_left - 4)}" y="{n(tower_top - 2)}" width="{n(tower_right - tower_left + 8)}" height="6" rx="1.5" fill="{cap}"/>',
        f'<rect x="{n(tower_left + 17)}" y="{n(tower_top + 26)}" width="8" height="20" rx="4" fill="{"url(#win)" if dark else "#5f5258"}" '
        f'opacity="{1 if dark else 0.7}"/>',
        f'<rect x="{n(tower_left + 23)}" y="236" width="3" height="{n(tower_top - 238)}" rx="1.2" fill="{"#8f8476" if not dark else "#a69ca6"}"/>',
        banner_flag(kind, tower_left + 26, 240),
    ]
    # The sentries stand behind the parapet of the wall; the merlons in front of them come after them.
    sentries = [("coral", 170.0), ("moss", 300.0), ("plum", 430.0), ("sand", 850.0), ("moss", 980.0), ("coral", 1110.0)]
    size = 128.0
    merlon_top = wall_top - 22
    for index, (shade, x) in enumerate(sentries):
        look = (3.2 if x < gate_left else -3.2) if index in (2, 3) else 0.0
        body.append(juno(f"w{index}", shade, x, merlon_top - 0.67 * size + size * 104 / 120, size, look=look, pike=index in (0, 5)))
    body += [
        merlons(-4, gate_left, merlon_top, 24, 22, 46, cap, cap_side),
        merlons(gate_right + 18, width, merlon_top, 24, 22, 46, cap, cap_side),
        f'<rect x="-2" y="{n(wall_top)}" width="{width + 4}" height="{n(height - wall_top + 2)}" fill="url(#st)"/>',
        f'<rect x="-2" y="{n(wall_top)}" width="{width + 4}" height="8" rx="1.5" fill="{cap}"/>',
        f'<path d="M0 {n(wall_top + 38)}H{width}M0 {n(wall_top + 66)}H{width}" stroke="{joint}" stroke-width="1.2" opacity="0.3"/>',
        beacon(536, merlon_top, dark=dark),
        beacon(744, merlon_top, dark=dark),
    ]
    # The gatehouse and the crown; Juno stands in the crown.
    juno_size = 200.0
    crown_merlon = crown_top - 22
    centre = (gate_left + gate_right) / 2
    door_w, door_top = 70.0, 494.0
    door_x = centre - door_w / 2 - 6
    arch = (
        f"M{n(door_x)} {height}V{n(door_top + door_w / 2)}A{n(door_w / 2)} {n(door_w / 2)} 0 0 1 {n(door_x + door_w)} "
        f"{n(door_top + door_w / 2)}V{height}Z"
    )
    body += [
        juno("juno", "cobalt", centre, crown_merlon - 0.67 * juno_size + juno_size * 104 / 120, juno_size),
        merlons(gate_left - 6, gate_right, crown_merlon, 24, 22, 43, cap, cap_side),
        f'<rect x="{n(gate_left)}" y="{n(crown_top)}" width="{n(gate_right - gate_left)}" height="{n(height - crown_top)}" fill="url(#st)"/>',
        f'<rect x="{n(gate_right - 20)}" y="{n(crown_top)}" width="20" height="{n(height - crown_top)}" fill="url(#sts)"/>',
        f'<rect x="{n(gate_left - 6)}" y="{n(crown_top)}" width="{n(gate_right - gate_left + 12)}" height="9" rx="2" fill="{cap}"/>',
        *[
            f'<rect x="{n(x)}" y="{n(crown_top + 30)}" width="9" height="26" rx="4.5" fill="{"url(#win)" if dark else "#5f5258"}" '
            f'opacity="{1 if dark else 0.7}"/>'
            for x in (gate_left + 32, gate_right - 58)
        ],
        f'<path d="M{n(door_x - 7)} {height}V{n(door_top + door_w / 2)}A{n(door_w / 2 + 7)} {n(door_w / 2 + 7)} 0 0 1 '
        f'{n(door_x + door_w + 7)} {n(door_top + door_w / 2)}V{height}Z" fill="{cap}"/>',
        f'<path d="{arch}" fill="url(#wood)"/>',
        f'<path d="M{n(door_x + door_w / 3)} {n(door_top + 8)}V{height}M{n(door_x + 2 * door_w / 3)} {n(door_top + 8)}V{height}" '
        f'stroke="#3b2f28" stroke-width="1.3" opacity="0.35"/>',
    ]
    if dark:
        body += [
            f'<ellipse cx="{n(centre)}" cy="{height}" rx="90" ry="40" fill="url(#fire-glow)" opacity="0.6"/>',
            grain(width, height, 0.05),
        ]
    body += [
        pill(
            kind,
            "AN INDEPENDENT SECURITY HARNESS",
            width / 2,
            34,
            fg="#4a4258" if not dark else "#d5d3f2",
            bg="#ffffff80" if not dark else "#ffffff12",
            border="#ffffffaa" if not dark else "#ffffff26",
        ),
        kind.sans.text("SentryTower", width / 2, 160, 108, weight=640, tracking=-4.4, fill="url(#wm)", anchor="middle"),
        kind.sans.text(TAGLINE, width / 2, 208, 25, weight=430, fill="#433b4f" if not dark else "#c6c3e2", anchor="middle"),
    ]
    defs.append(kind.defs())
    return svg(width, height, "SentryTower: Juno in the crown of the keep and six sentries on the wall", defs, body)


HEROES = {"swarm": hero_swarm, "scan": hero_scan, "skyline": hero_skyline, "rampart": hero_rampart}


# ----------------------------------------------------------------- charts


def chart_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with (ROOT / "benchmarks" / "confirmation-2026-10.csv").open() as stream:
        confirmation = {row["harness"]: row for row in csv.DictReader(stream)}
    hybrid, piolium = confirmation["SentryTower hybrid"], confirmation["Piolium"]
    rows.append(
        {
            "rival": "Piolium",
            "fixtures": 117,
            "ours": (float(hybrid["detection_pct"]), float(hybrid["detection_ci90_low"]), float(hybrid["detection_ci90_high"])),
            "theirs": (float(piolium["detection_pct"]), float(piolium["detection_ci90_low"]), float(piolium["detection_ci90_high"])),
            "ours_fa": float(hybrid["false_alarm_pct"]),
            "theirs_fa": float(piolium["false_alarm_pct"]),
            "ours_cost": float(hybrid["mean_cost_usd_per_run"]),
            "theirs_cost": float(piolium["mean_cost_usd_per_run"]),
        }
    )
    names = {"0 (0sec-labs/0)": "0 (0sec)", "OpenAI Codex Security": "Codex Security"}
    with (ROOT / "benchmarks" / "open-harnesses-2026-10.csv").open() as stream:
        for row in csv.DictReader(stream):
            rows.append(
                {
                    "rival": names.get(row["rival"], row["rival"]),
                    "fixtures": int(row["fixtures"]),
                    "ours": (float(row["hybrid_detection"]), float(row["hybrid_detection_lo"]), float(row["hybrid_detection_hi"])),
                    "theirs": (float(row["rival_detection"]), float(row["rival_detection_lo"]), float(row["rival_detection_hi"])),
                    "ours_fa": float(row["hybrid_false_alarms"]),
                    "theirs_fa": float(row["rival_false_alarms"]),
                    "ours_cost": float(row["hybrid_cost_per_run_usd"]),
                    "theirs_cost": float(row["rival_cost_per_run_usd"]),
                }
            )
    return rows


def chart_palette(light: bool) -> dict[str, str]:
    return {
        "background": "#f7f7f5" if light else "#16141f",
        "ink": "#16161a" if light else "#ece9f5",
        "muted": "#54545d" if light else "#b4b0c8",
        "grid": "#e6e2dc" if light else "#2e2a3c",
        "rule": "#dcd6ce" if light else "#353046",
        "theirs": "#b9aa9a" if light else "#6f6679",
        "whisker": "#23222a" if light else "#ece9f5",
        "border": "#e6e2dc" if light else "#2e2a3c",
    }


def detection_chart(kind: Type, mode: str) -> str:
    light = mode == "light"
    p = chart_palette(light)
    kind.begin()
    rows = chart_rows()
    width = 960
    label_right, left, scale = 172.0, 186.0, 9.0  # the bars start at ``left``; ``scale`` pixels for one point
    axis_max = 50
    fa_x, fixtures_x = 710.0, 830.0
    top, pair = 150.0, 62.0
    height = int(top + pair * len(rows) + 70)
    body = [
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="14" fill="{p["background"]}" stroke="{p["border"]}"/>',
        kind.sans.text("Detection of fresh advisories", 32, 52, 24, weight=620, fill=p["ink"], tracking=-0.4),
        kind.sans.text(
            "Each pair ran on the same fixtures with the same model, budget and sandbox: GLM 5.3 Flash, 20M tokens, 4 hours.",
            32,
            77,
            13.5,
            fill=p["muted"],
        ),
        juno("legend", "cobalt", 44, 118, 30),
        kind.sans.text("SentryTower", 64, 112, 13.5, weight=600, fill=p["ink"]),
        f'<rect x="162" y="101" width="20" height="12" rx="3" fill="{p["theirs"]}"/>',
        kind.sans.text("the open harness", 189, 112, 13.5, fill=p["muted"]),
        f'<path d="M314 107H344M314 102V112M344 102V112" stroke="{p["whisker"]}" stroke-width="1.2" fill="none"/>',
        kind.sans.text("90% interval", 351, 112, 13.5, fill=p["muted"]),
    ]
    for tick in range(0, axis_max + 1, 10):
        x = left + tick * scale
        body.append(f'<path d="M{n(x)} {n(top - 6)}V{n(top + pair * len(rows) - 8)}" stroke="{p["grid"]}" stroke-width="1"/>')
        body.append(kind.sans.text(f"{tick}%", x, top - 14, 12, fill=p["muted"], anchor="middle"))
    body += [
        kind.sans.text("False alarms", fa_x, top - 14, 12, fill=p["muted"]),
        kind.sans.text("Fixtures", fixtures_x, top - 14, 12, fill=p["muted"]),
    ]

    def bar(y: float, values: tuple[float, float, float], ours: bool) -> str:
        value, low, high = values
        x_low, x_high, middle = left + low * scale, left + high * scale, y + 8
        return (
            f'<rect x="{n(left)}" y="{n(y)}" width="{n(value * scale)}" height="16" rx="3.5" fill="{"url(#bar-ours)" if ours else p["theirs"]}"/>'
            f'<path d="M{n(x_low)} {n(middle)}H{n(x_high)}M{n(x_low)} {n(middle - 5)}V{n(middle + 5)}M{n(x_high)} {n(middle - 5)}'
            f'V{n(middle + 5)}" stroke="{p["whisker"]}" stroke-width="1.2" fill="none"/>'
            + kind.sans.text(f"{value:.1f}%", x_high + 8, y + 12.5, 13, weight=620 if ours else 400, fill=p["ink"] if ours else p["muted"])
        )

    for index, row in enumerate(rows):
        y = top + index * pair
        if index:
            body.append(f'<path d="M32 {n(y - 9)}H{width - 32}" stroke="{p["rule"]}" stroke-width="1"/>')
        body += [
            kind.sans.text("SentryTower", label_right, y + 13, 13.5, weight=600, fill=p["ink"], anchor="end"),
            kind.sans.text(str(row["rival"]), label_right, y + 37, 13.5, fill=p["muted"], anchor="end"),
            bar(y + 1, row["ours"], True),  # type: ignore[arg-type]
            bar(y + 25, row["theirs"], False),  # type: ignore[arg-type]
            kind.sans.text(f"{row['ours_fa']:.1f}%", fa_x, y + 13, 13.5, weight=600, fill=p["ink"]),
            kind.sans.text(f"{row['theirs_fa']:.1f}%", fa_x, y + 37, 13.5, fill=p["muted"]),
            kind.sans.text(str(row["fixtures"]), fixtures_x, y + 25, 13.5, fill=p["ink"]),
        ]
    notes_y = top + pair * len(rows) + 12
    notes = [
        "Detection: a finding within 10 lines of the vulnerable operation. False alarms: a finding on the fixed lines of the fixed version.",
        "Fewer than 117 fixtures: the harness reached its cost cap, or its campaign stopped. The answer keys were drafted by models.",
    ]
    for offset, line in enumerate(notes):
        body.append(kind.sans.text(line, 32, notes_y + 18 + offset * 20, 12, fill=p["muted"]))
    defs = [linear("bar-ours", [(0, AGENTS["cobalt"][1], 1), (1, AGENTS["cobalt"][2], 1)], x2=1, y2=0), kind.defs()]
    return svg(width, height, "Detection of fresh advisories: SentryTower against each open harness on the same fixtures", defs, body)


def cost_chart(kind: Type, mode: str) -> str:
    """Detection against the mean cost of an audit (log scale), with the Pareto frontier as a step line."""
    light = mode == "light"
    p = chart_palette(light)
    kind.begin()
    rows = chart_rows()
    first = rows[0]
    ours = ("SentryTower", float(first["ours_cost"]), float(first["ours"][0]), 117)  # type: ignore[arg-type, index]
    points = [ours]
    for row in rows:
        points.append((str(row["rival"]), float(row["theirs_cost"]), float(row["theirs"][0]), int(row["fixtures"])))  # type: ignore[arg-type, index]
    width, height = 960, 620
    left, right, top, bottom = 104.0, 904.0, 132.0, 508.0
    cost_min, cost_max, detect_max = 0.04, 1.6, 35.0

    def px(cost: float) -> float:
        return left + (math.log(cost) - math.log(cost_min)) / (math.log(cost_max) - math.log(cost_min)) * (right - left)

    def py(detection: float) -> float:
        return bottom - detection / detect_max * (bottom - top)

    # The Pareto frontier: the points that no other harness beats on both detection and cost.
    frontier, best = [], -1.0
    for name, cost, detection, _ in sorted(points, key=lambda item: item[1]):
        if detection > best:
            frontier.append((name, cost, detection))
            best = detection
    on_frontier = {name for name, _, _ in frontier}
    accent, accent_soft = AGENTS["cobalt"][1], AGENTS["cobalt"][0]
    body = [
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="14" fill="{p["background"]}" stroke="{p["border"]}"/>',
        kind.sans.text("Detection vs. cost per audit", 32, 52, 24, weight=620, fill=p["ink"], tracking=-0.4),
        kind.sans.text(
            "123 fresh advisories, the same model (GLM 5.3 Flash), budget and sandbox for every harness. Up and to the left is better.",
            32,
            77,
            13.5,
            fill=p["muted"],
        ),
    ]
    # Grid and axes.
    for tick in range(0, 36, 5):
        y = py(tick)
        body.append(f'<path d="M{n(left)} {n(y)}H{n(right)}" stroke="{p["grid"]}" stroke-width="1"/>')
        body.append(kind.sans.text(f"{tick}%", left - 12, y + 4, 12, fill=p["muted"], anchor="end"))
    for tick in (0.05, 0.1, 0.25, 0.5, 1.0):
        x = px(tick)
        body.append(f'<path d="M{n(x)} {n(top)}V{n(bottom)}" stroke="{p["grid"]}" stroke-width="1"/>')
        body.append(kind.sans.text(f"${tick:.2f}", x, bottom + 22, 12, fill=p["muted"], anchor="middle"))
    body += [
        f'<path d="M{n(left)} {n(bottom)}H{n(right)}" stroke="{p["muted"]}" stroke-width="1" opacity="0.6"/>',
        kind.sans.text(
            "Mean cost per audit (USD, log scale)", (left + right) / 2, bottom + 50, 13, weight=500, fill=p["muted"], anchor="middle"
        ),
        f'<g transform="rotate(-90 {n(left - 58)} {n((top + bottom) / 2)})">'
        + kind.sans.text("Detection rate", left - 58, (top + bottom) / 2 + 4, 13, weight=500, fill=p["muted"], anchor="middle")
        + "</g>",
    ]
    # "Better": the direction of the most detection for the least money.
    body += [
        f'<path d="M{n(left + 64)} {n(top + 52)}L{n(left + 24)} {n(top + 16)}M{n(left + 24)} {n(top + 16)}l0 13M{n(left + 24)} {n(top + 16)}l13 0" '
        f'stroke="{p["muted"]}" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.8"/>',
        kind.sans.text("Better", left + 70, top + 58, 12.5, weight=600, fill=p["muted"]),
    ]
    # The frontier as a step line: the best detection for each budget.
    steps = [f"M{n(px(frontier[0][1]))} {n(py(frontier[0][2]))}"]
    for _, cost, detection in frontier[1:]:
        steps.append(f"H{n(px(cost))}V{n(py(detection))}")
    steps.append(f"H{n(right)}")
    body += [
        f'<path d="{"".join(steps)}" stroke="{accent}" stroke-width="2" stroke-dasharray="6 5" fill="none" opacity="0.9"/>',
        kind.sans.text("Pareto frontier", right - 6, py(frontier[-1][2]) - 10, 12.5, weight=600, fill=accent, anchor="end"),
    ]
    # The points: the frontier in the accent, the others in stone; hollow when the harness finished fewer fixtures.
    labels = {
        "Piolium": (-11, -11, "end"),
        "Vercel deepsec": (12, 17, "start"),
        "0 (0sec)": (-12, 5, "end"),
        "OpenHack": (-12, -9, "end"),
        "Codex Security": (12, 5, "start"),
        "Clearwing": (12, 5, "start"),
        "Visa VVAH": (0, 24, "middle"),
    }
    for name, cost, detection, fixtures in points[1:]:
        x, y = px(cost), py(detection)
        partial = fixtures < 117
        colour = accent_soft if name in on_frontier else p["theirs"]
        stroke = accent if name in on_frontier else p["theirs"]
        fill = p["background"] if partial else colour
        body.append(f'<circle cx="{n(x)}" cy="{n(y)}" r="6.5" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        dx, dy, anchor = labels.get(name, (12, 5, "start"))
        label = f"{name} ({fixtures})" if partial else name
        body.append(kind.sans.text(label, x + dx, y + dy, 13, fill=p["ink"] if name in on_frontier else p["muted"], anchor=anchor))
    name, cost, detection, _ = ours
    x, y = px(cost), py(detection)
    body += [
        f'<circle cx="{n(x)}" cy="{n(y)}" r="15" fill="{accent}" opacity="0.14"/>',
        f'<circle cx="{n(x)}" cy="{n(y)}" r="8.5" fill="{accent}" stroke="{p["background"]}" stroke-width="2.5"/>',
        kind.sans.text("SentryTower", x - 16, y - 18, 15, weight=650, fill=p["ink"], anchor="end"),
        kind.sans.text(f"{detection:.1f}% at ${cost:.2f}", x - 16, y + 0, 13, fill=p["muted"], anchor="end"),
    ]
    legend_y = height - 26
    body += [
        f'<circle cx="38" cy="{n(legend_y - 4)}" r="6" fill="{accent_soft}" stroke="{accent}" stroke-width="2"/>',
        kind.sans.text("on the frontier", 52, legend_y, 12.5, fill=p["muted"]),
        f'<circle cx="168" cy="{n(legend_y - 4)}" r="6" fill="{p["theirs"]}" stroke="{p["theirs"]}" stroke-width="2"/>',
        kind.sans.text("dominated", 182, legend_y, 12.5, fill=p["muted"]),
        f'<circle cx="276" cy="{n(legend_y - 4)}" r="6" fill="{p["background"]}" stroke="{p["theirs"]}" stroke-width="2"/>',
        kind.sans.text(
            "fewer than 117 fixtures, the number in brackets; SentryTower detected more on each of those subsets",
            290,
            legend_y,
            12.5,
            fill=p["muted"],
        ),
    ]
    return svg(
        width,
        height,
        "Detection against the mean cost per audit, with the Pareto frontier: SentryTower has the highest detection",
        [kind.defs()],
        body,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--font", type=Path, required=True, help="Geist with the weight axis (woff2, ttf)")
    parser.add_argument("--mono-font", type=Path, required=True, help="Geist Mono with the weight axis (woff2, ttf)")
    parser.add_argument("--hero", choices=sorted(HEROES), default="swarm")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "assets")
    parser.add_argument("--all-heroes", type=Path, help="also write every hero to this folder")
    args = parser.parse_args()
    kind = Type(Font(args.font, "s"), Font(args.mono_font, "m"))
    files: dict[Path, str] = {}
    for mode in ("light", "dark"):
        files[args.out / f"hero-{mode}.svg"] = HEROES[args.hero](kind, mode == "dark")
        files[args.out / f"results-{mode}.svg"] = detection_chart(kind, mode)
        files[args.out / f"cost-{mode}.svg"] = cost_chart(kind, mode)
        if args.all_heroes:
            for name, make in HEROES.items():
                files[args.all_heroes / f"hero-{name}-{mode}.svg"] = make(kind, mode == "dark")
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"wrote {path} ({len(text) // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
