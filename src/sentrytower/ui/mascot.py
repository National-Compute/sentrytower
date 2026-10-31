"""The agent as half-block pixel art.

Each terminal cell shows two pixels, one above the other: the upper half
block ``▀`` in the colour of the upper pixel, on the colour of the lower
pixel. A terminal cell is about twice as tall as it is wide, so the pixels
are about square. The art needs 256 colours or more; with fewer colours the
screens show the agent's name without the art.
"""

from __future__ import annotations

import base64
import zlib
from functools import lru_cache

from .mascot_data import IMAGES
from .term import COLOR256, PLAIN, RGB, TRUECOLOR, Line, Style, line_cells
from .theme import AGENT_COLORS, DEFAULT_AGENT_COLOR

HERO = 26
BADGE = 14


@lru_cache(maxsize=16)
def pixels(color: str, width: int) -> tuple[tuple[RGB | None, ...], ...]:
    key = (color if color in AGENT_COLORS else DEFAULT_AGENT_COLOR, width)
    w, h, data = IMAGES[key]
    raw = zlib.decompress(base64.b64decode(data))
    rows = []
    for y in range(h):
        row = []
        for x in range(w):
            r, g, b, a = raw[4 * (y * w + x) : 4 * (y * w + x) + 4]
            row.append((r, g, b) if a else None)
        rows.append(tuple(row))
    return tuple(rows)


def art(color: str, width: int, mode: str) -> list[Line]:
    """The agent as lines of half blocks, or no lines when the terminal has fewer than 256 colours."""
    if mode not in (TRUECOLOR, COLOR256):
        return []
    grid = pixels(color, width)
    lines: list[Line] = []
    for y in range(0, len(grid), 2):
        top_row = grid[y]
        bottom_row = grid[y + 1] if y + 1 < len(grid) else (None,) * len(top_row)
        line: Line = []
        for top, bottom in zip(top_row, bottom_row, strict=True):
            if top and bottom:
                cell = ("▀", Style(fg=top, bg=bottom))
            elif top:
                cell = ("▀", Style(fg=top))
            elif bottom:
                cell = ("▄", Style(fg=bottom))
            else:
                cell = (" ", PLAIN)
            if line and line[-1][1] == cell[1]:
                line[-1] = (line[-1][0] + cell[0], cell[1])
            else:
                line.append(cell)
        lines.append(line)
    # No blank row above or below the agent.
    while lines and all(not text.strip() for text, _ in lines[0]):
        lines.pop(0)
    while lines and all(not text.strip() for text, _ in lines[-1]):
        lines.pop()
    return lines


def beside(left: list[Line], right: list[Line], gap: int = 3, *, top: int = 0) -> list[Line]:
    """Two blocks of lines side by side: ``right`` starts ``top`` lines down."""
    width = max((line_cells(line) for line in left), default=0)
    rows = max(len(left), len(right) + top)
    out: list[Line] = []
    for index in range(rows):
        left_line = left[index] if index < len(left) else []
        right_index = index - top
        right_line = right[right_index] if 0 <= right_index < len(right) else []
        filler = width - line_cells(left_line) + (gap if left else 0)
        out.append([*left_line, (" " * filler, PLAIN), *right_line] if right_line else list(left_line))
    return out
