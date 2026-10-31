"""Terminal capabilities and styled lines of text.

A ``Line`` is a list of ``(text, Style)`` segments. ``to_ansi`` writes a line
with the escape codes of the colour mode of the terminal: true colour, 256
colours, 16 colours or none. Widths count terminal cells: a wide character
(CJK, most emoji) takes two cells, a combining mark none.

The text of a segment can come from a model that read untrusted code, or
from a file name of the audited repository. ``to_ansi`` and ``to_plain``
write each control character of it as "?" (``printable``): only the styles
of the interface give escape codes, so a finding title cannot move the
cursor, change the title of the window or write the clipboard.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata
from dataclasses import dataclass
from typing import Mapping, TextIO

RGB = tuple[int, int, int]
TRUECOLOR, COLOR256, COLOR16, NOCOLOR = "truecolor", "256", "16", "none"
# Any of these variables marks a CI job: no prompts, no animation, the plain lines.
CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
    "TF_BUILD",
    "TEAMCITY_VERSION",
    "CIRCLECI",
    "BITBUCKET_BUILD_NUMBER",
    "DRONE",
    "CODEBUILD_BUILD_ID",
)
# Terminals that render 24-bit colour; macOS Terminal renders 256 colours.
TRUECOLOR_PROGRAMS = frozenset({"iTerm.app", "WezTerm", "vscode", "ghostty", "Hyper", "Tabby", "WarpTerminal", "rio", "zed"})
TRUECOLOR_TERMS = frozenset({"xterm-kitty", "xterm-ghostty", "alacritty", "wezterm", "foot", "contour"})


@dataclass(frozen=True)
class Caps:
    """What the terminal can do."""

    color: str = NOCOLOR
    unicode: bool = True
    interactive: bool = False
    width: int = 80
    height: int = 24
    background: str = "dark"


def color_mode(environ: Mapping[str, str]) -> str:
    if environ.get("NO_COLOR"):
        return NOCOLOR
    force = environ.get("FORCE_COLOR") or environ.get("CLICOLOR_FORCE")
    term = environ.get("TERM", "")
    if term == "dumb" and not force:
        return NOCOLOR
    if environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return TRUECOLOR
    if environ.get("TERM_PROGRAM") in TRUECOLOR_PROGRAMS or term in TRUECOLOR_TERMS:
        return TRUECOLOR
    if "256" in term or environ.get("TERM_PROGRAM") == "Apple_Terminal":
        return COLOR256
    if force:
        return TRUECOLOR if force in ("3", "truecolor") else COLOR256
    return COLOR16 if term else NOCOLOR


def background_of(environ: Mapping[str, str], configured: str | None = None) -> str:
    """dark or light: the configured theme, ``SENTRYTOWER_THEME``, else ``COLORFGBG``, else dark."""
    for value in (configured, environ.get("SENTRYTOWER_THEME")):
        if value in ("dark", "light"):
            return value
    parts = environ.get("COLORFGBG", "").split(";")
    if len(parts) >= 2 and parts[-1].isdigit():
        return "light" if int(parts[-1]) in (7, 15) else "dark"
    return "dark"


def in_ci(environ: Mapping[str, str]) -> bool:
    return any(environ.get(name) for name in CI_VARIABLES)


def detect(
    stdout: TextIO | None = None,
    stdin: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    plain: bool = False,
    theme: str | None = None,
) -> Caps:
    """The capabilities of this terminal. ``plain`` turns the interactive experience off."""
    out = stdout or sys.stdout
    inp = stdin or sys.stdin
    env = os.environ if environ is None else environ

    def tty(stream: TextIO) -> bool:
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError, OSError):
            return False

    interactive = not plain and tty(out) and tty(inp) and not in_ci(env) and env.get("TERM", "") != "dumb"
    encoding = (getattr(out, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    size = shutil.get_terminal_size((100, 30))
    return Caps(
        color=color_mode(env) if (interactive or env.get("FORCE_COLOR")) else NOCOLOR,
        unicode=encoding in ("utf8", "utf8sig") or (not encoding and "UTF-8" in env.get("LANG", "").upper()),
        interactive=interactive,
        width=max(40, size.columns),
        height=max(10, size.lines),
        background=background_of(env, theme),
    )


@dataclass(frozen=True)
class Style:
    fg: RGB | None = None
    bg: RGB | None = None
    bold: bool = False
    dim: bool = False
    italic: bool = False
    underline: bool = False


PLAIN = Style()
Segment = tuple[str, Style]
Line = list[Segment]


ZERO_WIDTH = frozenset(chr(code) for code in (0x200B, 0x200C, 0x200D, 0xFE0F))


def char_cells(char: str) -> int:
    if unicodedata.combining(char) or char in ZERO_WIDTH:
        return 0
    return 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1


def cells(text: str) -> int:
    """The width of a text in terminal cells."""
    return sum(char_cells(char) for char in text)


def line_cells(line: Line) -> int:
    return sum(cells(text) for text, _ in line)


def clip(line: Line, width: int, ellipsis: str = "…") -> Line:
    """The line cut to ``width`` cells; a cut line ends with the ellipsis."""
    if line_cells(line) <= width:
        return line
    room = max(0, width - cells(ellipsis))
    out: Line = []
    used = 0
    last_style = PLAIN
    for text, style in line:
        last_style = style
        kept = ""
        for char in text:
            size = char_cells(char)
            if used + size > room:
                break
            kept += char
            used += size
        if kept:
            out.append((kept, style))
        if used >= room or len(kept) < len(text):
            break
    out.append((ellipsis, last_style))
    return out


# The characters that a terminal reads as control codes (C0, DEL, C1), and the bidirectional embeddings,
# overrides and isolates, which show a text in another order than it has.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def printable(text: str) -> str:
    """``text`` with each control character as "?": one cell each, so the width of the text does not change."""
    return _CONTROL.sub("?", text)


# The same characters but the line feed and the tab, for a text of several lines.
_CONTROL_IN_TEXT = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def printable_text(text: str) -> str:
    """``text`` with its lines and tabs, and each other control character as "?" (a CRLF line end is a line feed)."""
    return _CONTROL_IN_TEXT.sub("?", text.replace("\r\n", "\n"))


def to_plain(line: Line) -> str:
    return "".join(printable(text) for text, _ in line)


_CUBE = (0, 95, 135, 175, 215, 255)
_NORMAL = ((0, 0, 0), (205, 49, 49), (13, 188, 121), (229, 229, 16), (36, 114, 200), (188, 63, 188), (17, 168, 205), (229, 229, 229))
_BRIGHT = ((102, 102, 102), (241, 76, 76), (35, 209, 139), (245, 245, 67), (59, 142, 234), (214, 112, 214), (41, 184, 219), (255, 255, 255))
_BASIC = _NORMAL + _BRIGHT


def _distance(a: RGB, b: RGB) -> int:
    return (a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2


def _nearest_level(value: int) -> int:
    """The index of the level of the 6x6x6 cube nearest to one channel."""
    return min(range(6), key=lambda i: abs(_CUBE[i] - value))


def to_256(rgb: RGB) -> int:
    """The nearest colour of the xterm 256-colour palette (the 6x6x6 cube or the grey ramp)."""
    index = [_nearest_level(value) for value in rgb]
    cube = (_CUBE[index[0]], _CUBE[index[1]], _CUBE[index[2]])
    grey_level = min(23, max(0, round((sum(rgb) / 3 - 8) / 10)))
    level = 8 + 10 * grey_level
    if _distance(rgb, (level, level, level)) < _distance(rgb, cube):
        return 232 + grey_level
    return 16 + 36 * index[0] + 6 * index[1] + index[2]


def to_16(rgb: RGB) -> int:
    return min(range(16), key=lambda i: _distance(rgb, _BASIC[i]))


def _color_code(rgb: RGB, mode: str, background: bool) -> str:
    if mode == TRUECOLOR:
        return f"{48 if background else 38};2;{rgb[0]};{rgb[1]};{rgb[2]}"
    if mode == COLOR256:
        return f"{48 if background else 38};5;{to_256(rgb)}"
    index = to_16(rgb)
    base = (40 if background else 30) if index < 8 else (100 if background else 90)
    return str(base + index % 8)


def sgr(style: Style, mode: str) -> str:
    """The escape code that starts ``style`` (empty for no colour or a plain style)."""
    if mode == NOCOLOR:
        return ""
    codes = []
    if style.bold:
        codes.append("1")
    if style.dim:
        codes.append("2")
    if style.italic:
        codes.append("3")
    if style.underline:
        codes.append("4")
    if style.fg is not None:
        codes.append(_color_code(style.fg, mode, False))
    if style.bg is not None:
        codes.append(_color_code(style.bg, mode, True))
    return f"\x1b[{';'.join(codes)}m" if codes else ""


def to_ansi(line: Line, mode: str) -> str:
    """The line with the escape codes of ``mode``; each styled segment ends with a reset."""
    if mode == NOCOLOR:
        return to_plain(line)
    out = []
    for text, style in line:
        start = sgr(style, mode)
        out.append(f"{start}{printable(text)}\x1b[0m" if start else printable(text))
    return "".join(out)
