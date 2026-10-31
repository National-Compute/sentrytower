"""A live region at the bottom of the terminal, and lines that stay in the scrollback above it.

``Screen.draw`` replaces the live region with new lines (the current prompt,
the progress of an audit). ``Screen.print`` writes lines that stay. Each
line is clipped to the width of the terminal, so no line wraps and the
region can be redrawn in place. The cursor is hidden while a region is
live and shown again at the end, also after an error.

``Recorder`` writes each change of the screen as one JSON line (the time,
the kind and the styled lines). ``scripts/render_demo.py`` turns such a
recording into the animated image of the README.
"""

from __future__ import annotations

import atexit
import json
import shutil
import sys
import time
from pathlib import Path
from typing import TextIO

from .term import Caps, Line, Style, clip, to_ansi

HIDE_CURSOR, SHOW_CURSOR = "\x1b[?25l", "\x1b[?25h"


def _style_record(style: Style) -> dict[str, object]:
    record: dict[str, object] = {}
    for key in ("fg", "bg"):
        value = getattr(style, key)
        if value is not None:
            record[key] = list(value)
    for key in ("bold", "dim", "italic", "underline"):
        if getattr(style, key):
            record[key] = True
    return record


class Recorder:
    """The changes of the screen as JSON lines: {"t": seconds, "kind": "print" | "draw" | "size", "lines": [...]}."""

    def __init__(self, path: Path, caps: Caps) -> None:
        self.path = path
        self.started = time.monotonic()
        self.stream = path.open("a", encoding="utf-8")
        self._write("size", [], width=caps.width, height=caps.height)

    def _write(self, kind: str, lines: list[Line], **extra: object) -> None:
        record = {
            "t": round(time.monotonic() - self.started, 3),
            "kind": kind,
            "lines": [[[text, _style_record(style)] for text, style in line] for line in lines],
            **extra,
        }
        self.stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.stream.flush()

    def print(self, lines: list[Line]) -> None:
        self._write("print", lines)

    def draw(self, lines: list[Line]) -> None:
        self._write("draw", lines)

    def close(self) -> None:
        self.stream.close()


class Screen:
    def __init__(self, caps: Caps, stream: TextIO | None = None, recorder: Recorder | None = None) -> None:
        self.caps = caps
        self.stream = stream or sys.stdout
        self.recorder = recorder
        self.live: list[Line] = []
        self._height = 0
        self._hidden = False
        atexit.register(self.close)

    @property
    def width(self) -> int:
        if self.stream is sys.stdout:
            return max(40, shutil.get_terminal_size((self.caps.width, self.caps.height)).columns)
        return self.caps.width

    @property
    def height(self) -> int:
        if self.stream is sys.stdout:
            return max(10, shutil.get_terminal_size((self.caps.width, self.caps.height)).lines)
        return self.caps.height

    def _write(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    def _clip(self, lines: list[Line]) -> list[Line]:
        """The lines cut to the width less one cell, so that no line wraps."""
        width = self.width - 1
        return [clip(line, width) for line in lines]

    def _render(self, lines: list[Line]) -> list[str]:
        return [to_ansi(line, self.caps.color) for line in lines]

    def _erase_live(self) -> str:
        if not self._height:
            return ""
        up = f"\x1b[{self._height - 1}A" if self._height > 1 else ""
        return f"\r{up}\x1b[J"

    def draw(self, lines: list[Line]) -> None:
        """Replace the live region with ``lines`` (at most the height of the terminal less one)."""
        limit = max(1, self.height - 1)
        shown = lines[-limit:] if len(lines) > limit else lines
        if not self._hidden:
            self._write(HIDE_CURSOR)
            self._hidden = True
        clipped = self._clip(shown)
        rendered = self._render(clipped)
        up = f"\x1b[{self._height - 1}A" if self._height > 1 else ""
        start = f"\r{up}" if self._height else ""
        self._write(start + "\n".join(f"\x1b[2K{text}" for text in rendered) + "\x1b[J")
        self._height = len(rendered)
        self.live = list(shown)
        if self.recorder is not None:
            self.recorder.draw(clipped)

    def print(self, lines: list[Line]) -> None:
        """Lines that stay in the scrollback; the live region is drawn again below them."""
        live = self.live
        clipped = self._clip(lines)
        text = self._erase_live() + "".join(line + "\n" for line in self._render(clipped))
        self._write(text)
        self._height = 0
        if self.recorder is not None:
            self.recorder.print(clipped)
        if live:
            self.draw(live)

    def clear(self) -> None:
        """Remove the live region."""
        self._write(self._erase_live())
        self._height = 0
        self.live = []
        if self.recorder is not None:
            self.recorder.draw([])

        self.live = []

    def close(self) -> None:
        if self._hidden:
            try:
                self._write(SHOW_CURSOR)
            except (OSError, ValueError):
                pass
            self._hidden = False
        if self.recorder is not None:
            self.recorder.close()
            self.recorder = None


def screen_for(caps: Caps, environ: dict[str, str] | None = None) -> Screen:
    """A screen of stdout; ``SENTRYTOWER_RECORD`` names a file that records each change."""
    import os

    env = os.environ if environ is None else environ
    path = env.get("SENTRYTOWER_RECORD")
    recorder = Recorder(Path(path), caps) if path else None
    return Screen(caps, recorder=recorder)
