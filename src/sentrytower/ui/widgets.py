"""The prompts of the interactive screens.

One prompt is live at a time, at the bottom of the terminal: a question
with its marker ``◆``, the answer area on a rail ``│``, and a line of key
hints. An answered prompt stays in the scrollback as ``◇`` with its answer,
so the whole setup reads as one column. Esc or Ctrl-C cancels
(``CancelledError``); nothing is saved.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from .keys import KeySource
from .mascot import BADGE, art
from .screen import Screen
from .term import PLAIN, Caps, Line, Style, cells
from .theme import AGENT_COLORS, Theme

T = TypeVar("T")


class CancelledError(Exception):
    """The person cancelled the prompt (Esc or Ctrl-C)."""


@dataclass(frozen=True)
class Symbols:
    bar: str = "│"
    active: str = "◆"
    done: str = "◇"
    stop: str = "■"
    start: str = "┌"
    end: str = "└"
    on: str = "●"
    off: str = "○"
    pointer: str = "❯"
    check: str = "✓"
    cross: str = "✗"
    star: str = "★"
    warning: str = "▲"
    dot: str = "·"
    cursor: str = "▌"
    spinner: tuple[str, ...] = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    bar_full: str = "━"
    bar_empty: str = "━"


ASCII = Symbols(
    bar="|",
    active="*",
    done="o",
    stop="x",
    start="/",
    end="\\",
    on=">",
    off=" ",
    pointer=">",
    check="+",
    cross="x",
    star="*",
    warning="!",
    dot="-",
    cursor="_",
    spinner=("-", "\\", "|", "/"),
    bar_full="#",
    bar_empty=".",
)


@dataclass
class Choice:
    value: Any
    label: str
    hint: str = ""
    tag: str = ""
    disabled: str | None = None
    search_text: str = ""
    columns: list[str] = field(default_factory=list)


def fuzzy_score(query: str, text: str) -> int | None:
    """A match score of ``query`` in ``text`` (higher is better), or None. Each word of the query must match."""
    text = text.lower()
    total = 0
    for word in query.lower().split():
        if text == word:
            total += 1000
        elif text.startswith(word):
            total += 600
        elif f"/{word}" in text or f"-{word}" in text:
            total += 400
        elif word in text:
            total += 300 - text.index(word)
        else:
            position = 0
            for char in word:
                found = text.find(char, position)
                if found < 0:
                    return None
                position = found + 1
            total += 50
    return total


class Prompter:
    def __init__(self, screen: Screen, keys: KeySource, theme: Theme, caps: Caps) -> None:
        self.screen = screen
        self.keys = keys
        self.theme = theme
        self.caps = caps
        self.sym = Symbols() if caps.unicode else ASCII

    def rail(self, line: Line | None = None, *, active: bool = False) -> Line:
        style = self.theme.mark if active else self.theme.dim
        return [(f"{self.sym.bar}  ", style), *(line or [])]

    def head(self, question: str, *, active: bool = True, marker: str | None = None) -> Line:
        symbol = marker or (self.sym.active if active else self.sym.done)
        style = self.theme.mark if active else self.theme.good
        return [(f"{symbol}  ", style), (question, self.theme.bold)]

    def foot(self, hint: str, *, warning: str | None = None) -> Line:
        if warning:
            return [(f"{self.sym.end}  ", self.theme.mark), (f"{self.sym.warning} {warning}", self.theme.caution)]
        return [(f"{self.sym.end}  ", self.theme.mark), (hint, self.theme.dim)]

    def print(self, lines: list[Line]) -> None:
        self.screen.print(lines)

    def intro(self, lines: list[Line]) -> None:
        self.screen.print(lines)

    def note(self, lines: list[Line]) -> None:
        """Lines on the rail that stay."""
        self.screen.print([self.rail(line) for line in lines])

    def answered(self, question: str, answer: str | Line, *, extra: list[Line] | None = None) -> None:
        value: Line = [(answer, self.theme.dim)] if isinstance(answer, str) else answer
        self.screen.print([self.head(question, active=False), self.rail(value), *[self.rail(line) for line in extra or []], self.rail()])

    def outro(self, text: str | Line) -> None:
        line: Line = [(text, PLAIN)] if isinstance(text, str) else text
        self.screen.print([[(f"{self.sym.end}  ", self.theme.dim), *line], []])

    def _key(self) -> str:
        try:
            key = self.keys.read()
        except KeyboardInterrupt:
            # Ctrl-C sends SIGINT in cbreak mode: it cancels like Esc.
            raise CancelledError() from None
        if key in (None, "esc"):
            raise CancelledError()
        return key

    def select(
        self,
        question: str,
        choices: Sequence[Choice],
        *,
        default: int = 0,
        hint: str | None = None,
        answer: Callable[[Choice], str] | None = None,
    ) -> Choice:
        """One of ``choices`` with the arrow keys."""
        index = default if 0 <= default < len(choices) else 0
        while choices[index].disabled and index + 1 < len(choices):
            index += 1
        width = max(cells(choice.label) for choice in choices)
        keys_hint = hint or f"↑↓ move {self.sym.dot} enter choose {self.sym.dot} esc cancel"
        while True:
            lines: list[Line] = [self.head(question)]
            for position, choice in enumerate(choices):
                chosen = position == index
                mark = (f"{self.sym.on} ", self.theme.mark) if chosen else (f"{self.sym.off} ", self.theme.dim)
                label_style = self.theme.bold if chosen else (self.theme.dim if choice.disabled else PLAIN)
                row: Line = [mark, (choice.label + " " * (width - cells(choice.label)), label_style)]
                note = choice.disabled or choice.hint
                if note:
                    row.append(("   " + note, self.theme.dim))
                if choice.tag:
                    row += [("  ", PLAIN), (f" {choice.tag} ", self.theme.tag)]
                lines.append(self.rail(row, active=True))
            lines.append(self.foot(keys_hint))
            self.screen.draw(lines)
            key = self._key()
            if key in ("up", "k", "shift-tab"):
                index = self._step(choices, index, -1)
            elif key in ("down", "j", "tab"):
                index = self._step(choices, index, 1)
            elif key == "enter" and not choices[index].disabled:
                self.screen.clear()
                self.answered(question, answer(choices[index]) if answer else choices[index].label)
                return choices[index]
            elif key.isdigit() and 0 < int(key) <= len(choices) and not choices[int(key) - 1].disabled:
                index = int(key) - 1

    @staticmethod
    def _step(choices: Sequence[Choice], index: int, delta: int) -> int:
        position = index
        for _ in range(len(choices)):
            position = (position + delta) % len(choices)
            if not choices[position].disabled:
                return position
        return index

    def text(
        self,
        question: str,
        *,
        default: str = "",
        placeholder: str = "",
        secret: bool = False,
        validate: Callable[[str], str | None] | None = None,
        hint: str | None = None,
        answer: Callable[[str], str] | None = None,
    ) -> str:
        """A line of text; ``validate`` returns a problem or None."""
        value = default
        problem: str | None = None
        keys_hint = hint or f"enter confirm {self.sym.dot} esc cancel"
        while True:
            shown = "•" * len(value) if secret and self.caps.unicode else ("*" * len(value) if secret else value)
            field_line: Line = [(shown, self.theme.bold)] if value else [(placeholder, self.theme.dim)] if placeholder else []
            cursor = (self.sym.cursor, self.theme.mark)
            field_line = [cursor, *field_line] if not value and placeholder else [*field_line, cursor]
            self.screen.draw([self.head(question), self.rail(field_line, active=True), self.foot(keys_hint, warning=problem)])
            key = self._key()
            if key == "enter":
                candidate = value.strip()
                problem = validate(candidate) if validate else None
                if problem is None:
                    self.screen.clear()
                    shown_answer = answer(candidate) if answer else ("•" * min(len(candidate), 12) if secret else candidate)
                    self.answered(question, shown_answer or "(none)")
                    return candidate
            elif key == "backspace":
                value = value[:-1]
                problem = None
            elif key == "ctrl-u":
                value = ""
                problem = None
            elif key == "ctrl-w":
                value = value.rstrip().rsplit(" ", 1)[0] if " " in value.rstrip() else ""
            elif len(key) == 1 and key.isprintable():
                value += key
                problem = None

    def search(
        self,
        question: str,
        choices: Sequence[Choice],
        *,
        query: str = "",
        limit: int = 8,
        hint: str | None = None,
        empty: str = "No match",
        answer: Callable[[Choice], str] | None = None,
    ) -> Choice:
        """One of many ``choices``: type to filter, arrows to move. Columns come from ``Choice.columns``."""
        index = 0
        top = 0
        while True:
            if query.strip():
                ranked: list[tuple[int, int, Choice]] = []
                for position, choice in enumerate(choices):
                    score = fuzzy_score(query, choice.search_text or choice.label)
                    if score is not None:
                        ranked.append((-score, position, choice))
                shown = [choice for _, _, choice in sorted(ranked, key=lambda item: (item[0], item[1]))]
            else:
                shown = list(choices)
            index = min(index, max(0, len(shown) - 1))
            top = min(max(top, index - limit + 1), index)
            window = shown[top : top + limit]
            widths = [
                max((cells(choice.columns[column]) for choice in window if len(choice.columns) > column), default=0)
                for column in range(max((len(choice.columns) for choice in window), default=0))
            ]
            lines: list[Line] = [self.head(question)]
            search = [("Search ", self.theme.dim), (f"{self.sym.pointer} ", self.theme.mark), (query, self.theme.bold)]
            lines.append(self.rail([*search, (self.sym.cursor, self.theme.mark)], active=True))
            if not window:
                lines.append(self.rail([("  " + empty, self.theme.dim)], active=True))
            for position, choice in enumerate(window, start=top):
                chosen = position == index
                row: Line = [((self.sym.pointer if chosen else " ") + " ", self.theme.mark)]
                for column, text in enumerate(choice.columns or [choice.label]):
                    width = widths[column] if column < len(widths) else cells(text)
                    style = (self.theme.bold if chosen else PLAIN) if column == 0 else self.theme.dim
                    if column == 0 and choice.tag:
                        style = self.theme.name if chosen else Style(fg=self.theme.accent_text)
                    row.append((text + " " * (width - cells(text)) + "   ", style))
                lines.append(self.rail(row, active=True))
            count = f"{len(shown)} of {len(choices)}"
            lines.append(self.foot(hint or f"{count} {self.sym.dot} type to search {self.sym.dot} ↑↓ move {self.sym.dot} enter choose"))
            self.screen.draw(lines)
            key = self._key()
            if key == "up":
                index = max(0, index - 1)
            elif key == "down":
                index = min(len(shown) - 1, index + 1)
            elif key == "pageup":
                index = max(0, index - limit)
            elif key == "pagedown":
                index = min(len(shown) - 1, index + limit)
            elif key == "enter" and shown:
                self.screen.clear()
                self.answered(question, answer(shown[index]) if answer else shown[index].label)
                return shown[index]
            elif key == "backspace":
                query = query[:-1]
                index = top = 0
            elif key == "ctrl-u":
                query = ""
                index = top = 0
            elif len(key) == 1 and key.isprintable():
                query += key
                index = top = 0

    def palette(self, question: str, *, default: str, name: str) -> str:
        """The agent colour: the five agents side by side (a list when the terminal is narrow or has few colours)."""
        keys = list(AGENT_COLORS)
        index = keys.index(default) if default in keys else 0
        gap = 4
        art_width = BADGE + gap
        fits = self.screen.width - 4 >= len(keys) * art_width and art(keys[0], BADGE, self.caps.color)
        if not fits:
            choices = [Choice(key, AGENT_COLORS[key][0]) for key in keys]
            return str(self.select(question, choices, default=index).value)
        while True:
            arts = [art(key, BADGE, self.caps.color) for key in keys]
            rows: list[Line] = []
            for row in range(len(arts[0])):
                line: Line = []
                for column, lines_of_art in enumerate(arts):
                    line += lines_of_art[row]
                    line.append((" " * gap, PLAIN))
                rows.append(line)
            labels: Line = []
            marks: Line = []
            for position, key in enumerate(keys):
                label, _, base, dark = AGENT_COLORS[key]
                chosen = position == index
                tone = base if self.theme.background == "dark" else dark
                labels.append((label + " " * (art_width - cells(label)), Style(fg=tone, bold=True) if chosen else self.theme.dim))
                underline = ("▔" if self.caps.unicode else "^") * len(label) if chosen else ""
                marks.append((underline + " " * (art_width - len(underline)), Style(fg=tone, bold=True)))
            lines = [self.head(question)] + [self.rail(row, active=True) for row in rows]
            lines += [self.rail(labels, active=True), self.rail(marks, active=True)]
            lines.append(self.foot(f"← → choose {self.sym.dot} enter confirm {self.sym.dot} {name} wears it on every screen"))
            self.screen.draw(lines)
            key = self._key()
            if key in ("left", "h", "shift-tab", "up"):
                index = (index - 1) % len(keys)
            elif key in ("right", "l", "tab", "down"):
                index = (index + 1) % len(keys)
            elif key == "enter":
                self.screen.clear()
                self.answered(question, AGENT_COLORS[keys[index]][0])
                return keys[index]

    def wait(self, message: str, work: Callable[[], T], *, done: str | None = None) -> T:
        """Run ``work`` in a thread and show a spinner until it ends; return its result or raise its error."""
        result: dict[str, Any] = {}

        def run() -> None:
            try:
                result["value"] = work()
            except BaseException as error:  # noqa: BLE001 - re-raised in the caller's thread
                result["error"] = error

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        frame = 0
        try:
            while thread.is_alive():
                spinner = self.sym.spinner[frame % len(self.sym.spinner)]
                self.screen.draw([[(f"{spinner}  ", self.theme.mark), (message, self.theme.dim)]])
                frame += 1
                thread.join(0.08)
        except KeyboardInterrupt:
            self.screen.clear()
            raise CancelledError() from None
        self.screen.clear()
        if "error" in result:
            raise result["error"]
        if done:
            self.screen.print([[(f"{self.sym.check}  ", self.theme.good), (done, PLAIN)]])
        return result["value"]  # type: ignore[no-any-return]


def tilde(path: Path, *, from_cwd: bool = False) -> str:
    """A path for the screen: ``~/...`` below the home folder, ``./...`` below the current folder (with ``from_cwd``).

    Both sides are resolved first: on macOS the temporary folders are below
    ``/var``, a symbolic link of ``/private/var``.
    """
    resolved = path.expanduser().resolve()
    home = Path.home().resolve()
    if resolved == home:
        return "~"
    if home in resolved.parents:
        return f"~/{resolved.relative_to(home)}"
    if from_cwd:
        cwd = Path.cwd().resolve()
        if cwd in resolved.parents:
            return f"./{resolved.relative_to(cwd)}"
    return str(path)


def progress_bar(fraction: float, width: int, theme: Theme, sym: Symbols) -> Line:
    fraction = max(0.0, min(1.0, fraction))
    full = round(fraction * width)
    return [(sym.bar_full * full, theme.mark), (sym.bar_empty * (width - full), theme.dim)]


def elapsed_text(seconds: float) -> str:
    seconds = int(max(0, seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def tokens_text(tokens: int | float | None) -> str:
    if tokens is None:
        return "0"
    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M" if tokens < 10_000_000 else f"{tokens / 1_000_000:.0f}M"
    if tokens >= 1_000:
        return f"{tokens / 1_000:.0f}k"
    return str(int(tokens))


def money(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"${value:.2f}" if value >= 0.01 or value == 0 else f"${value:.4f}"


def now() -> float:
    return time.monotonic()
