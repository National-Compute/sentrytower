"""Keys from the terminal: one key at a time, without echo, with the escape sequences of the arrow keys.

``KeyReader`` puts the terminal in cbreak mode (no line buffer, no echo;
Ctrl-C still sends SIGINT) and restores it on exit. ``read`` returns a key
name ("up", "down", "left", "right", "enter", "esc", "backspace", "tab",
"shift-tab", "home", "end", "pageup", "pagedown", "delete", "ctrl-u",
"ctrl-w") or the typed character. ``ScriptedKeys`` replays a list of keys
for tests and recordings.
"""

from __future__ import annotations

import os
import select
import sys
import time
from collections.abc import Iterable, Iterator
from typing import Protocol

_SEQUENCES = {
    "[A": "up",
    "[B": "down",
    "[C": "right",
    "[D": "left",
    "[H": "home",
    "[F": "end",
    "OA": "up",
    "OB": "down",
    "OC": "right",
    "OD": "left",
    "OH": "home",
    "OF": "end",
    "[1~": "home",
    "[4~": "end",
    "[7~": "home",
    "[8~": "end",
    "[3~": "delete",
    "[5~": "pageup",
    "[6~": "pagedown",
    "[Z": "shift-tab",
}
_CONTROL = {"\r": "enter", "\n": "enter", "\t": "tab", "\x7f": "backspace", "\x08": "backspace", "\x15": "ctrl-u", "\x17": "ctrl-w"}
ESCAPE_WAIT = 0.05


class KeySource(Protocol):
    def read(self, timeout: float | None = None) -> str | None: ...

    def flush(self) -> None: ...

    def __enter__(self) -> KeySource: ...

    def __exit__(self, *args: object) -> None: ...


class KeyReader:
    """Keys of the controlling terminal (stdin)."""

    def __init__(self, fd: int | None = None) -> None:
        self.fd = sys.stdin.fileno() if fd is None else fd
        self._saved: list | None = None  # type: ignore[type-arg]
        self._pending = b""

    def __enter__(self) -> KeyReader:
        import termios
        import tty

        self._saved = termios.tcgetattr(self.fd)
        tty.setcbreak(self.fd)
        return self

    def __exit__(self, *args: object) -> None:
        if self._saved is not None:
            import termios

            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._saved)
            self._saved = None

    def flush(self) -> None:
        """Drop the keys that came while nothing read them (for example during an audit)."""
        import termios

        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except (termios.error, OSError):
            pass
        self._pending = b""

    def _byte(self, timeout: float | None) -> bytes:
        if self._pending:
            byte, self._pending = self._pending[:1], self._pending[1:]
            return byte
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return b""
        return os.read(self.fd, 1)

    def read(self, timeout: float | None = None) -> str | None:
        """One key, or None when no key came within ``timeout`` seconds."""
        first = self._byte(timeout)
        if not first:
            return None
        if first == b"\x1b":
            sequence = b""
            while True:
                more = self._byte(ESCAPE_WAIT)
                if not more:
                    break
                sequence += more
                text = sequence.decode("ascii", errors="replace")
                if text in _SEQUENCES:
                    return _SEQUENCES[text]
                if len(sequence) > 6 or (len(sequence) >= 2 and (more.isalpha() or more == b"~")):
                    break
            return "esc" if not sequence else _SEQUENCES.get(sequence.decode("ascii", errors="replace"), "unknown")
        if first[0] >= 0x80:
            # A UTF-8 character: read its continuation bytes.
            count = 1 if first[0] < 0xE0 else 2 if first[0] < 0xF0 else 3
            data = first + b"".join(self._byte(ESCAPE_WAIT) for _ in range(count))
            return data.decode("utf-8", errors="replace")
        char = first.decode("ascii", errors="replace")
        return _CONTROL.get(char, char)


class ScriptedKeys:
    """Keys from a list; a number is a pause in seconds (for recordings), the end of the list is "esc"."""

    def __init__(self, keys: Iterable[str | float], *, typing_delay: float = 0.0) -> None:
        self._keys: Iterator[str | float] = iter(keys)
        self.typing_delay = typing_delay

    def __enter__(self) -> ScriptedKeys:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def flush(self) -> None:
        return None

    def read(self, timeout: float | None = None) -> str | None:
        for item in self._keys:
            if isinstance(item, (int, float)):
                time.sleep(float(item))
                continue
            if self.typing_delay:
                time.sleep(self.typing_delay)
            return item
        return "esc"
