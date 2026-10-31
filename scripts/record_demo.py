#!/usr/bin/env python3
"""Run SentryTower in a pseudo-terminal, type a scripted session, and record the screen.

Usage: python3 scripts/record_demo.py SCRIPT.json RECORDING.jsonl [--columns 100] [--rows 34] [-- COMMAND ...]

The script is a JSON list of steps:
    {"expect": "text"}          wait until the screen shows the text (at most 120 s; a long audit: "timeout": 3600)
    {"keys": ["down", "enter"]} send keys (key names as in ui/keys.py, or single characters)
    {"type": "Juno", "delay": 0.09}  type a text, one key at a time
    {"sleep": 1.5}              wait
COMMAND defaults to `sentrytower setup`. The recording is the screen
recording of the program (SENTRYTOWER_RECORD); this script only drives it.
The environment of this script goes to the program, so a key in it reaches
the program only through the environment, never through this script's
arguments or output.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import select
import struct
import sys
import termios
import time
from pathlib import Path

KEYS = {
    "up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D", "enter": "\r", "esc": "\x1b", "backspace": "\x7f",
    "tab": "\t", "shift-tab": "\x1b[Z", "ctrl-c": "\x03", "ctrl-u": "\x15", "pagedown": "\x1b[6~", "pageup": "\x1b[5~",
}  # fmt: skip


def screen_text(recording: Path) -> str:
    """The text of the current screen: the printed lines and the last live region."""
    printed: list[str] = []
    live: list[str] = []
    try:
        lines = recording.read_text().splitlines()
    except OSError:
        return ""
    for raw in lines:
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        text = ["".join(part[0] for part in line) for line in event.get("lines") or []]
        if event.get("kind") == "print":
            printed.extend(text)
        elif event.get("kind") == "draw":
            live = text
    return "\n".join(printed[-80:] + live)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("script", type=Path)
    parser.add_argument("recording", type=Path)
    parser.add_argument("--columns", type=int, default=100)
    parser.add_argument("--rows", type=int, default=34)
    # The command follows "--"; the options of this script may come before or after the two paths.
    argv = sys.argv[1:]
    command = argv[argv.index("--") + 1 :] if "--" in argv else []
    args = parser.parse_args(argv[: argv.index("--")] if "--" in argv else argv)
    command = command or ["sentrytower", "setup"]
    steps = json.loads(args.script.read_text())
    if args.recording.exists():
        args.recording.unlink()
    environment = {**os.environ, "SENTRYTOWER_RECORD": str(args.recording), "COLORTERM": "truecolor", "TERM": "xterm-256color",
                   "COLUMNS": str(args.columns), "LINES": str(args.rows)}  # fmt: skip
    for name in ("CI", "GITHUB_ACTIONS", "NO_COLOR"):
        environment.pop(name, None)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(command[0], command, environment)  # noqa: S606 - the program of the recording, without a shell
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", args.rows, args.columns, 0, 0))

    tail = bytearray()

    def drain(seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                tail.extend(data)
                del tail[:-8192]

    def last_output() -> str:
        """The last output of the program without escape codes (to see why a text never came)."""
        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", tail.decode("utf-8", errors="replace"))
        return "\n".join(line.rstrip() for line in text.splitlines()[-25:])

    def send(text: str) -> None:
        os.write(fd, text.encode())

    try:
        for step in steps:
            if "expect" in step:
                deadline = time.monotonic() + float(step.get("timeout", 120))
                while step["expect"] not in screen_text(args.recording):
                    if time.monotonic() > deadline:
                        print(f"record_demo: the screen never showed {step['expect']!r}; the last output:", file=sys.stderr)
                        print(last_output(), file=sys.stderr)
                        return 1
                    drain(0.2)
                drain(float(step.get("after", 0.4)))
            elif "keys" in step:
                for key in step["keys"]:
                    send(KEYS.get(key, key))
                    drain(float(step.get("delay", 0.35)))
            elif "type" in step:
                for char in step["type"]:
                    send(char)
                    drain(float(step.get("delay", 0.08)))
            elif "sleep" in step:
                drain(float(step["sleep"]))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            drain(0.2)
    finally:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    print(f"recorded {args.recording}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
