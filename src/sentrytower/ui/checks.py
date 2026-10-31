"""``sentrytower doctor`` in a terminal: each check with a mark, and the command that fixes a missing tool."""

from __future__ import annotations

import sys
from typing import Any

from ..programs import which
from .term import PLAIN, Line
from .theme import Theme
from .widgets import Symbols

INSTALL = {
    "darwin": {"rg": "brew install ripgrep", "fd": "brew install fd", "node": "brew install node"},
    "debian": {
        "rg": "sudo apt install ripgrep",
        "fd": "sudo apt install fd-find",
        "node": "see https://nodejs.org (Node.js 22.19 or later)",
    },
}


def platform_key() -> str | None:
    if sys.platform == "darwin":
        return "darwin" if which("brew") else None
    if which("apt"):
        return "debian"
    return None


def check_lines(checks: list[Any], theme: Theme, sym: Symbols) -> list[Line]:
    from ..doctor import FAIL, OK, SKIP, WARN

    marks = {OK: (sym.check, theme.good), WARN: (sym.warning, theme.caution), FAIL: (sym.cross, theme.bad), SKIP: (sym.dot, theme.dim)}
    names = {"python": "Python", "node": "Node.js", "pi": "Pi agent", "rg": "ripgrep", "fd": "fd", "api key": "Key", "endpoint": "Endpoint"}
    width = max(len(value) for value in names.values())
    install = INSTALL.get(platform_key() or "", {})
    lines: list[Line] = []
    for check in checks:
        mark, style = marks.get(check.status, (sym.dot, theme.dim))
        label = names.get(check.name, check.name)
        lines.append([(f"{mark}  ", style), (label + " " * (width - len(label)) + "  ", theme.bold), (check.detail, PLAIN)])
        if check.status in (WARN, FAIL):
            fix = install.get(check.name) if check.status == FAIL else None
            if fix:
                lines.append([(" " * (width + 5), PLAIN), ("run  ", theme.dim), (fix, theme.name)])
            elif check.hint:
                lines.append([(" " * (width + 5), PLAIN), (check.hint, theme.dim)])
    failed = sum(1 for check in checks if check.status == FAIL)
    lines.append([])
    if failed:
        summary = f"{failed} check{'s' if failed != 1 else ''} failed. "
        lines.append([(f"{sym.cross}  ", theme.bad), (summary, PLAIN), ("Fix them, then run sentrytower doctor again.", theme.dim)])
    else:
        lines.append([(f"{sym.check}  ", theme.good), ("Everything is ready.", PLAIN)])
    return lines
