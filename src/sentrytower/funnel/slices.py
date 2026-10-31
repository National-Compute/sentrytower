"""The code text that a direct model call sees: unit cards, unit slices and claim slices.

- A card (phase 1) is a short summary of one unit: the path and lines, the
  symbol and kind, the tags, the route and guard facts and the top lines of
  the pattern search, about 60 to 120 tokens.
- A unit slice (phase 2) is the code of the plain unit check: the first
  lines of the file (the imports) and the unit, with line numbers, in a code
  fence, and the line ranges that it shows; at most ``slice_max_chars``
  characters. A larger unit keeps windows around the lines that the pattern
  search marked. The slice gives no route fact, no mark and no weakness
  class.
- A claim slice (phase 4) is the code around one claimed line, the first
  lines of the file and the route and guard facts. It holds no text of the
  report that made the claim.

Each line has the prefix of the numbered read of the agent (``{n:>5}│``).
No slice gives the name of the repository, and no slice says that code is
vendored or upstream code.

The funnel accepts each repository: no limit on the count or the size of
the files stops a run. ``SourceFiles`` does not read one file above
``FILE_LIMIT_BYTES`` (such a file is generated or packed data); the units of
that file are skipped, and the run goes on.

Standard library only.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model_client import estimate_tokens

FILE_LIMIT_BYTES = 64 << 20
CACHE_LIMIT_BYTES = 192 << 20
# A card of phase 1: at most CARD_SIGNALS marks, the strongest first, each
# with at most CARD_SIGNAL_CHARS characters of its line; route lines of at
# most CARD_ROUTE_CHARS characters; at most CARD_MAX_TOKENS tokens
# (estimate) for the whole card.
CARD_SIGNALS = 5
CARD_SIGNAL_CHARS = 60
CARD_ROUTE_CHARS = 160
CARD_MAX_TOKENS = 180
WINDOW_RADII = (40, 25, 15, 8, 4)
CLAIM_RADIUS = 60


def split_lines(text: str) -> list[str]:
    """The lines of a text as the inventory, ripgrep and the agent count them.

    The text splits on "\n" only, and a line loses one trailing "\r". A form
    feed, a vertical tab or a Unicode line separator stays in its line:
    ``str.splitlines`` would split there and move each later line number.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


class SourceFiles:
    """The lines of the files of the repository, read one time and kept in a small cache.

    A path is relative to the repository root. A path that leaves the root
    (also through a link), a folder, or a file above ``limit_bytes`` gives
    None.
    """

    def __init__(
        self,
        root: Path,
        *,
        limit_bytes: int = FILE_LIMIT_BYTES,
        cache_size: int = 256,
        cache_bytes: int = CACHE_LIMIT_BYTES,
    ) -> None:
        self.root = Path(os.path.realpath(root))
        self.limit_bytes = limit_bytes
        self.cache_size = cache_size
        self.cache_bytes = cache_bytes
        self._cache: OrderedDict[str, tuple[list[str] | None, int]] = OrderedDict()
        self._cached_bytes = 0

    def resolve(self, path: str) -> Path | None:
        relative = path.strip().replace("\\", "/").lstrip("/")
        if not relative or "\0" in relative:
            return None
        candidate = Path(os.path.realpath(self.root / relative))
        if candidate != self.root and self.root not in candidate.parents:
            return None
        return candidate

    def is_file(self, path: str) -> bool:
        candidate = self.resolve(path)
        return candidate is not None and candidate.is_file()

    def lines(self, path: str) -> list[str] | None:
        """The lines of a file; the cache keeps at most ``cache_size`` files and ``cache_bytes`` bytes."""
        if path in self._cache:
            self._cache.move_to_end(path)
            return self._cache[path][0]
        lines: list[str] | None = None
        size = 0
        candidate = self.resolve(path)
        try:
            if candidate is not None and candidate.is_file():
                size = candidate.stat().st_size
                if size <= self.limit_bytes:
                    lines = split_lines(candidate.read_bytes().decode("utf-8", "replace"))
        except OSError:
            lines = None
        size = size if lines is not None else 0
        self._cache[path] = (lines, size)
        self._cached_bytes += size
        while len(self._cache) > 1 and (len(self._cache) > self.cache_size or self._cached_bytes > self.cache_bytes):
            _, (_, dropped) = self._cache.popitem(last=False)
            self._cached_bytes -= dropped
        return lines


def numbered(lines: list[str], first: int, last: int) -> str:
    """The lines ``first`` to ``last`` (1-based, inclusive) with the numbered-read prefix."""
    return "\n".join(f"{number:>5}│{lines[number - 1]}" for number in range(max(1, first), min(len(lines), last) + 1))


def _int(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def unit_range(unit: Mapping[str, Any]) -> tuple[int, int]:
    start = max(1, _int(unit.get("start_line"), 1))
    return start, max(start, _int(unit.get("end_line"), start))


def unit_routes(unit: Mapping[str, Any], routes: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The routes of the unit: in its file, and on a line of the unit or with the unit as handler."""
    start, end = unit_range(unit)
    symbol = unit.get("symbol")
    found = []
    for route in routes:
        if route.get("path") != unit.get("path"):
            continue
        line = _int(route.get("line"))
        if start <= line <= end or (symbol and route.get("handler") == symbol):
            found.append(route)
    return found


def route_text(route: Mapping[str, Any]) -> str:
    guards = route.get("guards") or []
    guard_text = ", ".join(str(guard) for guard in guards) if isinstance(guards, list) and guards else "none found"
    parts = [str(route.get("method") or "").upper(), str(route.get("route") or "")]
    head = " ".join(part for part in parts if part) or "route"
    framework = f" ({route['framework']})" if route.get("framework") else ""
    handler = f", handler {route['handler']}" if route.get("handler") else ""
    return f"{head}{framework} at line {_int(route.get('line'))}{handler}; guards: {guard_text}"


def signal_label(signal: Mapping[str, Any]) -> str:
    for key in ("class", "kind", "rule"):
        value = signal.get(key)
        if isinstance(value, str) and value:
            return value
    return "pattern"


def _signals(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [signal for signal in unit.get("signals") or [] if isinstance(signal, Mapping)]


# The order of the marks on a card: the strongest first. Sinks (and Semgrep
# results) first, then sources, routes, names and guards; in each kind the
# weight of the inventory rule (``inventory.RULE_BY_ID``), then the line.
_CARD_KIND_RANK = {"sink": 0, "semgrep": 0, "source": 1, "route": 2, "name": 3, "guard": 4}
_RULE_WEIGHTS: dict[str, float] | None = None


def _rule_weights() -> dict[str, float]:
    """The weight of each inventory rule; none without the inventory module."""
    global _RULE_WEIGHTS
    if _RULE_WEIGHTS is None:
        try:
            from .inventory import RULE_BY_ID  # type: ignore[attr-defined]

            _RULE_WEIGHTS = {str(name): float(rule.weight) for name, rule in RULE_BY_ID.items()}
        except Exception:  # noqa: BLE001 - without the inventory module the marks keep the order of the kinds
            _RULE_WEIGHTS = {}
    return _RULE_WEIGHTS


def card_signals(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The signals of a unit for its card, the strongest first."""
    weights = _rule_weights()

    def key(signal: Mapping[str, Any]) -> tuple[int, float, int]:
        rank = _CARD_KIND_RANK.get(str(signal.get("kind") or ""), len(_CARD_KIND_RANK))
        return rank, -weights.get(str(signal.get("rule") or ""), 1.0), _int(signal.get("line"))

    return sorted(_signals(unit), key=key)


def unit_classes(unit: Mapping[str, Any]) -> list[tuple[str | None, str, int]]:
    """The weakness classes that the signals of a unit name: (CWE, label, first line), in signal order.

    A signal of a search hit names no class, so it gives none.
    """
    found: list[tuple[str | None, str, int]] = []
    seen: set[tuple[str | None, str]] = set()
    for signal in _signals(unit):
        cwe = signal.get("cwe") if isinstance(signal.get("cwe"), str) and signal.get("cwe") else None
        label = signal_label(signal)
        if signal.get("kind") == "search-hit" or (cwe is None and label == "pattern"):
            continue
        key = (cwe, label)
        if key not in seen:
            seen.add(key)
            found.append((cwe, label, _int(signal.get("line"))))
    return found


def target_cwe(unit: Mapping[str, Any]) -> str | None:
    """The first CWE that the signals of a unit name, or None."""
    return next((cwe for cwe, _, _ in unit_classes(unit) if cwe), None)


def unit_card(unit: Mapping[str, Any], routes: Iterable[Mapping[str, Any]]) -> str:
    """The phase-1 card of a unit (at most ``CARD_MAX_TOKENS`` tokens).

    The card shows the unit, at most two routes and at most ``CARD_SIGNALS``
    marks, the strongest first (``card_signals``). The lines go into the
    budget in this order: the strongest mark, the routes, the other marks.
    A route that does not fit is left out; a mark that does not fit ends the
    list of marks.
    """
    start, end = unit_range(unit)
    symbol = unit.get("symbol") or "-"
    tags = unit.get("tags") or []
    tag_text = f" tags: {','.join(str(tag) for tag in tags[:6])}" if isinstance(tags, list) and tags else ""
    header = f"[{unit.get('id')}] {unit.get('path')}:{start}-{end} {symbol} ({unit.get('kind') or 'unit'}){tag_text}"
    route_lines = [f"  route: {route_text(route)}"[:CARD_ROUTE_CHARS] for route in list(routes)[:2]]
    mark_lines = []
    for signal in card_signals(unit)[:CARD_SIGNALS]:
        text = " ".join(str(signal.get("text") or "").split())[:CARD_SIGNAL_CHARS]
        cwe = f" {signal['cwe']}" if isinstance(signal.get("cwe"), str) and signal.get("cwe") else ""
        mark_lines.append(f"  L{_int(signal.get('line'))} {signal_label(signal)}{cwe}: {text}")
    shown_routes: list[str] = []
    shown_marks: list[str] = []
    order = [("mark", line) for line in mark_lines[:1]] + [("route", line) for line in route_lines]
    order += [("mark", line) for line in mark_lines[1:]]
    for kind, line in order:
        if estimate_tokens("\n".join([header, *shown_routes, *shown_marks, line])) <= CARD_MAX_TOKENS:
            (shown_marks if kind == "mark" else shown_routes).append(line)
        elif kind == "mark":
            break
    return "\n".join([header, *shown_routes, *shown_marks])


def _merge(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _windows_text(lines: list[str], windows: list[tuple[int, int]]) -> str:
    parts: list[str] = []
    previous = None
    for start, end in windows:
        if previous is not None and start > previous + 1:
            parts.append(f"     …│ (lines {previous + 1} to {start - 1} are not shown)")
        parts.append(numbered(lines, start, end))
        previous = end
    return "\n".join(parts)


def unit_windows(lines: list[str], start: int, end: int, marks: list[int], max_chars: int) -> tuple[str, bool, list[tuple[int, int]]]:
    """The unit lines with numbers, whether they are cut, and the shown ranges.

    A unit that is too long keeps windows around ``marks``; when even the
    smallest windows are too long, the lines from the start of the unit
    that fit.
    """
    end = min(end, len(lines))
    whole = numbered(lines, start, end)
    if len(whole) <= max_chars:
        return whole, False, [(start, end)]
    inside = sorted({mark for mark in marks if start <= mark <= end})
    for radius in WINDOW_RADII:
        windows = _merge([(start, min(end, start + 15)), *((max(start, mark - radius), min(end, mark + radius)) for mark in inside)])
        text = _windows_text(lines, windows)
        if len(text) <= max_chars:
            return text, True, windows
    shown: list[str] = []
    size = 0
    last = start - 1
    for number in range(start, end + 1):
        line = f"{number:>5}│{lines[number - 1]}"
        if size + len(line) + 1 > max_chars:
            break
        shown.append(line)
        size += len(line) + 1
        last = number
    return "\n".join(shown), True, [(start, max(start, last))]


def unit_body(lines: list[str], start: int, end: int, marks: list[int], max_chars: int) -> tuple[str, bool]:
    """The unit lines with numbers; windows around ``marks`` when the whole unit is too long."""
    text, cut, _ = unit_windows(lines, start, end, marks, max_chars)
    return text, cut


def ranges_text(ranges: list[tuple[int, int]]) -> str:
    """Line ranges in words: "1 to 12 and 40 to 75"."""
    parts = [f"{start} to {end}" if end > start else str(start) for start, end in ranges]
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def unit_code(
    unit: Mapping[str, Any], files: SourceFiles, *, max_chars: int, header_lines: int
) -> tuple[dict[str, str] | None, dict[str, Any]]:
    """The values of the plain unit-check template; None when the file cannot be read.

    ``code`` holds the first lines of the file (the imports, up to the line
    before the unit) and the unit, each with its number, and a gap line
    between parts that are not next to each other.
    """
    path = str(unit.get("path") or "")
    lines = files.lines(path)
    if lines is None:
        return None, {"error": "unreadable"}
    start, end = unit_range(unit)
    if start > len(lines):
        return None, {"error": "outside-file"}
    end = min(end, len(lines))
    head_last = min(header_lines, start - 1, len(lines))
    header_ranges = [(1, head_last)] if head_last >= 1 else []
    head_chars = sum(len(lines[number - 1]) + 7 for number in range(1, head_last + 1))
    budget = max(2_000, max_chars - head_chars - 600)
    marks = [_int(signal.get("line")) for signal in _signals(unit)]
    _, cut, windows = unit_windows(lines, start, end, marks, budget)
    shown = _merge([*header_ranges, *windows])
    code = _windows_text(lines, shown)
    fence = "````" if "```" in code else "```"
    language = str(unit.get("language") or "").lower()
    values = {
        "path": path,
        "shown": ranges_text(shown),
        "fence": fence,
        "language": language if language.replace("+", "").replace("#", "").isalnum() else "",
        "code": code,
    }
    return values, {"start": start, "end": end, "cut": cut, "shown": shown, "chars": len(code)}


def header_text(lines: list[str], start: int, header_lines: int) -> str:
    """The first lines of the file (the imports), up to the line before ``start``."""
    last = min(header_lines, start - 1, len(lines))
    return numbered(lines, 1, last) if last >= 1 else ""


def containing_unit(units: Iterable[Mapping[str, Any]], path: str, line: int) -> Mapping[str, Any] | None:
    """The smallest unit of ``path`` that holds ``line``."""
    best = None
    for unit in units:
        if unit.get("path") != path:
            continue
        start, end = unit_range(unit)
        if start <= line <= end and (best is None or end - start < unit_range(best)[1] - unit_range(best)[0]):
            best = unit
    return best


def claim_message(
    *,
    path: str,
    line: int,
    end_line: int,
    cwe: str | None,
    files: SourceFiles,
    unit: Mapping[str, Any] | None,
    routes: list[Mapping[str, Any]],
    max_chars: int,
    header_lines: int,
) -> tuple[str | None, dict[str, Any]]:
    """The user message of a blind verification: the code and the claim, not the reasoning."""
    lines = files.lines(path)
    if lines is None or not 1 <= line <= len(lines):
        return None, {"error": "unreadable"}
    end_line = max(line, min(end_line, len(lines)))
    if unit is not None:
        start, end = unit_range(unit)
        if end - start > 4 * CLAIM_RADIUS or not start <= line <= end:
            start, end = max(1, line - CLAIM_RADIUS), min(len(lines), end_line + CLAIM_RADIUS)
    else:
        start, end = max(1, line - CLAIM_RADIUS), min(len(lines), end_line + CLAIM_RADIUS)
    claim = f"Claim: line {line}" + (f" to {end_line}" if end_line > line else "") + f" of {path}"
    claim += f" has the weakness {cwe}." if cwe else " has a security weakness."
    head = [claim]
    for route in routes[:4]:
        head.append(f"Route: {route_text(route)}")
    header = header_text(lines, start, header_lines)
    prefix = "\n".join(head)
    budget = max(2_000, max_chars - len(prefix) - len(header) - 200)
    body, cut = unit_body(lines, start, min(end, len(lines)), list(range(line, end_line + 1)), budget)
    sections = [prefix]
    if header:
        sections.append("First lines of the file:\n" + header)
    sections.append(f"Code (lines {start} to {min(end, len(lines))}):\n" + body)
    text = "\n\n".join(sections) + "\n"
    return text, {"start": start, "end": end, "cut": cut, "chars": len(text)}
