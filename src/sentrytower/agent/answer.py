"""The findings of an answer of the agent: locations, CWE identifiers, severity and prose.

The answer contract asks for one JSON object ``{"findings": [...]}``. Each
item has a title, a list of locations (path relative to the repository
root, first and last line, the most important location first), CWE
identifiers, a severity, the evidence and the exploit conditions.

The reading accepts the common deviations from the schema and records each
one: a path alias (``file``, ``file_path``, ``filepath``), a line alias
(``line``, ``lines``, ``line_range``, ``start_line``), a ``path:N`` suffix,
a reversed range, and a location list given as one object or one string.
A bad location is dropped alone. An item without a valid location stays a
finding without a location. Only an item that is not an object is dropped.

Standard library only.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low")
# A line number has at most 9 digits: model text cannot make int() fail or a number without limit.
# "app.py:12", "app.py:12-14", or "app.py#L12-L14".
_PATH_WITH_LINES = re.compile(r"^(?P<path>.+?)(?::|#L)(?P<start>[0-9]{1,9})(?:-L?(?P<end>[0-9]{1,9}))?$")
_LINE_RANGE = re.compile(r"^\s*(?P<start>[0-9]{1,9})\s*(?:[-:]\s*(?P<end>[0-9]{1,9}))?\s*$")
_CWE_ID = re.compile(r"\bCWE-([0-9]{1,9})\b", re.IGNORECASE)
_URI_SCHEME = re.compile(r"^file:(?://)?", re.IGNORECASE)
IMAGE_REPOSITORY_ROOT = "/workspace/repo"
# The heading of the exploit conditions of a finding in the outputs. The conditions are a claim of the model that read
# the code; no part of SentryTower runs the code or observes an exploit.
CONDITIONS_LABEL = "Attack conditions, as the model states them"


@dataclass(frozen=True)
class Location:
    path: str
    line_start: int
    line_end: int
    note: str | None = None

    def key(self) -> tuple[str, int, int]:
        return (self.path, self.line_start, self.line_end)


@dataclass
class AgentFinding:
    """One finding of an answer, as the reading gives it."""

    index: int
    title: str
    severity: str
    cwe: list[str]
    locations: list[Location]
    evidence: str
    exploit_conditions: str
    deviations: list[str] = field(default_factory=list)
    dropped_locations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        text = self.evidence.strip()
        if self.exploit_conditions.strip():
            text = f"{text}\n\n{CONDITIONS_LABEL}: {self.exploit_conditions.strip()}".strip()
        return text


def relative_path(path: str, cwd: str | None, roots: tuple[str, ...] = ()) -> str:
    """A cited path relative to the repository root when it is under the root."""
    text = _URI_SCHEME.sub("", path.strip().replace("\\", "/"))
    if text.startswith("//"):
        text = "/" + text.lstrip("/")
    candidates = {root.rstrip("/") for root in (*roots, IMAGE_REPOSITORY_ROOT) if root and root.strip("/")}
    if cwd:
        candidates.add(cwd.rstrip("/"))
        if cwd.startswith("/private/"):
            candidates.add(cwd.removeprefix("/private").rstrip("/"))
    for prefix in sorted(candidates, key=len, reverse=True):
        if text.startswith(prefix + "/"):
            text = text[len(prefix) + 1 :]
            break
    while text.startswith("./"):
        text = text[2:]
    return text


def _line_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, float) and math.isfinite(value) and value.is_integer() and value >= 1:
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isascii() and text.isdigit() and len(text) <= 9 and int(text) >= 1:
            return int(text)
    return None


def _line_range(value: Any) -> tuple[int, int | None] | None:
    single = _line_number(value)
    if single is not None:
        return single, None
    if isinstance(value, str) and (match := _LINE_RANGE.match(value)):
        start = int(match.group("start"))
        end = int(match.group("end")) if match.group("end") else None
        return (start, end) if start >= 1 else None
    if isinstance(value, list) and value and len(value) <= 2:
        numbers = [_line_number(item) for item in value]
        if all(number is not None for number in numbers):
            return numbers[0], numbers[-1]  # type: ignore[return-value]
    return None


def parse_location(item: dict[str, Any], cwd: str | None, roots: tuple[str, ...] = ()) -> tuple[Location | None, list[str], str | None]:
    """One cited location: the path and the lines, the deviations, and a drop reason."""
    deviations: list[str] = []
    path = item.get("path")
    if not isinstance(path, str):
        for alias in ("file", "file_path", "filepath"):
            if isinstance(item.get(alias), str):
                path = item[alias]
                deviations.append(f"path from {alias}")
                break
    if not isinstance(path, str) or not path.strip():
        return None, deviations, "missing path"
    start = _line_number(item.get("line_start"))
    end = _line_number(item.get("line_end"))
    if start is None:
        for alias in ("line", "lines", "line_range", "start_line"):
            parsed = _line_range(item.get(alias))
            if parsed is not None:
                start, alias_end = parsed
                end = end or alias_end
                deviations.append(f"lines from {alias}")
                break
    if match := _PATH_WITH_LINES.match(path.strip()):
        path = match.group("path")
        if start is None:
            start = int(match.group("start"))
            end = end or int(match.group("end") or match.group("start"))
            deviations.append("lines from path")
        else:
            deviations.append("line suffix removed from path")
    if start is None or start < 1:
        return None, deviations, "missing line_start"
    relative = relative_path(path, cwd, roots)
    if not relative:
        return None, deviations, "missing path"
    if end is None:
        end = start
        deviations.append("line_end set to line_start")
    if end < start:
        start, end = end, start
        deviations.append("line range reversed")
    note = given if isinstance(given := item.get("note"), str) and given.strip() else None
    return Location(path=relative, line_start=start, line_end=end, note=note), deviations, None


def cited_locations(
    item: dict[str, Any], cwd: str | None, roots: tuple[str, ...] = ()
) -> tuple[list[Location], list[str], list[dict[str, Any]]]:
    """The valid locations of one finding in the listed order (no exact repeats), the deviations and the drops.

    An item without the key ``locations`` gives its top-level path and lines
    (an older answer format).
    """
    if "locations" not in item:
        location, found, _ = parse_location(item, cwd, roots)
        return ([location] if location is not None else []), found, []
    entries = item["locations"]
    deviations: list[str] = []
    if isinstance(entries, (dict, str)):
        deviations.append(f"locations is one {'object' if isinstance(entries, dict) else 'string'}")
        entries = [entries]
    if not isinstance(entries, list):
        return [], [*deviations, "locations is not a list"], []
    valid: list[Location] = []
    dropped: list[dict[str, Any]] = []
    for position, entry in enumerate(entries):
        origin = f"locations[{position}]"
        if isinstance(entry, str):
            entry = {"path": entry}
        if not isinstance(entry, dict):
            dropped.append({"location": position, "reason": "not an object"})
            continue
        location, entry_deviations, reason = parse_location(entry, cwd, roots)
        deviations.extend(f"{origin}: {deviation}" for deviation in entry_deviations)
        if location is None:
            dropped.append({"location": position, "reason": reason})
        elif any(other.key() == location.key() for other in valid):
            deviations.append(f"{origin}: duplicate removed")
        else:
            valid.append(location)
    return valid, deviations, dropped


def cwe_labels(value: Any) -> list[str]:
    """CWE identifiers in their order, without repeats and without leading zeros (CWE-079 gives CWE-79)."""
    values = value if isinstance(value, list) else [value]
    labels: list[str] = []
    for item in values:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            item = f"CWE-{item}"
        if isinstance(item, str):
            text = item.strip()
            for match in _CWE_ID.finditer(f"CWE-{text}" if text.isascii() and text.isdigit() else text):
                label = f"CWE-{int(match.group(1))}"
                if label not in labels:
                    labels.append(label)
    return labels


def normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in SEVERITIES else "unknown"


def read_findings(
    document: dict[str, Any], *, cwd: str | None, roots: tuple[str, ...] = ()
) -> tuple[list[AgentFinding], list[dict[str, Any]]]:
    """The findings of an answer and the dropped items (an item that is not an object)."""
    findings: list[AgentFinding] = []
    dropped: list[dict[str, Any]] = []
    for index, item in enumerate(document.get("findings") or []):
        if not isinstance(item, dict):
            dropped.append({"index": index, "reason": "not an object"})
            continue
        locations, deviations, dropped_locations = cited_locations(item, cwd, roots)
        labels = cwe_labels(item.get("cwe"))
        primary = labels[0] if labels else None
        first = locations[0] if locations else None
        title = given if isinstance(given := item.get("title"), str) else ""
        title = title.strip() or (f"{primary or 'Finding'} in {first.path}" if first else primary or "Finding")
        evidence = text if isinstance(text := item.get("evidence"), str) else ""
        conditions = more if isinstance(more := item.get("exploit_conditions"), str) else ""
        findings.append(
            AgentFinding(
                index=index,
                title=title,
                severity=normalize_severity(item.get("severity")),
                cwe=labels,
                locations=locations,
                evidence=evidence,
                exploit_conditions=conditions,
                deviations=deviations,
                dropped_locations=dropped_locations,
            )
        )
    return findings, dropped
