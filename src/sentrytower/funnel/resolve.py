"""Phase 4 without the model: line resolution, ranking, duplicates and the output caps.

Each source gives findings of one form (``Finding``): the free-roaming
session and the deep-check sessions. A unit check gives leads, never output
findings; the orchestrator resolves the line of a lead with the same rules.
The orchestrator resolves the line of each finding, verifies it, and then
selects the output:

1. Line resolution of a deep-check finding (the findings of the
   free-roaming session keep their reported locations): the
   critical-operation line (1 to 3 lines) is the line of the quoted code
   near a reported location, else in the unit, else the line of a
   pattern-search mark near a reported location in the file of the first
   location. It replaces the reported location that holds it, in its place:
   the order of the reported locations stays, and only the first
   ``max_locations`` of them can take it. When nothing resolves, the claimed
   locations stay.
2. Ranking of the deep-check findings: the keep score of the blind
   verification (0.5 without one), then the severity, then the queue score
   of the unit, then the creation order.
3. One ranked list: the findings of the free-roaming session first, in
   their order, then the deep-check findings in rank order. A deep-check
   finding that repeats a kept finding (the same defect: one file, first
   locations at most ``dedup_radius_lines`` apart) goes.
4. Caps for each finding of the list: at most ``max_findings_per_file``
   findings for each file of a first location, and at most
   ``max_findings_total`` findings for the run.

These four rules give tier 1, the output of a standard run, with the
verdict that a standard run uses (the first vote). A run of more than one
standard run adds tier 2 after it: further findings in the extra slots
(``extra_findings_total``, ``extra_findings_per_file``), from the same
sources and from the passes (focus sessions, the sweep). Tier 2 takes a
finding that its votes call exploitable, then one whose verification did not
run; it never removes or reorders a tier-1 finding.

Standard library only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .pacing import Parameters
from .protocols import clean_quote, normalize_cwe
from .slices import SourceFiles, split_lines

# The tier of each source of the output: the free-roaming session and a
# deep-check finding at its lead, then another finding of a deep check.
FREE_SOURCE = "free-roaming"
FOCUS_SOURCE = "focus"
SWEEP_SOURCE = "sweep"
SOURCE_TIERS = {FREE_SOURCE: 3, "deep-check": 3, "nearby": 2, FOCUS_SOURCE: 2, SWEEP_SOURCE: 2}
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
UNVERIFIED_SCORE = 0.5
# The reason of an unverified finding when the run gave none: its verification did not start before the stop.
UNVERIFIED_REASON = "the run stopped before its verification"
# Code that a finding quotes in its prose, as `code`.
_CODE_SPAN = re.compile(r"(?<!\\)`((?:\\`|[^`\n])*?)(?<!\\)`")
_CODE_CHARACTERS = frozenset("()[]{}=.;:<>'\"/$_")
_SPACES = re.compile(r"\s+")
# Folder prefixes that a model writes before a repository path: the
# repository folder of the container image, its form without the first "/",
# "./", and the prefixes of a diff. ``configure_root`` adds the repository
# folder of the run when it is another folder.
_DEFAULT_PREFIXES = ("/workspace/repo/", "workspace/repo/", "./", "a/", "b/")
_ROOT_PREFIXES: tuple[str, ...] = _DEFAULT_PREFIXES


def configure_root(*roots: str) -> tuple[str, ...]:
    """Add the repository folder of the run (as given and as a real path) to the root prefixes.

    The container image mounts the repository at ``/workspace/repo``; a run
    in another folder adds that folder, with and without its first "/".
    Returns the prefixes.
    """
    global _ROOT_PREFIXES
    added: list[str] = []
    for root in roots:
        for form in (str(root), os.path.realpath(str(root))):
            text = form.replace("\\", "/").rstrip("/")
            if text.count("/") < 1 or not text.strip("/"):
                continue
            for prefix in (text + "/", text.lstrip("/") + "/"):
                if prefix not in _DEFAULT_PREFIXES and prefix not in added:
                    added.append(prefix)
    _ROOT_PREFIXES = (*_DEFAULT_PREFIXES, *added)
    return _ROOT_PREFIXES


@dataclass
class Finding:
    """One output candidate of any source."""

    id: str
    source: str
    order: int
    title: str
    severity: str
    evidence: str
    exploit_conditions: str
    cwe: list[str]
    reported: list[dict[str, Any]]
    quotes: list[str] = field(default_factory=list)
    verdict: str | None = None
    unit_id: str | None = None
    lead_id: str | None = None
    unit_score: float = 0.0
    unit_range: tuple[int, int] | None = None
    resolution: dict[str, Any] | None = None
    locations: list[dict[str, Any]] = field(default_factory=list)
    verify: dict[str, Any] | None = None
    # The first vote of the verification: the verdict of a standard run (verify holds the combined votes).
    first_verify: dict[str, Any] | None = None
    dropped: str | None = None
    note: str | None = None
    # Why a finding that a run verifies has no verification (the call failed, the budget refused it, the run stopped).
    verify_note: str | None = None
    # The tier of the output: 1 (the standard rule) or 2 (the extra slots of a deeper run); 0 when not in the output.
    output_tier: int = 0

    @property
    def tier(self) -> int:
        return SOURCE_TIERS.get(self.source, 0)

    @property
    def verification(self) -> str:
        """verified; unverified (a verification that failed, was refused or did not run); none for a free-roaming finding."""
        if self.source == FREE_SOURCE:
            return "none"
        return "verified" if self.verify is not None else "unverified"

    def first(self) -> dict[str, Any] | None:
        return self.locations[0] if self.locations else None


def code_quotes(text: str) -> list[str]:
    """The code spans that a prose text quotes, without plain words."""
    spans = (clean_quote(span.replace("\\`", "`")) for span in _CODE_SPAN.findall(text or ""))
    return [span for span in spans if 6 <= len(span) <= 200 and _CODE_CHARACTERS & set(span)]


def clean_path(path: str) -> str:
    text = path.strip().replace("\\", "/")
    changed = True
    while changed:
        changed = False
        for prefix in _ROOT_PREFIXES:
            if text.startswith(prefix) and len(text) > len(prefix):
                text = text[len(prefix) :]
                changed = True
    return text.lstrip("/")


def resolve_path(path: str, files: SourceFiles, known: Iterable[str] = ()) -> str | None:
    """The repository path of a cited path: exact, else the one known path that ends with it."""
    cleaned = clean_path(path)
    if not cleaned:
        return None
    if files.is_file(cleaned):
        return cleaned
    suffix = "/" + cleaned
    found = [candidate for candidate in known if candidate.endswith(suffix) and files.is_file(candidate)]
    return found[0] if len(found) == 1 else None


def _normal(text: str) -> str:
    return _SPACES.sub(" ", text).strip()


def quote_lines(lines: list[str], quote: str) -> list[tuple[int, int]]:
    """Each place of a quote in the file as (first line, line count up to 3)."""
    parts = [_normal(part) for part in split_lines(quote) if _normal(part)]
    if not parts or len(parts[0]) < 4:
        return []
    normalized = [_normal(line) for line in lines]
    places = []
    for index, line in enumerate(normalized):
        if parts[0] not in line:
            continue
        span = 1
        for offset, part in enumerate(parts[1:3], start=1):
            if index + offset < len(normalized) and part in normalized[index + offset]:
                span += 1
            else:
                break
        places.append((index + 1, span))
    return places


def _nearest(places: list[tuple[int, int]], target: int) -> tuple[int, int]:
    return min(places, key=lambda place: (abs(place[0] - target), place[0]))


def _located(finding: Finding, files: SourceFiles, known: list[str]) -> list[tuple[int, str, list[str], int, int]]:
    """The reported locations with a readable file, in their order: (index, path, lines, first line, last line)."""
    located = []
    for index, item in enumerate(finding.reported):
        path = resolve_path(str(item.get("path") or ""), files, known)
        if path is not None:
            located.append((index, path, files.lines(path) or [], int(item["line_start"]), int(item["line_end"])))
    return located


def _resolved(
    located: list[tuple[int, str, list[str], int, int]], position: int, path: str, start: int, end: int, method: str
) -> dict[str, Any]:
    """The resolution and the reported location that it replaces: the first one that holds the line, else its source."""
    holder = next(
        (index for index, other, _, low, high in located if other == path and low <= start <= high),
        located[position][0],
    )
    return {"path": path, "line_start": start, "line_end": end, "method": method, "location": holder}


def resolve_first(
    finding: Finding,
    files: SourceFiles,
    known: Iterable[str],
    signals: Mapping[str, Sequence[Mapping[str, Any]]],
    parameters: Parameters,
) -> dict[str, Any] | None:
    """The resolved critical-operation location of a finding, or None without a readable location.

    Only the first ``max_locations`` reported locations with a readable file
    take part: the output keeps the order of the reported locations and at
    most that many of them. ``location`` of the result is the index of the
    reported location that the resolved line replaces.

    1. A quote of the finding near a reported location (within
       ``resolve_window_lines``), else in the unit of the finding, else a
       quote with at most three places in the file of the first location.
    2. The nearest mark of the pattern search within 10 lines of a reported
       location in the file of the first location, a mark of a CWE of the
       finding first.
    3. The first reported location with a readable file, unchanged.
    """
    located = _located(finding, files, list(known))[: parameters.max_locations]
    if not located:
        return None
    quotes = [quote for quote in (clean_quote(text) for text in finding.quotes) if quote]
    window = parameters.resolve_window_lines
    for quote in quotes:
        for position, (_, path, lines, start, end) in enumerate(located):
            places = quote_lines(lines, quote)
            near = [place for place in places if start - window <= place[0] <= end + window]
            if not near and position == 0 and finding.unit_range is not None:
                low, high = finding.unit_range
                near = [place for place in places if low <= place[0] <= high]
            if near:
                line, span = _nearest(near, start)
                return _resolved(located, position, path, line, line + span - 1, "quote")
    _, path, lines, start, end = located[0]
    for quote in quotes:
        places = quote_lines(lines, quote)
        if 0 < len(places) <= 3:
            line, span = _nearest(places, start)
            return _resolved(located, 0, path, line, line + span - 1, "quote")
    wanted = set(finding.cwe)
    first_path = located[0][1]
    for position, (_, path, lines, start, end) in enumerate(located):
        if path != first_path:
            # The marks come from the file of the first location only.
            continue
        marks = [
            signal for signal in signals.get(path, []) if isinstance(signal.get("line"), int) and start - 10 <= signal["line"] <= end + 10
        ]
        if marks:
            same = [signal for signal in marks if normalize_cwe(signal.get("cwe")) in wanted] or marks
            line = min((signal["line"] for signal in same), key=lambda value: (abs(value - start), value))
            return _resolved(located, position, path, line, line, "signal")
    for index, path, lines, start, end in located:
        if lines and start > len(lines):
            continue
        end = min(end, len(lines)) if lines else end
        return {"path": path, "line_start": start, "line_end": max(start, end), "method": "claimed", "location": index}
    return None


def final_locations(
    finding: Finding,
    resolution: dict[str, Any] | None,
    files: SourceFiles,
    known: Iterable[str],
    parameters: Parameters,
) -> list[dict[str, Any]]:
    """The output locations: the reported locations in their order, the resolved line in the place of its location.

    The resolved line replaces one reported location and adds none. A
    location of a file that the repository does not have, a repeat and a
    span above ``max_location_lines`` drop out; at most ``max_locations``
    stay.
    """
    locations: list[dict[str, Any]] = []
    limit = parameters.max_location_lines
    target = None if resolution is None else resolution.get("location")
    known = list(known)
    for index, item in enumerate(finding.reported):
        path = resolve_path(str(item.get("path") or ""), files, known)
        if path is None:
            continue
        if index == target and resolution is not None:
            entry = {"path": resolution["path"], "line_start": resolution["line_start"], "line_end": resolution["line_end"]}
        else:
            entry = {"path": path, "line_start": int(item["line_start"]), "line_end": int(item["line_end"])}
        if entry["line_end"] - entry["line_start"] + 1 <= limit and entry not in locations:
            locations.append(entry)
        if len(locations) >= parameters.max_locations:
            break
    return locations


def rank_key(finding: Finding, *, first: bool = False) -> tuple[Any, ...]:
    """The order of the deep-check findings: keep score, severity, queue score, creation order.

    ``first`` takes the keep score of the first vote (the rank of a standard run).
    """
    verdict = (finding.first_verify or finding.verify) if first else finding.verify
    score = None if verdict is None else verdict.get("keep_score")
    return (
        -(UNVERIFIED_SCORE if score is None else float(score)),
        -SEVERITY_RANK.get(finding.severity, 0),
        -finding.unit_score,
        finding.order,
    )


def same_defect(first: Mapping[str, Any], second: Mapping[str, Any], radius: int) -> bool:
    if first["path"] != second["path"]:
        return False
    return max(first["line_start"], second["line_start"]) - min(first["line_end"], second["line_end"]) <= radius


# The sources of the passes of a deeper run: never in tier 1.
PASS_SOURCES = (FOCUS_SOURCE, SWEEP_SOURCE)


def select_output(findings: Iterable[Finding], parameters: Parameters) -> tuple[list[Finding], list[dict[str, Any]]]:
    """The output findings in one ranked list (tier 1, then tier 2), and a record of each finding that is not in it.

    Tier 1 is the rule of a standard run: the findings of the free-roaming
    session first, in their order, then the deep-check findings in rank order
    with the verdict of their first vote (``rank_key``); a deep-check finding
    that repeats a kept finding (the same defect) goes; then each finding of
    the list, free or not, fills the caps: at most ``max_findings_per_file``
    findings for each file of a first location (``file-cap``) and at most
    ``max_findings_total`` findings for the run (``run-cap``). The findings of
    the passes are not in tier 1.

    Tier 2 comes after tier 1 (a run of more than one standard run): the
    findings that tier 1 left and the findings of the passes, those that the
    majority of their votes calls exploitable first, then those whose
    verification did not run, each in rank order, up to
    ``extra_findings_total`` findings and ``max_findings_per_file`` +
    ``extra_findings_per_file`` for each file (tier 1 counts). A finding of
    tier 2 never removes or reorders a finding of tier 1.
    """
    findings = list(findings)
    radius = parameters.dedup_radius_lines
    removed: list[dict[str, Any]] = []
    free = sorted((finding for finding in findings if finding.source == FREE_SOURCE), key=lambda item: item.order)
    workers: list[Finding] = []
    for finding in findings:
        finding.output_tier = 0
        if finding.source == FREE_SOURCE:
            continue
        elif finding.dropped is not None:
            removed.append(_removed(finding, finding.dropped))
        elif not finding.locations:
            removed.append(_removed(finding, "no-location"))
        else:
            workers.append(finding)
    standard = [finding for finding in workers if finding.source not in PASS_SOURCES]
    tier1: list[Finding] = []
    left: list[tuple[Finding, str]] = []
    per_file: dict[str, int] = {}

    def repeat_of(finding: Finding, kept: list[Finding]) -> Finding | None:
        first = finding.locations[0] if finding.locations else None
        return next(
            (other for other in kept if first is not None and other.locations and same_defect(other.locations[0], first, radius)), None
        )

    for finding in [*free, *sorted(standard, key=lambda item: rank_key(item, first=True))]:
        first = finding.locations[0] if finding.locations else None
        # Two findings of the free-roaming session never remove each other.
        repeat = None if finding.source == FREE_SOURCE else repeat_of(finding, tier1)
        if repeat is not None:
            removed.append(_removed(finding, "duplicate", repeat.id))
        elif first is not None and per_file.get(first["path"], 0) >= parameters.max_findings_per_file:
            left.append((finding, "file-cap"))
        elif len(tier1) >= parameters.max_findings_total:
            left.append((finding, "run-cap"))
        else:
            tier1.append(finding)
            if first is not None:
                per_file[first["path"]] = per_file.get(first["path"], 0) + 1
    # Tier 2: the extra slots of a deeper run.
    reasons = {finding.id: reason for finding, reason in left}
    others = [finding for finding, _ in left if finding.source != FREE_SOURCE] + [item for item in workers if item.source in PASS_SOURCES]
    exploitable = sorted((item for item in others if item.verify is not None and item.verify.get("verdict") == "exploitable"), key=rank_key)
    unverified = sorted((item for item in others if item.verify is None), key=rank_key)
    chosen = {item.id for item in [*exploitable, *unverified]}
    tier2: list[Finding] = []
    for finding in [*exploitable, *unverified]:
        first = finding.locations[0]
        repeat = repeat_of(finding, [*tier1, *tier2])
        if repeat is not None:
            removed.append(_removed(finding, "duplicate", repeat.id))
        elif per_file.get(first["path"], 0) >= parameters.max_findings_per_file + parameters.extra_findings_per_file:
            removed.append(_removed(finding, reasons.get(finding.id, "file-cap")))
        elif len(tier2) >= parameters.extra_findings_total:
            removed.append(_removed(finding, reasons.get(finding.id, "run-cap")))
        else:
            tier2.append(finding)
            per_file[first["path"]] = per_file.get(first["path"], 0) + 1
    for finding, reason in left:
        if finding.id not in chosen:
            removed.append(_removed(finding, reason))
    for item in workers:
        if item.source in PASS_SOURCES and item.id not in chosen:
            removed.append(_removed(item, "not-exploitable"))
    for item in tier1:
        item.output_tier = 1
    for item in tier2:
        item.output_tier = 2
    return [*tier1, *tier2], removed


def _removed(finding: Finding, reason: str, duplicate_of: str | None = None) -> dict[str, Any]:
    first = finding.first() or (finding.reported[0] if finding.reported else {})
    record: dict[str, Any] = {
        "id": finding.id,
        "source": finding.source,
        "reason": reason,
        "path": first.get("path"),
        "line": first.get("line_start"),
    }
    if duplicate_of is not None:
        record["duplicate_of"] = duplicate_of
    return record


def finding_item(finding: Finding, rank: int) -> dict[str, Any]:
    """One output finding: the fields of the agent findings schema and the funnel record."""
    verify = finding.verify or {}
    return {
        "title": finding.title,
        "locations": [dict(item) for item in finding.locations],
        "cwe": list(finding.cwe),
        "severity": finding.severity,
        "evidence": finding.evidence,
        "exploit_conditions": finding.exploit_conditions,
        "funnel": {
            "id": finding.id,
            "rank": rank,
            "source": finding.source,
            "tier": finding.tier,
            "output_tier": finding.output_tier or 1,
            "verdict": finding.verdict,
            "unit_id": finding.unit_id,
            "lead_id": finding.lead_id,
            "resolution": (finding.resolution or {}).get("method"),
            "reported_locations": [dict(item) for item in finding.reported],
            "verify": verify.get("verdict"),
            "keep_score": verify.get("keep_score"),
            "verification": finding.verification,
            "verification_reason": (finding.verify_note or UNVERIFIED_REASON) if finding.verification == "unverified" else None,
        },
    }


def reported_locations(items: Any) -> list[dict[str, Any]]:
    """The valid locations of a finding item: path, first line and last line."""
    found = []
    for item in items if isinstance(items, list) else [items]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        start, end = item.get("line_start"), item.get("line_end")
        if isinstance(start, bool) or not isinstance(start, int) or start < 1:
            continue
        if isinstance(end, bool) or not isinstance(end, int) or end < 1:
            end = start
        start, end = min(start, end), max(start, end)
        location = {"path": clean_path(item["path"]), "line_start": start, "line_end": end}
        if location["path"] and location not in found:
            found.append(location)
    return found


def finding_from_item(item: Mapping[str, Any], *, identifier: str, source: str, order: int, extra_quotes: Iterable[str] = ()) -> Finding:
    """A finding from one item of the agent findings schema (the free-roaming session or a deep check)."""
    severity = str(item.get("severity") or "").strip().lower()
    labels = item.get("cwe")
    cwe = [label for label in (normalize_cwe(value) for value in (labels if isinstance(labels, list) else [labels])) if label]
    evidence = text if isinstance(text := item.get("evidence"), str) else ""
    conditions = given if isinstance(given := item.get("exploit_conditions"), str) else ""
    notes = " ".join(str(location.get("note") or "") for location in item.get("locations") or [] if isinstance(location, dict))
    raw_title = item.get("title")
    title = raw_title if isinstance(raw_title, str) and raw_title.strip() else "Finding"
    return Finding(
        id=identifier,
        source=source,
        order=order,
        title=title.strip()[:300],
        severity=severity if severity in SEVERITY_RANK else "medium",
        evidence=evidence,
        exploit_conditions=conditions,
        cwe=list(dict.fromkeys(cwe)),
        reported=reported_locations(item.get("locations")),
        quotes=[*extra_quotes, *code_quotes(evidence), *code_quotes(notes)],
    )
