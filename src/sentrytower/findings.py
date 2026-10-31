"""The findings of a run in the public output format (``findings.json``, schema version 1.0.0).

Each finding has a title, a severity, CWE identifiers, a primary location
(file and line range), up to three related locations, an explanation, the
engine that found it and the route of the run. docs/output-format.md gives
the full schema; ``schemas/findings-v1.schema.json`` is its JSON Schema.

Optional fields hold the result of the run (``run.result``),
the tier of each finding, and the state of its verification
(``verification.status``: ``verified``; ``unverified``, with
``verification.reason``, when the verification failed, was refused or did
not run; ``none`` when the route does not verify the source of the finding).

Engines:

- ``free-roaming``: the agent session of the funnel on the whole repository;
- ``deep-check``: an agent session of the funnel on one code unit with a
  lead (its findings also have the score of a blind verification);
- ``single-agent``: the agent of the route for repositories with more than
  1,000 files.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from . import __version__
from .agent.answer import AgentFinding, cwe_labels, normalize_severity, relative_path

SCHEMA_VERSION = "1.0.0"
SCHEMA_URL = "https://raw.githubusercontent.com/National-Compute/sentrytower/v1/src/sentrytower/schemas/findings-v1.schema.json"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEVERITY_ORDER = {name: rank for rank, name in enumerate(SEVERITIES)}
ENGINE_FREE = "free-roaming"
ENGINE_DEEP = "deep-check"
ENGINE_AGENT = "single-agent"
MAX_LOCATIONS = 4
# The largest line number of a location; a model can claim any number.
MAX_LINE = 10_000_000
# The states of the verification of a finding.
VERIFIED = "verified"
UNVERIFIED = "unverified"
NOT_VERIFIED = "none"
_SPACES = re.compile(r"\s+")


@dataclass(frozen=True)
class OutputLocation:
    path: str
    start_line: int
    end_line: int
    note: str | None = None

    def record(self) -> dict[str, Any]:
        item: dict[str, Any] = {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}
        if self.note:
            item["note"] = self.note
        return item


@dataclass
class OutputFinding:
    """One finding of the output, in rank order."""

    rank: int
    title: str
    severity: str
    cwe: list[str]
    locations: list[OutputLocation]
    evidence: str
    exploit_conditions: str
    engine: str
    route: str
    confidence: float | None = None
    verification: dict[str, Any] | None = None
    # Tier 1: the findings of the standard run; tier 2: further findings of a deeper run (a preview).
    tier: int = 1
    # verified, unverified (with a short reason) or none (the route does not verify this source).
    verification_status: str = NOT_VERIFIED
    verification_reason: str | None = None

    @property
    def id(self) -> str:
        return f"ST-{self.rank:03d}"

    @property
    def location(self) -> OutputLocation | None:
        return self.locations[0] if self.locations else None

    @property
    def explanation(self) -> str:
        text = self.evidence.strip()
        if self.exploit_conditions.strip():
            text = f"{text}\n\nExploit conditions: {self.exploit_conditions.strip()}".strip()
        return text

    def fingerprint(self) -> str:
        """A stable identity of the finding across runs: the file, the first CWE and the title words."""
        first = self.location
        words = _SPACES.sub(" ", self.title.lower()).strip()
        material = "|".join([first.path if first else "", self.cwe[0] if self.cwe else "", words])
        return "sha256:" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]

    def record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rank": self.rank,
            "title": self.title,
            "severity": self.severity,
            "cwe": list(self.cwe),
            "location": self.location.record() if self.location else None,
            "related_locations": [location.record() for location in self.locations[1:]],
            "explanation": self.explanation,
            "evidence": self.evidence,
            "exploit_conditions": self.exploit_conditions,
            "engine": self.engine,
            "route": self.route,
            "confidence": self.confidence,
            "verification": {
                **(self.verification or {"verdict": None, "keep_score": None}),
                "status": self.verification_status,
                "reason": self.verification_reason,
            },
            "tier": self.tier,
            "fingerprint": self.fingerprint(),
        }

    def verification_label(self) -> str | None:
        """The label of a finding without a verification in the reports, else None."""
        if self.verification_status != UNVERIFIED:
            return None
        return f"unverified: {self.verification_reason}" if self.verification_reason else "unverified"


def clean_text(value: str) -> str:
    """Model text without lone UTF-16 surrogates (a pair becomes its character, a lone half becomes U+FFFD).

    JSON allows an escape of half of a surrogate pair, and a truncation can
    leave one; it has no UTF-8 form, so the output files could not hold it.
    """
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def from_agent(finding: AgentFinding, *, rank: int, route: str, engine: str) -> OutputFinding:
    """An output finding from a finding of an agent answer (single agent or free-roaming session)."""
    locations = [
        OutputLocation(
            clean_text(location.path), location.line_start, location.line_end, clean_text(location.note) if location.note else None
        )
        for location in finding.locations
        if 1 <= location.line_start <= location.line_end <= MAX_LINE
    ][:MAX_LOCATIONS]
    return OutputFinding(
        rank=rank,
        title=clean_text(finding.title[:300]),
        severity=finding.severity,
        cwe=list(finding.cwe),
        locations=locations,
        evidence=clean_text(finding.evidence),
        exploit_conditions=clean_text(finding.exploit_conditions),
        engine=engine,
        route=route,
    )


def from_funnel_item(item: dict[str, Any], *, rank: int, route: str, roots: tuple[str, ...] = ()) -> OutputFinding:
    """An output finding from a deep-check finding of the funnel output: its locations in order, the first primary."""
    record: dict[str, Any] = found if isinstance(found := item.get("funnel"), dict) else {}
    locations: list[OutputLocation] = []
    for entry in entries if isinstance(entries := item.get("locations"), list) else []:
        if len(locations) >= MAX_LOCATIONS:
            break
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        start, end = entry.get("line_start"), entry.get("line_end")
        if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool) or isinstance(end, bool):
            continue
        if not (1 <= start <= MAX_LINE and 1 <= end <= MAX_LINE):
            continue
        path = clean_text(relative_path(entry["path"], None, roots))
        locations.append(OutputLocation(path, min(start, end), max(start, end)))
    score = record.get("keep_score")
    confidence = float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 1 else None
    verdict = record.get("verify")
    status = record.get("verification")
    if status not in (VERIFIED, UNVERIFIED, NOT_VERIFIED):
        status = VERIFIED if verdict is not None or confidence is not None else UNVERIFIED
    reason = record.get("verification_reason")
    return OutputFinding(
        rank=rank,
        title=clean_text(str(item.get("title") or "Finding")[:300]),
        severity=normalize_severity(item.get("severity")),
        cwe=cwe_labels(item.get("cwe")),
        locations=locations,
        evidence=clean_text(text) if isinstance(text := item.get("evidence"), str) else "",
        exploit_conditions=clean_text(more) if isinstance(more := item.get("exploit_conditions"), str) else "",
        engine=ENGINE_DEEP,
        route=route,
        confidence=confidence,
        verification={"verdict": verdict, "keep_score": confidence} if verdict is not None or confidence is not None else None,
        verification_status=status,
        verification_reason=str(reason) if status == UNVERIFIED and isinstance(reason, str) and reason else None,
    )


def severity_counts(findings: Iterable[OutputFinding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {name: counts.get(name, 0) for name in SEVERITIES}


def findings_document(findings: list[OutputFinding], run: dict[str, Any]) -> dict[str, Any]:
    """The ``findings.json`` document; its run part holds the result of the run (``result.py``)."""
    part: dict[str, Any] = {
        "id": run.get("run_id"),
        "route": run.get("route"),
        "started_at": run.get("started_at"),
        "repository": run.get("repository", {}).get("name"),
        "files_counted": run.get("repository", {}).get("files_counted"),
    }
    if isinstance(run.get("result"), dict):
        part["result"] = run["result"]
    return {
        "$schema": SCHEMA_URL,
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "SentryTower", "version": __version__},
        "run": part,
        "summary": {"findings": len(findings), "by_severity": severity_counts(findings)},
        "findings": [finding.record() for finding in findings],
    }


def at_or_above(findings: Iterable[OutputFinding], threshold: str) -> list[OutputFinding]:
    """The findings with a severity at or above ``threshold`` (critical, high, medium or low).

    A finding without a known severity counts as medium.
    """
    limit = SEVERITY_ORDER[threshold]
    return [finding for finding in findings if SEVERITY_ORDER["medium" if finding.severity == "unknown" else finding.severity] <= limit]
