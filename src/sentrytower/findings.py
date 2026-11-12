"""The findings of a run in the public output format (``findings.json``, schema version 2.0.0).

Each finding of ``findings.json`` is a ``Finding`` of the National Compute
data contracts, version 1 (``contracts/schemas/finding/1.json``), the
format of the hosted product; ``schemas/findings-v2.schema.json`` is the
JSON Schema of the document, and docs/output-format.md gives each field.
``OutputFinding.record`` writes a finding with the mappings of the
contracts (``contracts/nc_contracts``), and ``from_contract`` reads one back:

- ``severity``: one of the five levels of the CLI (``critical``, ``high``,
  ``medium``, ``low``, ``unknown``); the contract's ``info`` never occurs;
- ``evidence``: the class and the blind verification. The verification
  never executes a claim, so the class is ``defective`` when a verified
  majority called the finding exploitable and ``suspected`` otherwise;
  ``verification.status`` is ``verified``, ``unverified`` (with
  ``reason``: the verification failed, was refused or did not run) or
  ``none`` (the route does not verify the source of the finding), with
  the outcome and the score of the votes when they exist;
- ``engine``: SentryTower, its version and the engine that found the
  finding (``mode``);
- ``fingerprint``: ``sentrytowerFindingHash/v1``, a stable identity across
  runs;
- ``properties``: the rank, the route, the tier and the votes of a slice.

Engines (``engine.mode``):

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
from typing import Any, Iterable, Mapping

from . import __version__
from .agent.answer import AgentFinding, cwe_labels, normalize_severity, relative_path
from .contracts.nc_contracts import (
    evidence_from_cli,
    outcome_to_cli_verdict,
    severity_from_cli,
    severity_rank,
    severity_to_cli,
    status_from_cli,
    status_to_cli,
)
from .contracts.nc_contracts.types import Evidence, Finding, Location, Target

SCHEMA_VERSION = "2.0.0"
SCHEMA_URL = "https://raw.githubusercontent.com/National-Compute/sentrytower/main/src/sentrytower/schemas/findings-v2.schema.json"
TOOL_NAME = "SentryTower"
FINGERPRINT_SCHEME = "sentrytowerFindingHash/v1"
# The severities that the CLI gives, from the worst: the contract's scale without ``info``.
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

    def record(self) -> Location:
        """The location as a contract Location."""
        item: Location = {"path": self.path, "startLine": self.start_line, "endLine": self.end_line}
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
        """A stable identity of the finding across runs: 32 hex digits of SHA-256 over the file, the first CWE and the title words."""
        first = self.location
        words = _SPACES.sub(" ", self.title.lower()).strip()
        material = "|".join([first.path if first else "", self.cwe[0] if self.cwe else "", words])
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]

    def evidence_record(self) -> Evidence:
        """The evidence of the finding: the contract's mapping of the verification of the CLI."""
        given = self.verification or {}
        return evidence_from_cli(
            {
                "verdict": given.get("verdict"),
                "keep_score": self.confidence if self.confidence is not None else given.get("keep_score"),
                "status": self.verification_status,
                "reason": self.verification_reason,
            }
        )

    def record(self, target: Target | None = None) -> Finding:
        """The finding as a contract Finding (version 1); ``target`` is the audited repository."""
        # The fields come in the order of the schema, so the required ones after the description follow below.
        finding: Finding = {  # type: ignore[typeddict-item]
            "id": self.id,
            "fingerprint": {"scheme": FINGERPRINT_SCHEME, "value": self.fingerprint()},
            "kind": "code",
            "title": self.title,
        }
        if self.explanation:
            finding["description"] = self.explanation
        finding["severity"] = severity_from_cli(self.severity)
        finding["evidence"] = self.evidence_record()
        finding["engine"] = {"name": TOOL_NAME, "version": __version__, "mode": self.engine}
        if self.cwe:
            finding["ruleId"] = self.cwe[0]
        if target is not None:
            finding["target"] = target
        if self.location is not None:
            finding["location"] = self.location.record()
        if len(self.locations) > 1:
            finding["relatedLocations"] = [location.record() for location in self.locations[1:]]
        finding["cwe"] = list(self.cwe)
        properties: dict[str, Any] = {"rank": self.rank, "route": self.route, "tier": self.tier}
        votes = (self.verification or {}).get("votes")
        if isinstance(votes, list):
            properties["votes"] = votes
        finding["properties"] = properties
        return finding

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


def from_contract(item: Mapping[str, Any], *, position: int = 1) -> OutputFinding:
    """An output finding from a contract Finding of ``findings.json`` (for ``sentrytower last``).

    The inverse of ``OutputFinding.record``: the description becomes the
    evidence text. A field of the wrong type takes its default, so a file
    that another program changed cannot stop the command.
    """
    properties = _mapping(item.get("properties"))
    verification = _mapping(_mapping(item.get("evidence")).get("verification"))
    status = status_to_cli(status_from_cli(verification.get("status"))) if verification else NOT_VERIFIED
    outcome = verification.get("outcome")
    verdict = outcome_to_cli_verdict(outcome) if outcome in ("supports", "refutes", "inconclusive") else None
    score = _score(verification.get("score"))
    reason = verification.get("reason")
    votes = properties.get("votes")
    record: dict[str, Any] | None = None
    if verdict is not None or score is not None or isinstance(votes, list):
        record = {"verdict": verdict, "keep_score": score} | ({"votes": votes} if isinstance(votes, list) else {})
    first = _location_from(item.get("location"))
    related = [found for value in _list(item.get("relatedLocations")) if (found := _location_from(value))]
    rank = properties.get("rank")
    return OutputFinding(
        rank=rank if isinstance(rank, int) and not isinstance(rank, bool) and rank >= 1 else position,
        title=_text(item.get("title")),
        severity=severity_to_cli(item.get("severity", "unknown")),
        cwe=[value for value in _list(item.get("cwe")) if isinstance(value, str)],
        locations=([first] if first else []) + related,
        evidence=_text(item.get("description")),
        exploit_conditions="",
        engine=_text(_mapping(item.get("engine")).get("mode")),
        route=_text(properties.get("route")),
        confidence=score,
        verification=record,
        tier=2 if properties.get("tier") == 2 else 1,
        verification_status=status,
        verification_reason=reason if status == UNVERIFIED and isinstance(reason, str) and reason else None,
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _score(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1 else None


def _line(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_LINE else None


def _location_from(value: Any) -> OutputLocation | None:
    location = _mapping(value)
    path = location.get("path")
    if not isinstance(path, str) or not path:
        return None
    start = _line(location.get("startLine")) or 1
    end = _line(location.get("endLine")) or start
    note = location.get("note")
    return OutputLocation(path, start, max(start, end), note if isinstance(note, str) and note else None)


def severity_counts(findings: Iterable[OutputFinding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {name: counts.get(name, 0) for name in SEVERITIES}


def findings_document(findings: list[OutputFinding], run: dict[str, Any]) -> dict[str, Any]:
    """The ``findings.json`` document: the run (with its result, ``result.py``), the summary and each contract Finding."""
    repository = run.get("repository") or {}
    part: dict[str, Any] = {
        "id": run.get("run_id"),
        "route": run.get("route"),
        "started_at": run.get("started_at"),
        "repository": repository.get("name"),
        "files_counted": repository.get("files_counted"),
    }
    if isinstance(run.get("result"), dict):
        part["result"] = run["result"]
    return {
        "$schema": SCHEMA_URL,
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "run": part,
        "summary": {"findings": len(findings), "by_severity": severity_counts(findings)},
        "findings": [finding.record(repository_target(run)) for finding in findings],
    }


def repository_target(run: Mapping[str, Any]) -> Target | None:
    """The contract Target of the audited repository: its folder name; None when the run has no name."""
    name = _mapping(run.get("repository")).get("name")
    return {"kind": "repository", "locator": name} if isinstance(name, str) and name else None


def at_or_above(findings: Iterable[OutputFinding], threshold: str) -> list[OutputFinding]:
    """The findings with a severity at or above ``threshold`` (critical, high, medium or low).

    The order is the contract's severity rank. A finding without a known
    severity counts as medium.
    """
    limit = severity_rank(severity_from_cli(threshold))
    return [
        finding
        for finding in findings
        if severity_rank("medium" if (level := severity_from_cli(finding.severity)) == "unknown" else level) <= limit
    ]
