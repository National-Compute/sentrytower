"""The protocols of the funnel: prompt files, protocol IDs and answer parsers.

Each model task has a role (rating, unit check, triage, verification, deep
check) and each role has one protocol. A protocol is a tuple of prompt files
(in ``sentrytower/prompts``) and an answer parser. The run records the
protocol of each role.

- rating (``funnel-rating-v2``): the model gives a score from 1 to 5 and a
  CWE for each unit card;
- unit check (``funnel-unit-check-plain-v1``): a short system message and
  the plain question "audit this code", with a structured answer (line,
  quoted line, CWE, confidence, reason). No prompt asks the model to
  describe and then decide, frames the code as a violation, or accepts
  "safe" only with a quoted guard: in a controlled study these rules raised
  the flags on fixed code more than on vulnerable code;
- triage (``funnel-triage-verify-v1``): the prompt, the message and the
  parser of the verification, on the unit and the line of a lead; its score
  orders the units for the deep checks;
- verification (``funnel-verify-v2``): the conditions of the claim, the
  checks that the code shows, a verdict and a score; it ranks;
- deep check (``funnel-deep-check-v3``): check the unit and the lines of
  interest of all its leads (one session for each unit); report only an
  issue with a concrete path of attacker data to the operation; the answer
  contract and the findings schema of the single agent.

Standard library only.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Callable

from .model_client import extract_object
from .pacing import Parameters
from .slices import split_lines

FUNNEL_VERSION = "funnel-v1.4"
ROLES = ("rating", "unit_check", "triage", "verify", "deep_check")
RATING_V2 = "funnel-rating-v2"
UNIT_CHECK_PLAIN_V1 = "funnel-unit-check-plain-v1"
VERIFY_V2 = "funnel-verify-v2"
TRIAGE_VERIFY_V1 = "funnel-triage-verify-v1"
DEEP_CHECK_V3 = "funnel-deep-check-v3"
VERIFY_PROMPT = "funnel-verify.txt"
# The unit check: a system file and a template of the user message.
UNIT_CHECK_SYSTEM = "funnel-unit-check-system.txt"
UNIT_CHECK_TEMPLATE = "funnel-unit-check.txt"
# The answer of a deep check: the output contract and the findings schema of
# the single agent, unchanged.
WORKER_CONTRACT = "agent-output.txt"
WORKER_SCHEMA = "agent-findings.schema.json"
CONFIDENCES = ("high", "medium", "low")
VERIFY_VERDICTS = ("exploitable", "safe", "unclear")
SEVERITIES = ("critical", "high", "medium", "low")
REASON_LIMIT = 300
QUOTE_LIMIT = 400
PROMPT_PACKAGE = "sentrytower.prompts"
_CWE = re.compile(r"^\s*(?:cwe)?[\s_-]*0*(\d{1,5})\s*$", re.IGNORECASE)
_NUMBERED_PREFIX = re.compile(r"^\s*\d+\s*[│|]\s?")
_PLACEHOLDER = re.compile(r"\{\{([a-z_]+)\}\}")


class ParseError(ValueError):
    """The answer has no usable object for the protocol."""


@dataclass(frozen=True)
class Protocol:
    """One protocol: its ID, its role, its prompt files (in order) and its parser."""

    id: str
    role: str
    prompts: tuple[str, ...]
    parser: Callable[..., Any]


def normalize_cwe(value: Any) -> str | None:
    """``CWE-<n>`` without leading zeros, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    if isinstance(value, str):
        match = _CWE.match(value.strip())
        if match and int(match.group(1)) > 0:
            return f"CWE-{int(match.group(1))}"
    return None


def clean_quote(value: Any, limit: int = QUOTE_LIMIT) -> str:
    """A quoted line without a line-number prefix, backticks or outer white space."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if text.startswith("`") and text.endswith("`") and len(text) > 1:
        text = text.strip("`").strip()
    lines = [_NUMBERED_PREFIX.sub("", line, count=1) for line in split_lines(text)]
    return "\n".join(lines).strip()[:limit]


def short_text(value: Any, limit: int = REASON_LIMIT) -> str:
    return " ".join(value.split())[:limit] if isinstance(value, str) else ""


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, float) and value.is_integer() and value >= 1:
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isascii() and text.isdigit() and len(text) <= 9 and int(text) >= 1:
            return int(text)
    return None


def _choice(value: Any, choices: tuple[str, ...], synonyms: dict[str, str], default: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    text = synonyms.get(text, text)
    return text if text in choices else default


def parse_ratings(text: str, ids: list[str]) -> dict[str, tuple[int, str | None]]:
    """The score (1 to 5) and the CWE of each card ID in the answer."""
    try:
        document = extract_object(text, "ratings")
    except ValueError as error:
        raise ParseError(str(error)) from error
    items = document.get("ratings")
    if not isinstance(items, list):
        raise ParseError("ratings is not a list")
    wanted = set(ids)
    ratings: dict[str, tuple[int, str | None]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        identifier = item.get("id")
        if not isinstance(identifier, str) or identifier not in wanted or identifier in ratings:
            continue
        score = item.get("score")
        if isinstance(score, str):
            try:
                score = float(score.strip())
            except ValueError:
                continue
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            continue
        ratings[identifier] = (min(5, max(1, round(score))), normalize_cwe(item.get("cwe")))
    return ratings


def parse_unit_findings(text: str) -> dict[str, Any]:
    """The findings of a plain unit check as candidates: line, quoted line, CWE, confidence and reason.

    A finding at the confidence "low" is the verdict "unsure", each other
    finding is "vulnerable". A finding without a known confidence is
    "medium". The answer names no "safe" item: the question asks for
    vulnerabilities only.
    """
    try:
        document = extract_object(text, "findings")
    except ValueError as error:
        raise ParseError(str(error)) from error
    items = document.get("findings")
    if not isinstance(items, list):
        raise ParseError("findings is not a list")
    candidates = []
    for item in items:
        if not isinstance(item, dict):
            continue
        confidence = _choice(item.get("confidence"), CONFIDENCES, {"med": "medium", "moderate": "medium"}, "medium")
        candidates.append(
            {
                "verdict": "unsure" if confidence == "low" else "vulnerable",
                "confidence": confidence,
                "cwe": normalize_cwe(item.get("cwe")),
                "severity": None,
                "sink_line": _positive_int(item.get("line")),
                "sink_quote": clean_quote(item.get("quote")),
                "reason": short_text(item.get("reason")),
            }
        )
    return {"findings": len(candidates), "candidates": candidates}


def parse_verify(text: str) -> dict[str, Any]:
    """The verdict, the keep score (0 to 1) and the quoted checks of a verification answer."""
    try:
        document = extract_object(text, "verdict")
    except ValueError as error:
        raise ParseError(str(error)) from error
    verdict = _choice(
        document.get("verdict"),
        VERIFY_VERDICTS,
        {"vulnerable": "exploitable", "not_vulnerable": "safe", "unsure": "unclear", "uncertain": "unclear"},
        "unclear",
    )
    score = document.get("keep_score")
    if isinstance(score, str):
        try:
            score = float(score.strip().rstrip("%"))
        except ValueError:
            score = None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        score = {"exploitable": 0.75, "safe": 0.25}.get(verdict, 0.5)
    elif score > 1:
        score = score / 100 if score <= 100 else 1.0
    conditions = found if isinstance(found := document.get("conditions"), list) else []
    guards = [clean_quote(item.get("guard_quote")) for item in conditions if isinstance(item, dict)]
    guard = clean_quote(document.get("guard_quote"))
    return {
        "verdict": verdict,
        "keep_score": round(min(1.0, max(0.0, float(score))), 3),
        "guard_quote": guard,
        "guards": [quote for quote in [guard, *guards] if quote],
        "conditions": len(conditions),
        "holding": sum(1 for item in conditions if isinstance(item, dict) and item.get("holds") is True),
    }


def parse_worker_answer(document: dict[str, Any]) -> dict[str, Any]:
    """The findings of a deep-check answer (items of the agent findings schema)."""
    return {"findings": [item for item in document.get("findings") or [] if isinstance(item, dict)]}


PROTOCOLS: dict[str, Protocol] = {
    protocol.id: protocol
    for protocol in (
        Protocol(RATING_V2, "rating", ("funnel-rating.txt",), parse_ratings),
        Protocol(UNIT_CHECK_PLAIN_V1, "unit_check", (UNIT_CHECK_SYSTEM, UNIT_CHECK_TEMPLATE), parse_unit_findings),
        Protocol(VERIFY_V2, "verify", (VERIFY_PROMPT,), parse_verify),
        # The blind verification of phase 4 on a lead: the same prompt, message and parser.
        Protocol(TRIAGE_VERIFY_V1, "triage", (VERIFY_PROMPT,), parse_verify),
        Protocol(DEEP_CHECK_V3, "deep_check", ("funnel-deep-check.txt", WORKER_CONTRACT, WORKER_SCHEMA), parse_worker_answer),
    )
}
DEFAULT_PROTOCOLS = {
    "rating": RATING_V2,
    "unit_check": UNIT_CHECK_PLAIN_V1,
    "triage": TRIAGE_VERIFY_V1,
    "verify": VERIFY_V2,
    "deep_check": DEEP_CHECK_V3,
}


def combine_votes(votes: list[dict[str, Any]]) -> dict[str, Any]:
    """One verdict of several blind verifications: the majority verdict (else "unclear") and the mean score."""
    verdict, count = Counter(str(vote.get("verdict")) for vote in votes).most_common(1)[0]
    scores = [float(vote["keep_score"]) for vote in votes if isinstance(vote.get("keep_score"), (int, float))]
    combined = dict(votes[0])
    combined.update(
        verdict=verdict if 2 * count > len(votes) else "unclear",
        keep_score=round(sum(scores) / len(scores), 4) if scores else combined.get("keep_score"),
        votes=[vote.get("verdict") for vote in votes],
    )
    return combined


def prompt_files(protocols: dict[str, str] | None = None) -> tuple[str, ...]:
    """The prompt files of the selected protocols, without repeats, in role order."""
    selected = protocols or DEFAULT_PROTOCOLS
    names: list[str] = []
    for role in ROLES:
        for name in PROTOCOLS[selected[role]].prompts:
            if name not in names:
                names.append(name)
    return tuple(names)


def read_prompt(name: str) -> str:
    """A prompt file of the package, as read (with its last newline)."""
    return resources.files(PROMPT_PACKAGE).joinpath(name).read_text(encoding="utf-8")


def render(template: str, values: dict[str, str]) -> str:
    """Fill each ``{{name}}`` of the template; an unknown name is an error."""

    def value(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise KeyError(f"the template needs {name}")
        return values[name]

    return _PLACEHOLDER.sub(value, template)


@dataclass(frozen=True)
class Setup:
    """The setup of a run: the protocol of each role, the prompt texts and the parameters."""

    version: str
    protocols: dict[str, str]
    prompts: dict[str, str]
    parameters: Parameters
    free_session_protocol: str | None = None
    texts: dict[str, str] = field(default_factory=dict)

    def protocol(self, role: str) -> Protocol:
        return PROTOCOLS[self.protocols[role]]

    def prompt(self, role: str, index: int = 0) -> str:
        """The text of a prompt file of the protocol of ``role`` (the first one by default), stripped."""
        return self.prompts[self.protocol(role).prompts[index]]

    def record(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "protocols": dict(self.protocols),
            "free_session_protocol": self.free_session_protocol,
        }


def load_setup(parameters: Parameters, free_session_protocol: str | None = None) -> Setup:
    """The setup of a run: the default protocols and the prompt files of the package."""
    protocols = dict(DEFAULT_PROTOCOLS)
    texts = {name: read_prompt(name) for name in prompt_files(protocols)}
    prompts = {name: text.strip() for name, text in texts.items()}
    return Setup(FUNNEL_VERSION, protocols, prompts, parameters, free_session_protocol, texts)
