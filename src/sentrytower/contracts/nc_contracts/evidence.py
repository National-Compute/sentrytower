# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Evidence mappings.

Each function is total and never raises. An input that a function does not
recognize maps to ``unknown`` where the target has that value, and to the
documented fallback where it has not.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from .types import Evidence, EvidenceClass, Verification, VerificationOutcome, VerificationStatus

#: The evidence ladder, from the strongest.
EVIDENCE_CLASSES: tuple[EvidenceClass, ...] = ("reproduced", "reachable", "defective", "suspected")
#: The method name of the CLI's blind verification.
BLIND_VOTE = "blind-vote"

CliVerdict = Literal["exploitable", "safe", "unclear"]
CliVerificationStatus = Literal["verified", "unverified", "none"]


class CliVerificationRecord(TypedDict):
    """The ``verification`` object that the CLI writes in findings.json."""

    verdict: CliVerdict | None
    keep_score: float | None
    status: CliVerificationStatus
    reason: str | None


def evidence_class_rank(evidence_class: EvidenceClass) -> int:
    """0 for ``reproduced`` to 3 for ``suspected``."""
    return EVIDENCE_CLASSES.index(evidence_class) if evidence_class in EVIDENCE_CLASSES else len(EVIDENCE_CLASSES) - 1


def evidence_class_from(value: Any) -> EvidenceClass:
    """A stored evidence class. A value that is not on the ladder is ``suspected``,
    the class that claims nothing beyond a statement."""
    text = value.strip().lower() if isinstance(value, str) else ""
    return text if text in EVIDENCE_CLASSES else "suspected"  # type: ignore[return-value]


def outcome_from_cli_verdict(value: Any) -> VerificationOutcome | None:
    """``exploitable`` supports, ``safe`` refutes, ``unclear`` is inconclusive; None is no
    outcome; any other value is ``unknown``."""
    if value is None:
        return None
    return {"exploitable": "supports", "safe": "refutes", "unclear": "inconclusive"}.get(
        value if isinstance(value, str) else "", "unknown"
    )  # type: ignore[return-value]


def outcome_to_cli_verdict(outcome: VerificationOutcome | None) -> CliVerdict | None:
    """The inverse of outcome_from_cli_verdict; ``unknown`` and no outcome are None."""
    return {"supports": "exploitable", "refutes": "safe", "inconclusive": "unclear"}.get(outcome or "")  # type: ignore[return-value]


def status_from_cli(value: Any) -> VerificationStatus:
    """The CLI's three states map to themselves; any other value is ``unknown``."""
    return value if value in ("verified", "unverified", "none") else "unknown"


def status_to_cli(status: VerificationStatus) -> CliVerificationStatus:
    """``unknown`` is ``unverified``, the state of a verification that gave no usable result."""
    return status if status in ("verified", "none") else "unverified"  # type: ignore[return-value]


def evidence_from_cli(record: Any) -> Evidence:
    """The evidence of a CLI finding, from its ``verification`` object. The blind
    verification never executes the claim, so the class is ``defective`` when a verified
    majority called the finding exploitable, and ``suspected`` in every other case. A
    missing object is status ``none``. A score outside 0 to 1 is left out."""
    if not isinstance(record, dict):
        return {"class": "suspected", "verification": {"status": "none"}}
    status = status_from_cli(record.get("status"))
    outcome = outcome_from_cli_verdict(record.get("verdict"))
    score = record.get("keep_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
        score = None
    verification: Verification = {"status": status}
    if outcome is not None or score is not None:
        verification["method"] = BLIND_VOTE
    if outcome is not None:
        verification["outcome"] = outcome
    if score is not None:
        verification["score"] = score
    reason = record.get("reason")
    if isinstance(reason, str) and reason:
        verification["reason"] = reason
    return {
        "class": "defective" if status == "verified" and outcome == "supports" else "suspected",
        "verification": verification,
    }


def evidence_to_cli(evidence: Evidence) -> CliVerificationRecord:
    """The CLI's ``verification`` object for evidence. Evidence with no verification is
    status ``none``. The class does not appear: the CLI has no field for it."""
    verification = evidence.get("verification")
    if verification is None:
        return {"verdict": None, "keep_score": None, "status": "none", "reason": None}
    return {
        "verdict": outcome_to_cli_verdict(verification.get("outcome")),
        "keep_score": verification.get("score"),
        "status": status_to_cli(verification["status"]),
        "reason": verification.get("reason"),
    }
