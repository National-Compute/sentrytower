# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CycloneDX 1.6 VEX analysis <-> the decision of an Exposure.

Both directions are total and never raise. A value that CycloneDX 1.6 does
not define maps to ``unknown`` on the way in; ``unknown`` has no CycloneDX
form, so the way out writes the state as ``in_triage`` and leaves an unknown
justification or response out.
"""

from __future__ import annotations

from typing import Any

from .types import ExposureDecision

VEX_STATES = ("resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected")
VEX_JUSTIFICATIONS = (
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
)
VEX_RESPONSES = ("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available")


def _known(values: tuple[str, ...], value: Any) -> str:
    return value if isinstance(value, str) and value in values else "unknown"


def decision_from_vex(analysis: Any) -> ExposureDecision:
    """The decision of an exposure from a CycloneDX ``analysis`` object. An absent or
    unrecognized state is ``unknown``; an unrecognized justification or response is
    ``unknown``; an absent justification or response stays absent."""
    source = analysis if isinstance(analysis, dict) else {}
    decision: ExposureDecision = {"state": _known(VEX_STATES, source.get("state"))}  # type: ignore[typeddict-item]
    if "justification" in source:
        decision["justification"] = _known(VEX_JUSTIFICATIONS, source["justification"])  # type: ignore[typeddict-item]
    if isinstance(source.get("response"), list):
        decision["response"] = [_known(VEX_RESPONSES, r) for r in source["response"]]  # type: ignore[typeddict-item]
    for key in ("detail", "firstIssued", "lastUpdated"):
        if isinstance(source.get(key), str):
            decision[key] = source[key]  # type: ignore[literal-required]
    return decision


def decision_to_vex(decision: ExposureDecision) -> dict[str, Any]:
    """The CycloneDX analysis of a decision. ``unknown`` state is ``in_triage``; an
    ``unknown`` justification or response is left out. ``decidedBy`` and ``until`` have
    no CycloneDX field and do not appear."""
    state = decision.get("state")
    analysis: dict[str, Any] = {"state": state if state in VEX_STATES else "in_triage"}
    justification = decision.get("justification")
    if justification and justification != "unknown":
        analysis["justification"] = justification
    response = [r for r in decision.get("response") or [] if r != "unknown"]
    if response:
        analysis["response"] = response
    for key in ("detail", "firstIssued", "lastUpdated"):
        if decision.get(key) is not None:
            analysis[key] = decision[key]  # type: ignore[literal-required]
    return analysis
