# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Severity mappings.

Each function is total: an input that it does not recognize maps to
``unknown`` (or, for a target with no ``unknown``, to the documented
fallback), and no function raises.
"""

from __future__ import annotations

import math
import re
from typing import Any, Literal

from .types import Severity

#: The contract severities, from the worst.
SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info", "unknown")

SwarmSeverity = Literal["critical", "high", "medium", "low"]
CliSeverity = Literal["critical", "high", "medium", "low", "unknown"]
SarifLevel = Literal["error", "warning", "note", "none"]

_DECIMAL = re.compile(r"-?[0-9]+(\.[0-9]+)?")
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0", "unknown": "5.5"}


def is_severity(value: Any) -> bool:
    return isinstance(value, str) and value in SEVERITIES


def severity_rank(severity: Severity) -> int:
    """0 for ``critical`` to 5 for ``unknown``."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES) - 1


def _name(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def severity_from_swarm(value: Any) -> Severity:
    """The swarm's four levels map to themselves (case and space ignored); anything else is ``unknown``."""
    text = _name(value)
    return text if text in ("critical", "high", "medium", "low") else "unknown"  # type: ignore[return-value]


def severity_to_swarm(severity: Severity) -> SwarmSeverity:
    """To the swarm's four levels: ``info`` is ``low``. ``unknown`` is ``medium``, the rule
    that the ``finding`` table (its default) and the CLI's severity threshold already apply."""
    if severity in ("critical", "high", "medium", "low"):
        return severity  # type: ignore[return-value]
    return "low" if severity == "info" else "medium"


def severity_from_scanner(value: Any) -> Severity:
    """A scanner's severity name: case and space ignored; ``moderate`` is ``medium``;
    ``informational`` and ``negligible`` are ``info``; any other name is ``unknown``."""
    text = _name(value)
    if text in SEVERITIES:
        return text  # type: ignore[return-value]
    if text == "moderate":
        return "medium"
    if text in ("informational", "negligible"):
        return "info"
    return "unknown"


def severity_to_scanner(severity: Severity) -> Severity:
    """The scanner's six levels are the contract's six levels."""
    return severity if is_severity(severity) else "unknown"


def severity_from_cli(value: Any) -> Severity:
    """The CLI's five levels map to themselves (case and space ignored); anything else is ``unknown``."""
    text = _name(value)
    return text if text in ("critical", "high", "medium", "low") else "unknown"  # type: ignore[return-value]


def severity_to_cli(severity: Severity) -> CliSeverity:
    """To the CLI's five levels: ``info`` is ``low``, the nearest level that the CLI has."""
    if severity == "info":
        return "low"
    return severity if is_severity(severity) else "unknown"  # type: ignore[return-value]


def severity_from_cvss_score(value: Any) -> Severity:
    """A CVSS base score (a number, or a decimal string) by the CVSS bands: 9.0 to 10.0
    ``critical``, 7.0 to 8.9 ``high``, 4.0 to 6.9 ``medium``, 0.1 to 3.9 ``low``, 0.0
    ``info``. A value outside 0 to 10, or not a number, is ``unknown``."""
    if isinstance(value, bool):
        return "unknown"
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str) and _DECIMAL.fullmatch(value.strip()):
        score = float(value.strip())
    else:
        return "unknown"
    if not math.isfinite(score) or score < 0 or score > 10:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "info"


def severity_to_security_severity(severity: Severity) -> str:
    """The SARIF ``security-severity`` that GitHub reads as a CVSS-like score; the public
    CLI's values. ``unknown`` shows as medium; ``info`` is 0.0, below every band."""
    return _SECURITY_SEVERITY.get(severity, _SECURITY_SEVERITY["unknown"])


def severity_to_sarif_level(severity: Severity) -> SarifLevel:
    """``error`` for critical and high, ``warning`` for medium and unknown, ``note`` for low and info."""
    if severity in ("critical", "high"):
        return "error"
    if severity in ("low", "info"):
        return "note"
    return "warning"


def severity_from_sarif_level(value: Any) -> Severity:
    """``error`` is ``high``, ``warning`` ``medium``, ``note`` ``low``, ``none`` ``info``;
    anything else is ``unknown``. The SARIF mapping reads ``security-severity`` first."""
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(
        value if isinstance(value, str) else "", "unknown"
    )  # type: ignore[return-value]
