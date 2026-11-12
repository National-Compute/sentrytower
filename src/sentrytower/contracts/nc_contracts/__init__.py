# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The National Compute data contracts for Python.

``nc_contracts.types`` holds a TypedDict or alias for each entity of the JSON
Schemas; the other modules map the stored and standard forms to and from the
contract: ``severity``, ``evidence``, ``sarif`` (SARIF 2.1.0) and ``vex``
(CycloneDX 1.6 VEX analysis). Standard library only; Python 3.11 or later.
"""

from .evidence import (
    EVIDENCE_CLASSES,
    evidence_class_from,
    evidence_class_rank,
    evidence_from_cli,
    evidence_to_cli,
    outcome_from_cli_verdict,
    outcome_to_cli_verdict,
    status_from_cli,
    status_to_cli,
)
from .sarif import (
    finding_from_sarif_result,
    finding_to_sarif_result,
    findings_from_sarif_log,
    findings_to_sarif_log,
    path_from_uri,
    repository_uri,
)
from .severity import (
    SEVERITIES,
    is_severity,
    severity_from_cli,
    severity_from_cvss_score,
    severity_from_sarif_level,
    severity_from_scanner,
    severity_from_swarm,
    severity_rank,
    severity_to_cli,
    severity_to_sarif_level,
    severity_to_scanner,
    severity_to_security_severity,
    severity_to_swarm,
)
from .types import CONTRACTS_VERSION, ENTITY_TYPES, RUN_EVENT_KINDS, SCHEMA_IDS
from .vex import decision_from_vex, decision_to_vex

__version__ = CONTRACTS_VERSION

__all__ = [
    "CONTRACTS_VERSION",
    "ENTITY_TYPES",
    "EVIDENCE_CLASSES",
    "RUN_EVENT_KINDS",
    "SCHEMA_IDS",
    "SEVERITIES",
    "decision_from_vex",
    "decision_to_vex",
    "evidence_class_from",
    "evidence_class_rank",
    "evidence_from_cli",
    "evidence_to_cli",
    "finding_from_sarif_result",
    "finding_to_sarif_result",
    "findings_from_sarif_log",
    "findings_to_sarif_log",
    "is_severity",
    "outcome_from_cli_verdict",
    "outcome_to_cli_verdict",
    "path_from_uri",
    "repository_uri",
    "severity_from_cli",
    "severity_from_cvss_score",
    "severity_from_sarif_level",
    "severity_from_scanner",
    "severity_from_swarm",
    "severity_rank",
    "severity_to_cli",
    "severity_to_sarif_level",
    "severity_to_scanner",
    "severity_to_security_severity",
    "severity_to_swarm",
    "status_from_cli",
    "status_to_cli",
]
