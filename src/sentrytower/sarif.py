"""The findings of a run as SARIF 2.1.0 (``findings.sarif``), ready for GitHub code scanning.

Each result is the SARIF mapping of the data contracts
(``contracts/nc_contracts/sarif.py``) applied to the contract Finding of
the finding in ``findings.json``, so a reader of the contracts gets each
finding back from its result:

- the rule (the first CWE; ``SENTRYTOWER-UNCLASSIFIED`` for a finding
  without a CWE), the level (``error`` for critical and high, ``warning``
  for medium and unknown, ``note`` for low), the title and the
  explanation as the message, the primary location and the related
  locations with their notes, and the partial fingerprint
  ``sentrytowerFindingHash/v1``;
- the properties ``id``, ``severity``, ``security-severity``, ``cwe``,
  ``engine``, ``verification`` (``verified``, ``unverified`` with
  ``verificationReason``, or ``none``), ``confidence`` when the finding has
  a verification score, ``rank``, ``route`` and ``tier``, and
  ``nationalcompute/finding``: the fields of the Finding that SARIF has no
  place for (the kind, the title, the engine, the rule, the evidence, the
  target).

This module adds what code scanning needs beyond the mapping:

- one rule for each CWE of the findings, with a name, a help link, the
  tags ``security`` and ``external/cwe/cwe-<n>`` and a ``security-severity``
  (the highest severity of its findings in the run), which GitHub shows as
  the severity of an alert;
- a path relative to the repository root (``%SRCROOT%``), with an optional
  folder in front (``path_prefix``) for the audit of a subfolder, because
  code scanning reads each path from the root of the repository. A finding
  without a location in the repository is counted in the run properties,
  not reported: SARIF consumers need a location;
- ``automationDetails.id`` is ``<category>/``: one code-scanning category
  for each audit, so that two audits of one repository keep their alerts.
"""

from __future__ import annotations

import posixpath
from dataclasses import replace
from typing import Any

from . import __version__
from .config import PROJECT_URL
from .contracts.nc_contracts import finding_to_sarif_result, severity_from_cli, severity_to_security_severity
from .contracts.nc_contracts.sarif import SARIF_SCHEMA, SARIF_VERSION, UNCLASSIFIED_RULE
from .contracts.nc_contracts.types import Finding, Target
from .findings import OutputFinding, repository_target

DEFAULT_CATEGORY = "sentrytower"
UNCLASSIFIED = UNCLASSIFIED_RULE

# The names of common weaknesses (MITRE CWE). A CWE that the table does not
# name gets its identifier as its name.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-23": "Relative Path Traversal",
    "CWE-59": "Link Following",
    "CWE-73": "External Control of File Name or Path",
    "CWE-74": "Injection",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-117": "Log Injection",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Information Exposure Through an Error Message",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-367": "Time-of-check Time-of-use Race Condition",
    "CWE-377": "Insecure Temporary File",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-489": "Active Debug Code",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity Reference",
    "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-643": "XPath Injection",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-835": "Infinite Loop",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
    "CWE-1004": "Sensitive Cookie Without HttpOnly Flag",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Inefficient Regular Expression Complexity",
    "CWE-1336": "Server-Side Template Injection",
}


def rule_id(finding: OutputFinding) -> str:
    return finding.cwe[0] if finding.cwe else UNCLASSIFIED


def normalize_prefix(prefix: str) -> str:
    """A folder of the repository for the front of each path: ``sub/dir/``, or an empty string."""
    text = prefix.strip().replace("\\", "/")
    folder = posixpath.normpath(text) if text else "."
    if folder == ".":
        return ""
    if folder.startswith(("/", "../")) or folder == "..":
        raise ValueError("the SARIF path prefix must be a folder in the repository (a relative path)")
    return folder + "/"


def repository_path(path: str, prefix: str = "") -> str | None:
    """The path from the repository root (``prefix`` in front), or None for a path outside the repository.

    The SARIF mapping percent-encodes it as the URI of the location.
    """
    text = path.strip().replace("\\", "/")
    if not text or text.startswith("/") or "\0" in text:
        return None
    normalized = posixpath.normpath(text)
    if normalized in (".", "..") or normalized.startswith("../"):
        return None
    return prefix + normalized


def _security_severity(finding: OutputFinding) -> float:
    return float(severity_to_security_severity(severity_from_cli(finding.severity)))


def _rule(identifier: str, findings: list[OutputFinding]) -> dict[str, Any]:
    worst = max((_security_severity(finding) for finding in findings), default=5.5)
    level = "error" if worst >= 7.0 else ("warning" if worst >= 4.0 else "note")
    if identifier == UNCLASSIFIED:
        name, tags = "Unclassified vulnerability", ["security"]
        help_uri = f"{PROJECT_URL}/blob/main/docs/output-format.md"
    else:
        number = identifier.split("-", 1)[1]
        name = CWE_NAMES.get(identifier, identifier)
        tags = ["security", f"external/cwe/cwe-{number}"]
        help_uri = f"https://cwe.mitre.org/data/definitions/{number}.html"
    return {
        "id": identifier,
        "name": "".join(part.capitalize() for part in name.replace("-", " ").split()) or identifier,
        "shortDescription": {"text": name},
        "fullDescription": {"text": f"{name} ({identifier})" if identifier != UNCLASSIFIED else name},
        "helpUri": help_uri,
        "help": {"text": f"{name}. See {help_uri}."},
        "defaultConfiguration": {"level": level},
        "properties": {
            "tags": tags,
            "security-severity": f"{worst:.1f}",
            "precision": "medium",
            "problem.severity": "error" if worst >= 7.0 else "warning",
        },
    }


def _located(finding: OutputFinding, prefix: str, target: Target | None) -> Finding | None:
    """The contract Finding of ``finding`` with its paths from the repository root; None without a location in it."""
    first = finding.location
    path = repository_path(first.path, prefix) if first else None
    if first is None or path is None:
        return None
    record = finding.record(target)
    record["location"] = replace(first, path=path).record()
    related = [
        replace(location, path=found).record() for location in finding.locations[1:] if (found := repository_path(location.path, prefix))
    ]
    if related:
        record["relatedLocations"] = related
    else:
        record.pop("relatedLocations", None)
    return record


def sarif_document(
    findings: list[OutputFinding], run: dict[str, Any], *, category: str = DEFAULT_CATEGORY, path_prefix: str = ""
) -> dict[str, Any]:
    """The SARIF 2.1.0 log of a run.

    ``category`` is the code-scanning category; ``path_prefix`` is the folder
    of the audited folder in the repository (empty for the repository root).
    """
    prefix = normalize_prefix(path_prefix)
    automation = (category.strip().strip("/") or DEFAULT_CATEGORY) + "/"
    target = repository_target(run)
    located = [(finding, record) for finding in findings if (record := _located(finding, prefix, target)) is not None]
    rule_ids = list(dict.fromkeys(rule_id(finding) for finding, _ in located))
    rules = [_rule(identifier, [finding for finding, _ in located if rule_id(finding) == identifier]) for identifier in rule_ids]
    index = {identifier: position for position, identifier in enumerate(rule_ids)}
    results = []
    for _, record in located:
        mapped = finding_to_sarif_result(record)
        results.append(
            {"ruleId": mapped["ruleId"], "ruleIndex": index[mapped["ruleId"]]} | {k: v for k, v in mapped.items() if k != "ruleId"}
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentryTower",
                        "semanticVersion": __version__,
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": rules,
                    }
                },
                # One category for each audit: a repository that crosses the size threshold keeps its alerts.
                "automationDetails": {"id": automation},
                "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The root of the audited repository."}}},
                "results": results,
                "properties": {
                    "route": run.get("route"),
                    "filesCounted": (run.get("repository") or {}).get("files_counted"),
                    "findingsWithoutLocation": len(findings) - len(located),
                    "models": (run.get("models") or {}),
                },
            }
        ],
    }
