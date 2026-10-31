"""The findings of a run as SARIF 2.1.0 (``findings.sarif``), ready for GitHub code scanning.

- One run, with the tool ``SentryTower`` and one rule for each CWE of the
  findings (``CWE-<n>``; ``SENTRYTOWER-UNCLASSIFIED`` for a finding without
  a CWE). A rule has the tags ``security`` and ``external/cwe/cwe-<n>`` and a
  ``security-severity`` (the highest severity of its findings in the run),
  which GitHub shows as the severity of an alert.
- One result for each finding with a location: the level (``error`` for
  critical and high, ``warning`` for medium, ``note`` for low), the title
  and the explanation as the message, the primary location relative to the
  repository root (``%SRCROOT%``), the related locations, a partial
  fingerprint, and the rank, the severity, the engine, the route, the tier
  and the verification (``verified``, ``unverified`` with
  ``verificationReason``, or ``none``) as properties. A finding without a location in the repository is counted
  in the run properties; SARIF consumers need a location.
- A path is a relative URI: percent-encoded, with an optional folder in
  front (``path_prefix``) for the audit of a subfolder, because code
  scanning reads each path from the root of the repository.
- ``automationDetails.id`` is ``<category>/``: one code-scanning category
  for each audit, so that two audits of one repository keep their alerts.
"""

from __future__ import annotations

import posixpath
import urllib.parse
from typing import Any

from . import __version__
from .config import PROJECT_URL
from .findings import OutputFinding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
DEFAULT_CATEGORY = "sentrytower"
# The characters of a path that stay as they are in a URI; the rest is percent-encoded.
_URI_SAFE = "/!$&'()*+,;=@"
UNCLASSIFIED = "SENTRYTOWER-UNCLASSIFIED"
# GitHub reads security-severity as a CVSS-like number: 9.0 and more is critical,
# 7.0 to 8.9 high, 4.0 to 6.9 medium, 0.1 to 3.9 low.
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "unknown": 5.5}
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "warning"}
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


def repository_uri(path: str, prefix: str = "") -> str | None:
    """The relative URI of a repository path, or None for a path outside the repository."""
    text = path.strip().replace("\\", "/")
    if not text or text.startswith("/") or "\0" in text:
        return None
    normalized = posixpath.normpath(text)
    if normalized in (".", "..") or normalized.startswith("../"):
        return None
    return urllib.parse.quote(prefix + normalized, safe=_URI_SAFE)


def _location(path: str, start: int, end: int, *, message: str | None = None, identifier: int | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start, "endLine": max(start, end)},
        }
    }
    if identifier is not None:
        location["id"] = identifier
    if message:
        location["message"] = {"text": message}
    return location


def _rule(identifier: str, findings: list[OutputFinding]) -> dict[str, Any]:
    worst = max((SECURITY_SEVERITY.get(finding.severity, 5.5) for finding in findings), default=5.5)
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


def sarif_document(
    findings: list[OutputFinding], run: dict[str, Any], *, category: str = DEFAULT_CATEGORY, path_prefix: str = ""
) -> dict[str, Any]:
    """The SARIF 2.1.0 log of a run.

    ``category`` is the code-scanning category; ``path_prefix`` is the folder
    of the audited folder in the repository (empty for the repository root).
    """
    prefix = normalize_prefix(path_prefix)
    automation = (category.strip().strip("/") or DEFAULT_CATEGORY) + "/"
    located = [finding for finding in findings if finding.location is not None and repository_uri(finding.location.path, prefix)]
    rule_ids = list(dict.fromkeys(rule_id(finding) for finding in located))
    rules = [_rule(identifier, [finding for finding in located if rule_id(finding) == identifier]) for identifier in rule_ids]
    index = {identifier: position for position, identifier in enumerate(rule_ids)}
    results = []
    for finding in located:
        first = finding.location
        assert first is not None
        message = finding.title
        if finding.explanation:
            message = f"{finding.title}\n\n{finding.explanation}"
        result: dict[str, Any] = {
            "ruleId": rule_id(finding),
            "ruleIndex": index[rule_id(finding)],
            "level": LEVELS.get(finding.severity, "warning"),
            "message": {"text": message},
            "locations": [_location(repository_uri(first.path, prefix) or "", first.start_line, first.end_line)],
            "partialFingerprints": {"sentrytowerFindingHash/v1": finding.fingerprint().removeprefix("sha256:")},
            "properties": {
                "id": finding.id,
                "rank": finding.rank,
                "severity": finding.severity,
                "security-severity": f"{SECURITY_SEVERITY.get(finding.severity, 5.5):.1f}",
                "cwe": list(finding.cwe),
                "engine": finding.engine,
                "route": finding.route,
                "tier": finding.tier,
                "verification": finding.verification_status,
            },
        }
        if finding.confidence is not None:
            result["properties"]["confidence"] = finding.confidence
        if finding.verification_reason:
            result["properties"]["verificationReason"] = finding.verification_reason
        related = [
            _location(uri, location.start_line, location.end_line, message=location.note, identifier=number)
            for number, location in enumerate(finding.locations[1:], start=1)
            if (uri := repository_uri(location.path, prefix))
        ]
        if related:
            result["relatedLocations"] = related
        results.append(result)
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
