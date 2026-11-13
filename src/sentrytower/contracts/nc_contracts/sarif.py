# SPDX-License-Identifier: Apache-2.0 OR MIT
"""SARIF 2.1.0 result <-> Finding. Both directions are total and never raise.

Finding to result:

- ``ruleId``: ``ruleId``; else the first CWE; else ``SENTRYTOWER-UNCLASSIFIED``
- ``severity``: ``level``, ``properties.severity``, ``properties["security-severity"]``
- ``title``, ``description``: ``message.text``, as ``"title\\n\\ndescription"``
- ``location``: ``locations[0]``, relative to ``%SRCROOT%``, percent-encoded
- ``relatedLocations``: ``relatedLocations``, with ids from 1 and the note as message
- ``path``: ``codeFlows[0].threadFlows[0]``, the role in ``properties.role``
- ``fingerprint``: ``partialFingerprints``, the scheme as the key
- ``id``, ``cwe``, ``engine.mode``: ``properties.id``, ``.cwe``, ``.engine`` (the CLI's keys)
- ``evidence.verification``: ``properties.verification``, ``.confidence``,
  ``.verificationReason`` (the CLI's keys)
- ``properties``: ``properties``, except the keys above
- every other field: ``properties["nationalcompute/finding"]``

Result to finding reads the same places. For a result from another tool it
falls back to the SARIF fields: severity from ``security-severity``, then the
level (the rule's default level, then ``warning``, when the result has none);
CWE from the rule's ``external/cwe/cwe-<n>`` tags or a CWE rule id; the engine
from the run's tool; the target from ``versionControlProvenance``; the kind
``code`` with the evidence class ``suspected``. A result with no fingerprint
gets the scheme ``sarifResultHash/v1``.

The TypeScript module src/sarif.ts implements the same mapping; both pass the
cases in test/vectors/sarif.json.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .evidence import evidence_from_cli, status_from_cli
from .severity import (
    is_severity,
    severity_from_cvss_score,
    severity_from_sarif_level,
    severity_rank,
    severity_to_sarif_level,
    severity_to_security_severity,
)
from .types import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
#: The rule of a finding with no rule and no CWE; the public CLI uses the same id.
UNCLASSIFIED_RULE = "SENTRYTOWER-UNCLASSIFIED"
#: The property that carries the fields of a finding that SARIF has no place for.
FINDING_PROPERTY = "nationalcompute/finding"
#: The fingerprint scheme of a result with no fingerprint.
SARIF_RESULT_HASH = "sarifResultHash/v1"

_SRCROOT = "%SRCROOT%"
_PREFERRED_SCHEMES = ("sentrytowerFindingHash/v1", "sentrytowerScannerFinding/v1")
_RESERVED = frozenset(
    ("id", "severity", "security-severity", "cwe", "engine", "verification", "confidence", "verificationReason", FINDING_PROPERTY)
)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*(/v[1-9][0-9]*)?")
_VALUE = re.compile(r"[\x21-\x7e]{1,256}")
_CWE = re.compile(r"CWE-[1-9][0-9]*")
_CWE_TAG = re.compile(r"external/cwe/cwe-0*([1-9][0-9]*)", re.IGNORECASE)
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_KINDS = ("code", "dependency_vulnerability", "image_vulnerability", "malicious_package", "secret", "iac")
_ROLES = ("source", "hop", "sink")
_SAFE = "/!$&'()*+,;=@"
_SURROGATE = re.compile("[\ud800-\udfff]")
_ESCAPES = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_BAG_KEYS = ("ruleId", "evidence", "target", "advisories", "component", "fixedVersions", "reproduction", "createdAt")


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _positive(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, float) and value.is_integer() and value >= 1:
        return int(value)
    return None


def _strings(value: Any) -> list[str] | None:
    return list(value) if isinstance(value, list) and all(isinstance(v, str) for v in value) else None


def _first(*values: Any) -> Any:
    """The first value that is not None, as JavaScript's ``??`` chooses it."""
    return next((v for v in values if v is not None), None)


def _dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _utf8(text: str) -> bytes:
    """UTF-8 bytes; a lone surrogate becomes U+FFFD, as JavaScript's TextEncoder writes it."""
    return _SURROGATE.sub("�", text).encode("utf-8")


def repository_uri(path: str) -> str:
    """A repository path as a relative URI: ``\\`` becomes ``/``, and every byte outside the
    CLI's safe set is percent-encoded."""
    from urllib.parse import quote

    return quote(_utf8(path.replace("\\", "/")), safe=_SAFE)


def path_from_uri(uri: str) -> str:
    """A URI as a path: each run of %XX escapes decodes as UTF-8, a lone ``%`` stays, and a
    ``file://`` scheme is dropped."""
    bare = uri[len("file://"):] if uri.startswith("file://") else uri
    return _ESCAPES.sub(lambda m: bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8", "replace"), bare)


def _to_location(location: dict[str, Any], identifier: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if identifier is not None:
        out["id"] = identifier
    physical: dict[str, Any] = {"artifactLocation": {"uri": repository_uri(location["path"]), "uriBaseId": _SRCROOT}}
    # SARIF needs a start line for a region; an excerpt without one goes in the properties.
    if location.get("startLine") is not None:
        region: dict[str, Any] = {"startLine": location["startLine"]}
        for key in ("endLine", "startColumn", "endColumn"):
            if location.get(key) is not None:
                region[key] = location[key]
        if location.get("excerpt") is not None:
            region["snippet"] = {"text": location["excerpt"]}
        physical["region"] = region
    elif location.get("excerpt") is not None:
        out["properties"] = {"excerpt": location["excerpt"]}
    out["physicalLocation"] = physical
    if location.get("note") is not None:
        out["message"] = {"text": location["note"]}
    return out


def _from_location(value: Any) -> dict[str, Any] | None:
    source = _dict(value)
    physical = _dict(source.get("physicalLocation")) if source else None
    if physical is None:
        return None
    artifact = _dict(physical.get("artifactLocation"))
    uri = _text(artifact.get("uri")) if artifact else None
    if not uri:
        return None
    location: dict[str, Any] = {"path": path_from_uri(uri) or uri}
    region = _dict(physical.get("region")) or {}
    start = _positive(region.get("startLine"))
    if start is not None:
        location["startLine"] = start
        for key in ("endLine", "startColumn", "endColumn"):
            number = _positive(region.get(key))
            if number is not None:
                location[key] = number
    message = _dict(source.get("message"))
    if message is not None and isinstance(message.get("text"), str):
        location["note"] = message["text"]
    snippet = _dict(region.get("snippet"))
    excerpt = snippet.get("text") if snippet is not None else None
    if not isinstance(excerpt, str):
        properties = _dict(source.get("properties"))
        excerpt = properties.get("excerpt") if properties is not None else None
    if isinstance(excerpt, str):
        location["excerpt"] = excerpt
    return location


def finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """The SARIF result of a finding."""
    cwe = finding.get("cwe")
    description = finding.get("description")
    result: dict[str, Any] = {
        "ruleId": _first(finding.get("ruleId"), cwe[0] if cwe else None, UNCLASSIFIED_RULE),
        "level": severity_to_sarif_level(finding["severity"]),
        "message": {"text": f"{finding['title']}\n\n{description}" if description else finding["title"]},
    }
    if finding.get("location") is not None:
        result["locations"] = [_to_location(finding["location"])]  # type: ignore[arg-type]
    if finding.get("relatedLocations"):
        result["relatedLocations"] = [_to_location(loc, i) for i, loc in enumerate(finding["relatedLocations"], 1)]  # type: ignore[arg-type]
    if finding.get("path"):
        steps = [{"location": _to_location(s["location"]), "properties": {"role": s["role"]}} for s in finding["path"]]  # type: ignore[arg-type]
        result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
    result["partialFingerprints"] = {finding["fingerprint"]["scheme"]: finding["fingerprint"]["value"]}

    properties: dict[str, Any] = {k: v for k, v in (finding.get("properties") or {}).items() if k not in _RESERVED}
    if finding.get("id") is not None:
        properties["id"] = finding["id"]
    properties["severity"] = finding["severity"]
    properties["security-severity"] = severity_to_security_severity(finding["severity"])
    if cwe is not None:
        properties["cwe"] = list(cwe)
    if finding["engine"].get("mode") is not None:
        properties["engine"] = finding["engine"]["mode"]
    evidence = finding.get("evidence")
    verification = evidence.get("verification") if evidence is not None else None
    if verification is not None:
        properties["verification"] = verification["status"]
        if verification.get("score") is not None:
            properties["confidence"] = verification["score"]
        if verification.get("reason") is not None:
            properties["verificationReason"] = verification["reason"]
    bag: dict[str, Any] = {"kind": finding["kind"], "title": finding["title"], "engine": finding["engine"]}
    for key in _BAG_KEYS:
        if finding.get(key) is not None:
            bag[key] = finding[key]  # type: ignore[literal-required]
    properties[FINDING_PROPERTY] = bag
    result["properties"] = properties
    return result


def _rule_of(result: dict[str, Any], run: Any) -> dict[str, Any] | None:
    tool = _dict(_dict(run).get("tool")) if _dict(run) else None
    driver = _dict(tool.get("driver")) if tool else None
    rules = driver.get("rules") if driver else None
    if not isinstance(rules, list):
        return None
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        by_index = _dict(rules[index])
        if by_index is not None and ("ruleId" not in result or by_index.get("id") == result.get("ruleId")):
            return by_index
    return next((r for r in rules if isinstance(r, dict) and r.get("id") == result.get("ruleId")), None)


def _fingerprint_of(result: dict[str, Any]) -> dict[str, str]:
    def entries(source: Any) -> list[tuple[str, str]]:
        found = [
            (k, v)
            for k, v in (_dict(source) or {}).items()
            if isinstance(v, str) and _SCHEME.fullmatch(k) and _VALUE.fullmatch(v)
        ]
        return sorted(found, key=lambda kv: kv[0])

    candidates = entries(result.get("partialFingerprints")) + entries(result.get("fingerprints"))
    chosen = next((c for s in _PREFERRED_SCHEMES for c in candidates if c[0] == s), None) or (candidates[0] if candidates else None)
    if chosen:
        return {"scheme": chosen[0], "value": chosen[1]}
    locations = result.get("locations")
    first = _dict(locations[0]) if isinstance(locations, list) and locations else None
    physical = _dict(first.get("physicalLocation")) if first else None
    artifact = _dict(physical.get("artifactLocation")) if physical else None
    region = _dict(physical.get("region")) if physical else None
    uri = artifact.get("uri") if artifact else None
    line = region.get("startLine") if region else None
    message = _dict(result.get("message"))
    material = "|".join(
        [
            result["ruleId"] if isinstance(result.get("ruleId"), str) else "",
            uri if isinstance(uri, str) else "",
            _number(line) if isinstance(line, (int, float)) and not isinstance(line, bool) else "",
            message["text"] if message is not None and isinstance(message.get("text"), str) else "",
        ]
    )
    return {"scheme": SARIF_RESULT_HASH, "value": hashlib.sha256(_utf8(material)).hexdigest()}


def _number(value: float) -> str:
    """A number as JavaScript's String() writes it, for the integers and plain decimals of a line."""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _severity_of(result: dict[str, Any], properties: dict[str, Any], rule: dict[str, Any] | None) -> str:
    if is_severity(properties.get("severity")):
        return properties["severity"]
    score = properties.get("security-severity")
    if score is None and rule is not None:
        rule_properties = _dict(rule.get("properties"))
        score = rule_properties.get("security-severity") if rule_properties else None
    if score is not None:
        severity = severity_from_cvss_score(score)
        if severity != "unknown":
            return severity
    # SARIF: an absent level is the rule's default level, else ``warning``.
    level = result.get("level")
    if level is None and rule is not None:
        configuration = _dict(rule.get("defaultConfiguration"))
        level = configuration.get("level") if configuration else None
    return severity_from_sarif_level("warning" if level is None else level)


def _cwe_of(result: dict[str, Any], properties: dict[str, Any], rule: dict[str, Any] | None) -> list[str] | None:
    listed = _strings(properties.get("cwe"))
    if listed is not None:
        return [c for c in listed if _CWE.fullmatch(c)]
    rule_properties = _dict(rule.get("properties")) if rule else None
    tags = _strings(rule_properties.get("tags")) if rule_properties else None
    tagged = [f"CWE-{m.group(1)}" for m in (_CWE_TAG.fullmatch(t) for t in tags or []) if m]
    if tagged:
        return list(dict.fromkeys(tagged))
    rule_id = result.get("ruleId")
    return [rule_id] if isinstance(rule_id, str) and _CWE.fullmatch(rule_id) else None


def _engine_of(run: Any, properties: dict[str, Any]) -> dict[str, Any]:
    tool = _dict(_dict(run).get("tool")) if _dict(run) else None
    driver = _dict(tool.get("driver")) if tool else None
    engine: dict[str, Any] = {"name": (_text(driver.get("name")) if driver else None) or "unknown"}
    version = (_text(driver.get("semanticVersion")) or _text(driver.get("version"))) if driver else None
    if version:
        engine["version"] = version
    mode = _text(properties.get("engine"))
    if mode:
        engine["mode"] = mode
    return engine


def _target_of(run: Any) -> dict[str, Any] | None:
    provenance = _dict(run).get("versionControlProvenance") if _dict(run) else None
    first = _dict(provenance[0]) if isinstance(provenance, list) and provenance else None
    locator = _text(first.get("repositoryUri")) if first else None
    if not locator or first is None:
        return None
    target: dict[str, Any] = {"kind": "repository", "locator": locator}
    revision = first.get("revisionId")
    if isinstance(revision, str) and _COMMIT.fullmatch(revision):
        target["revision"] = revision
    return target


def _path_of(result: dict[str, Any]) -> list[dict[str, Any]] | None:
    flows = result.get("codeFlows")
    flow = _dict(flows[0]) if isinstance(flows, list) and flows else None
    threads = flow.get("threadFlows") if flow else None
    thread = _dict(threads[0]) if isinstance(threads, list) and threads else None
    steps = thread.get("locations") if thread else None
    located = []
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        location = _from_location(step.get("location"))
        if location is not None:
            properties = _dict(step.get("properties"))
            located.append((location, properties.get("role") if properties else None))
    if not located:
        return None
    # A step without a role takes it from its position: first source, last sink, hop between.
    last = len(located) - 1
    return [
        {
            "role": role if role in _ROLES else ("source" if i == 0 else "sink" if i == last else "hop"),
            "location": location,
        }
        for i, (location, role) in enumerate(located)
    ]


def finding_from_sarif_result(result: Any, run: Any = None) -> Finding:
    """The finding of a SARIF result; ``run`` gives the tool, the rules and the repository
    when it is known."""
    source: dict[str, Any] = result if isinstance(result, dict) else {"message": {}}
    properties: dict[str, Any] = _dict(source.get("properties")) or {}
    bag = _dict(properties.get(FINDING_PROPERTY))
    rule = _rule_of(source, run)
    message_object = _dict(source.get("message"))
    message = message_object["text"] if message_object and isinstance(message_object.get("text"), str) else ""

    given = _text(bag.get("title")) if bag is not None else None
    description: str | None = None
    if given:
        title = given
        if message.startswith(f"{given}\n\n"):
            description = message[len(given) + 2:]
        elif message and message != given:
            description = message
    else:
        split = message.find("\n\n")
        title = (message[:split] if split >= 0 else message).strip() or _text(source.get("ruleId")) or "SARIF result"
        if split >= 0 and message[split + 2:]:
            description = message[split + 2:]

    kind = bag.get("kind") if bag is not None and bag.get("kind") in _KINDS else "code"
    bag_engine = _dict(bag.get("engine")) if bag is not None else None
    finding: dict[str, Any] = {
        "fingerprint": _fingerprint_of(source),
        "kind": kind,
        "title": title,
        "severity": _severity_of(source, properties, rule),
        "engine": dict(bag_engine) if bag_engine is not None and _text(bag_engine.get("name")) else _engine_of(run, properties),
    }
    identifier = _text(properties.get("id"))
    if identifier:
        finding["id"] = identifier
    if description is not None:
        finding["description"] = description

    bag_evidence = _dict(bag.get("evidence")) if bag is not None else None
    if bag_evidence is not None and isinstance(bag_evidence.get("class"), str):
        finding["evidence"] = bag_evidence
    elif kind == "code":
        if "verification" not in properties:
            finding["evidence"] = {"class": "suspected"}
        else:
            finding["evidence"] = evidence_from_cli(
                {
                    "status": status_from_cli(properties["verification"]),
                    "keep_score": properties.get("confidence"),
                    "reason": properties.get("verificationReason"),
                }
            )

    rule_id = _text(bag.get("ruleId")) if bag is not None else (_text(source.get("ruleId")) or (_text(rule.get("id")) if rule else None))
    if rule_id:
        finding["ruleId"] = rule_id
    target = _dict(bag.get("target")) if bag is not None else None
    target = target if target is not None else _target_of(run)
    if target is not None:
        finding["target"] = target

    locations = source.get("locations")
    location = next((loc for loc in map(_from_location, locations) if loc), None) if isinstance(locations, list) else None
    if location is not None:
        finding["location"] = location
    related_source = source.get("relatedLocations")
    related = [loc for loc in map(_from_location, related_source) if loc] if isinstance(related_source, list) else []
    if related:
        finding["relatedLocations"] = related
    path = _path_of(source)
    if path:
        finding["path"] = path

    cwe = _strings(properties.get("cwe")) if bag is not None else _cwe_of(source, properties, rule)
    if cwe is not None:
        finding["cwe"] = cwe
    for key in ("advisories", "fixedVersions"):
        values = _strings(bag.get(key)) if bag is not None else None
        if values is not None:
            finding[key] = values
    for key in ("component", "reproduction"):
        value = _dict(bag.get(key)) if bag is not None else None
        if value is not None:
            finding[key] = value
    created = _text(bag.get("createdAt")) if bag is not None else None
    if created:
        finding["createdAt"] = created

    extra = {k: v for k, v in properties.items() if k not in _RESERVED}
    if extra:
        finding["properties"] = extra
    return finding  # type: ignore[return-value]


def _rule_for(rule_id: str, findings: list[Finding]) -> dict[str, Any]:
    worst = "unknown"
    for f in findings:
        if severity_rank(f["severity"]) < severity_rank(worst):  # type: ignore[arg-type]
            worst = f["severity"]
    score = max(float(severity_to_security_severity(f["severity"])) for f in findings)
    cwe = rule_id[len("CWE-"):] if _CWE.fullmatch(rule_id) else None
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "defaultConfiguration": {"level": severity_to_sarif_level(worst)},  # type: ignore[arg-type]
        "properties": {
            "tags": ["security", f"external/cwe/cwe-{cwe}"] if cwe else ["security"],
            "security-severity": f"{score:.1f}",
        },
    }
    if cwe:
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe}.html"
    return rule


def findings_to_sarif_log(
    findings: list[Finding], tool: dict[str, str], *, category: str | None = None, require_location: bool = True
) -> dict[str, Any]:
    """A SARIF 2.1.0 log with one run. ``category`` sets ``automationDetails.id``
    (``<category>/``). By default a finding without a location is counted in
    ``properties.findingsWithoutLocation`` and left out, because code scanning needs one."""
    included = findings if not require_location else [f for f in findings if f.get("location") is not None]
    results = [finding_to_sarif_result(f) for f in included]
    ids = list(dict.fromkeys(r.get("ruleId") or UNCLASSIFIED_RULE for r in results))
    rules = [_rule_for(i, [f for f, r in zip(included, results, strict=True) if r.get("ruleId") == i]) for i in ids]
    for r in results:
        r["ruleIndex"] = ids.index(r.get("ruleId") or UNCLASSIFIED_RULE)
    driver: dict[str, Any] = {"name": tool["name"], "rules": rules}
    if tool.get("version"):
        driver["version"] = tool["version"]
        driver["semanticVersion"] = tool["version"]
    if tool.get("informationUri"):
        driver["informationUri"] = tool["informationUri"]
    run: dict[str, Any] = {"tool": {"driver": driver}}
    name = (category or "").strip().strip("/")
    if name:
        run["automationDetails"] = {"id": f"{name}/"}
    run["originalUriBaseIds"] = {_SRCROOT: {"description": {"text": "The root of the scanned target."}}}
    run["results"] = results
    run["properties"] = {"findingsWithoutLocation": len(findings) - len(included)}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def findings_from_sarif_log(log: Any) -> list[Finding]:
    """The findings of every result of every run of a SARIF log."""
    runs = log.get("runs") if isinstance(log, dict) else None
    if not isinstance(runs, list):
        return []
    return [
        finding_from_sarif_result(result, run)
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("results"), list)
        for result in run["results"]
    ]
