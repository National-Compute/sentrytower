"""The output files: findings.json against its JSON Schema and the data contracts, SARIF 2.1.0, the report.

``tests/data/golden-findings.json`` and ``golden-findings.sarif`` hold the
outputs of the findings below. A change of them is a change of the public
output format: say so in the change log, then rewrite them with
``.venv/bin/python tests/test_outputs.py``.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from sentrytower import __version__
from sentrytower.audit import write_outputs
from sentrytower.contracts.nc_contracts import findings_from_sarif_log
from sentrytower.findings import (
    ENGINE_AGENT,
    ENGINE_DEEP,
    ENGINE_FREE,
    OutputFinding,
    OutputLocation,
    at_or_above,
    findings_document,
    from_contract,
)
from sentrytower.html_report import html_report, rich_text
from sentrytower.report import markdown_report
from sentrytower.sarif import UNCLASSIFIED, sarif_document

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
GOLDEN_FINDINGS = DATA / "golden-findings.json"
GOLDEN_SARIF = DATA / "golden-findings.sarif"
RUN = {
    "run_id": "0" * 32,
    "route": "funnel",
    "started_at": "2026-10-22T10:00:00+00:00",
    "seconds": 812.4,
    "stop": "queue-empty",
    "repository": {"name": "webapp", "files_counted": 412, "counted_up_to": 1001},
    "models": {"unit_check": "z-ai/glm-5.3-flash"},
    "usage": {"total": {"total_tokens": 7_812_345, "cost_usd": 0.31, "cost_source": "provider"}},
}


def findings() -> list[OutputFinding]:
    return [
        OutputFinding(
            rank=1,
            title="Path traversal in read",
            severity="high",
            cwe=["CWE-22"],
            locations=[OutputLocation("files.py", 51, 53, "open")],
            evidence="`open(os.path.join(BASE, name))`",
            exploit_conditions="../ in the name.",
            engine=ENGINE_FREE,
            route="funnel",
        ),
        OutputFinding(
            rank=2,
            title="Command injection | in ping",
            severity="critical",
            cwe=["CWE-78", "CWE-77"],
            locations=[OutputLocation("app.py", 60, 60), OutputLocation("app.py", 57, 59, "the route")],
            evidence="The host goes to the shell.",
            exploit_conditions="",
            engine=ENGINE_DEEP,
            route="funnel",
            confidence=0.82,
            verification={"verdict": "exploitable", "keep_score": 0.82},
            verification_status="verified",
        ),
        OutputFinding(
            rank=3,
            title="Unclassified issue",
            severity="low",
            cwe=[],
            locations=[OutputLocation("lib/x.js", 4, 4)],
            evidence="e",
            exploit_conditions="c",
            engine=ENGINE_DEEP,
            route="funnel",
            confidence=0.4,
            verification={"verdict": "unclear", "keep_score": 0.4},
            verification_status="verified",
        ),
        OutputFinding(
            rank=4,
            title="No location",
            severity="unknown",
            cwe=["CWE-200"],
            locations=[],
            evidence="e",
            exploit_conditions="",
            engine=ENGINE_AGENT,
            route="agent",
        ),
    ]


def test_findings_json_follows_its_schema_and_the_contract(findings_validator: jsonschema.Draft202012Validator) -> None:
    document = findings_document(findings(), RUN)
    findings_validator.validate(document)
    assert document["schema_version"] == "2.0.0" and document["summary"]["by_severity"]["critical"] == 1
    command = document["findings"][1]
    assert command["id"] == "ST-002" and command["kind"] == "code" and command["severity"] == "critical"
    assert command["location"] == {"path": "app.py", "startLine": 60, "endLine": 60}
    assert command["relatedLocations"] == [{"path": "app.py", "startLine": 57, "endLine": 59, "note": "the route"}]
    assert command["engine"] == {"name": "SentryTower", "version": __version__, "mode": "deep-check"}
    assert command["evidence"] == {
        "class": "defective",
        "verification": {"status": "verified", "method": "blind-vote", "outcome": "supports", "score": 0.82},
    }
    assert command["properties"] == {"rank": 2, "route": "funnel", "tier": 1} and command["ruleId"] == "CWE-78"
    assert command["fingerprint"]["scheme"] == "sentrytowerFindingHash/v1" and re.fullmatch(
        r"[0-9a-f]{32}", command["fingerprint"]["value"]
    )
    assert command["target"] == {"kind": "repository", "locator": "webapp"} and command["description"] == "The host goes to the shell."
    traversal = document["findings"][0]
    assert traversal["description"] == "`open(os.path.join(BASE, name))`\n\nExploit conditions: ../ in the name."
    assert traversal["evidence"] == {"class": "suspected", "verification": {"status": "none"}}
    assert traversal["location"] == {"path": "files.py", "startLine": 51, "endLine": 53, "note": "open"}
    unclassified, nowhere = document["findings"][2], document["findings"][3]
    assert "ruleId" not in unclassified and unclassified["cwe"] == [] and unclassified["evidence"]["class"] == "suspected"
    assert "location" not in nowhere and "relatedLocations" not in nowhere and nowhere["severity"] == "unknown"


def test_the_fingerprint_keeps_the_digest_of_version_1() -> None:
    """Version 1 wrote ``sha256:`` and the same 32 hex digits, so a history of fingerprints across runs carries over."""
    (record,) = findings_document(findings()[1:2], RUN)["findings"]
    assert record["fingerprint"]["value"] == "11fc1767c6c75dc0cae94dd615e830b1"


VERIFIED = {"status": "verified", "method": "blind-vote"}


@pytest.mark.parametrize(
    ("verification", "status", "reason", "evidence"),
    [
        (
            {"verdict": "exploitable", "keep_score": 0.9},
            "verified",
            None,
            {"class": "defective", "verification": {**VERIFIED, "outcome": "supports", "score": 0.9}},
        ),
        (
            {"verdict": "safe", "keep_score": 0.1},
            "verified",
            None,
            {"class": "suspected", "verification": {**VERIFIED, "outcome": "refutes", "score": 0.1}},
        ),
        (
            {"verdict": "unclear", "keep_score": 0.5},
            "verified",
            None,
            {"class": "suspected", "verification": {**VERIFIED, "outcome": "inconclusive", "score": 0.5}},
        ),
        # Only a verified majority makes a finding defective.
        (
            {"verdict": "exploitable", "keep_score": 0.9},
            "unverified",
            "the run stopped first",
            {
                "class": "suspected",
                "verification": {
                    "status": "unverified",
                    "method": "blind-vote",
                    "outcome": "supports",
                    "score": 0.9,
                    "reason": "the run stopped first",
                },
            },
        ),
        (
            None,
            "unverified",
            "the verification call failed",
            {"class": "suspected", "verification": {"status": "unverified", "reason": "the verification call failed"}},
        ),
        (None, "none", None, {"class": "suspected", "verification": {"status": "none"}}),
        # A score outside 0 to 1 is left out.
        (
            {"verdict": "exploitable", "keep_score": 7.0},
            "verified",
            None,
            {"class": "defective", "verification": {**VERIFIED, "outcome": "supports"}},
        ),
    ],
)
def test_the_evidence_class_follows_the_blind_verification(
    verification: dict[str, Any] | None, status: str, reason: str | None, evidence: dict[str, Any]
) -> None:
    finding = OutputFinding(
        rank=1,
        title="t",
        severity="high",
        cwe=["CWE-89"],
        locations=[OutputLocation("db.py", 1, 2)],
        evidence="e",
        exploit_conditions="",
        engine=ENGINE_DEEP,
        route="funnel",
        confidence=(verification or {}).get("keep_score"),
        verification=verification,
        verification_status=status,
        verification_reason=reason,
    )
    assert finding.record()["evidence"] == evidence


def test_the_votes_of_a_slice_finding_are_a_property(findings_validator: jsonschema.Draft202012Validator) -> None:
    votes = ["exploitable", "exploitable", "safe"]
    finding = OutputFinding(
        rank=7,
        title="IDOR in the order view",
        severity="medium",
        cwe=["CWE-639"],
        locations=[OutputLocation("api/orders.js", 12, 18)],
        evidence="e",
        exploit_conditions="c",
        engine=ENGINE_AGENT,
        route="agent",
        tier=2,
        confidence=0.7,
        verification={"verdict": "exploitable", "keep_score": 0.7, "votes": votes},
        verification_status="verified",
    )
    document = findings_document([finding], {**RUN, "route": "agent"})
    findings_validator.validate(document)
    (record,) = document["findings"]
    assert record["properties"] == {"rank": 7, "route": "agent", "tier": 2, "votes": votes} and record["evidence"]["class"] == "defective"
    (result,) = sarif_document([finding], RUN)["runs"][0]["results"]
    assert result["properties"]["votes"] == votes and result["properties"]["tier"] == 2


def test_the_schema_refuses_what_the_cli_never_writes(findings_validator: jsonschema.Draft202012Validator) -> None:
    document = findings_document(findings(), RUN)
    for change in (
        lambda item: item["evidence"].update({"class": "reproduced"}),
        lambda item: item.update({"severity": "severe"}),
        lambda item: item["fingerprint"].update({"value": "sha256:" + item["fingerprint"]["value"]}),
        lambda item: item["engine"].update({"mode": "swarm"}),
        lambda item: item.pop("evidence"),
        lambda item: item["properties"].pop("rank"),
        lambda item: item["location"].update({"startLine": 0}),
        lambda item: item.update({"cwe": ["CWE-089"]}),
    ):
        broken = copy.deepcopy(document)
        change(broken["findings"][0])
        assert not findings_validator.is_valid(broken)


def test_a_finding_of_findings_json_reads_back_as_it_was_written() -> None:
    for position, original in enumerate(findings(), 1):
        record = original.record()
        assert from_contract(record, position=position).record() == record
    # A field of the wrong type takes its default: a file that another program changed cannot stop `sentrytower last`.
    junk = from_contract(
        {
            "title": 3,
            "severity": "severe",
            "location": {"path": "a.py", "startLine": "x"},
            "evidence": {"verification": "x"},
            "properties": [],
        },
        position=4,
    )
    assert (junk.rank, junk.title, junk.severity, junk.location, junk.verification_status) == (
        4,
        "",
        "unknown",
        OutputLocation("a.py", 1, 1),
        "none",
    )
    assert from_contract({"severity": "info", "relatedLocations": "x"}).severity == "low"


def test_the_sarif_log_is_valid_sarif_2_1_0() -> None:
    log = sarif_document(findings(), RUN)
    schema = json.loads((DATA / "sarif-schema-2.1.0.json").read_text())
    jsonschema.Draft4Validator(schema).validate(log)
    run = log["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"CWE-22", "CWE-78", UNCLASSIFIED}
    assert rules["CWE-78"]["properties"]["security-severity"] == "9.5" and "external/cwe/cwe-78" in rules["CWE-78"]["properties"]["tags"]
    assert rules["CWE-22"]["shortDescription"]["text"] == "Path Traversal"
    results = run["results"]
    # A finding without a location is counted in the run properties, not reported as a result.
    assert len(results) == 3 and run["properties"]["findingsWithoutLocation"] == 1
    command = results[1]
    assert command["level"] == "error" and command["ruleId"] == "CWE-78"
    region = command["locations"][0]["physicalLocation"]
    assert region["artifactLocation"] == {"uri": "app.py", "uriBaseId": "%SRCROOT%"} and region["region"] == {
        "startLine": 60,
        "endLine": 60,
    }
    assert command["relatedLocations"][0]["message"]["text"] == "the route"
    assert results[2]["level"] == "note" and run["automationDetails"]["id"] == "sentrytower/"
    # The flat properties are those of version 1; the contract fields that SARIF has no place for are in one property.
    assert set(command["properties"]) == {
        "id", "rank", "severity", "security-severity", "cwe", "engine", "route", "tier", "verification", "confidence", "nationalcompute/finding",
    }  # fmt: skip
    assert command["properties"]["engine"] == "deep-check" and command["properties"]["verification"] == "verified"
    assert command["partialFingerprints"] == {"sentrytowerFindingHash/v1": "11fc1767c6c75dc0cae94dd615e830b1"}
    assert command["properties"]["nationalcompute/finding"]["evidence"]["class"] == "defective"


@pytest.mark.parametrize("prefix", ["", "services/api"])
def test_each_sarif_result_gives_back_its_finding_of_findings_json(prefix: str) -> None:
    """The SARIF mapping of the contracts reads each result back as the finding of findings.json, its paths from the repository root."""
    document = findings_document(findings(), RUN)
    expected = []
    for item in copy.deepcopy(document["findings"]):
        if "location" not in item:
            continue
        for location in [item["location"], *item.get("relatedLocations", [])]:
            location["path"] = f"{prefix}/{location['path']}" if prefix else location["path"]
        expected.append(item)
    assert findings_from_sarif_log(sarif_document(findings(), RUN, path_prefix=prefix)) == expected


def test_a_path_with_spaces_and_percent_signs_survives_the_sarif_round_trip() -> None:
    finding = OutputFinding(
        rank=1,
        title="XSS in the page",
        severity="medium",
        cwe=["CWE-79"],
        locations=[
            OutputLocation("web/my page%20.js", 3, 4),
            OutputLocation("../outside.js", 1, 1),
            OutputLocation("web/ok.js", 9, 9, "the sink"),
        ],
        evidence="e",
        exploit_conditions="",
        engine=ENGINE_FREE,
        route="funnel",
    )
    log = sarif_document([finding], RUN)
    (result,) = log["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "web/my%20page%2520.js"
    (back,) = findings_from_sarif_log(log)
    # A related location outside the repository is not in SARIF; findings.json keeps it.
    assert back["location"]["path"] == "web/my page%20.js" and [item["path"] for item in back["relatedLocations"]] == ["web/ok.js"]
    assert len(findings_document([finding], RUN)["findings"][0]["relatedLocations"]) == 2


def test_the_report_has_a_table_and_the_details() -> None:
    report = markdown_report(findings(), RUN)
    assert report.startswith("# SentryTower security audit")
    # How a finding is known stands under the title, before the facts of the run.
    assert report.index("Each finding is a claim of a language model.") < report.index("- Repository:")
    assert "| 2 | critical | CWE-78, CWE-77 | `app.py:60` | Command injection \\| in ping | funnel, deep check |" in report
    assert "### ST-001: Path traversal in read" in report and "**Exploit conditions.** ../ in the name." in report
    assert "$0.3100 (provider)" in report and "7,812,345" in report
    empty = markdown_report([], RUN)
    assert "SentryTower reported no finding. This is not proof that the code is safe" in empty


def test_write_outputs_writes_the_selected_files_and_run_json(tmp_path: Path) -> None:
    run = dict(RUN)
    files = write_outputs(findings(), run, tmp_path / "out", ("json", "sarif"))
    assert sorted(path.name for path in files.values()) == ["findings.json", "findings.sarif", "run.json"]
    assert json.loads((tmp_path / "out" / "run.json").read_text())["outputs"] == {
        "json": "findings.json",
        "sarif": "findings.sarif",
        "run": "run.json",
    }
    assert not list((tmp_path / "out").glob(".*.tmp"))


@pytest.mark.parametrize(("threshold", "count"), [("critical", 1), ("high", 2), ("medium", 3), ("low", 4)])
def test_the_fail_on_threshold(threshold: str, count: int) -> None:
    # A finding of unknown severity counts as medium.
    assert len(at_or_above(findings(), threshold)) == count


def test_the_html_report_is_one_safe_page_with_each_finding(tmp_path: Path) -> None:
    items = findings()
    items[0].title = 'Path <script>alert("x")</script> traversal'
    items[
        1
    ].evidence = "The host goes to the shell:\n\n```python\nos.system('ping ' + host)  # <b>\n```\n\n- first **step**\n- second `step`"
    run = {
        **RUN,
        "status": "complete",
        "ended_at": "2026-10-30T12:00:00+00:00",
        "configuration": {"agent": {"name": "Ada <x>", "color": "plum"}},
        "warnings": ["a <warning>"],
    }
    page = html_report(items, run)
    assert page.startswith("<!doctype html>") and "Content-Security-Policy" in page and "<script" not in page
    assert "Path &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; traversal" in page and "Ada &lt;x&gt;" in page
    # A code block keeps its text, escaped; a list and inline code and bold text become HTML.
    assert "<pre><code>os.system(&#x27;ping &#x27; + host)  # &lt;b&gt;</code></pre>" in page
    assert "<ul><li>first <strong>step</strong></li><li>second <code>step</code></li></ul>" in page
    assert 'href="https://cwe.mitre.org/data/definitions/78.html"' in page and 'id="ST-002"' in page and 'href="#ST-002"' in page
    assert "a &lt;warning&gt;" in page and "found 4 issues in webapp" in page and "<svg" in page
    # Each finding has its card, and the page names the other files of the run.
    assert page.count("<article ") == 4 and "No location" in page
    # How a finding is known stands under the headline, in the header, and once.
    assert "Each finding is a claim of a language model." in page.split("</header>")[0] and page.count("claim of a language model") == 1
    # By severity: the critical finding (rank 2) comes before the high one (rank 1).
    assert page.index('id="ST-002"') < page.index('id="ST-001"') < page.index('id="ST-003"') < page.index('id="ST-004"')
    files = write_outputs(items, dict(run), tmp_path / "out", ("json", "html"))
    assert files["html"].name == "report.html" and "<code>findings.json</code>" in files["html"].read_text()


def test_the_html_report_of_a_run_without_findings_and_of_a_failed_run() -> None:
    empty = html_report([], {**RUN, "status": "complete"})
    assert "reported no finding in webapp" in empty and "<table>" not in empty
    # What the empty result covers stands under the headline, in the header.
    assert "not proof that the code is safe" in empty.split("</header>")[0] and "claim of a language model" not in empty
    failed = html_report([], {**RUN, "status": "failed", "failure": "the funnel wrote no findings file"})
    assert "could not finish the audit of webapp" in failed and "the funnel wrote no findings file" in failed


def test_rich_text_never_lets_markup_through() -> None:
    text = rich_text("<img src=x onerror=alert(1)> `<b>` **<i>** [link](javascript:alert(1))")
    assert "<img" not in text and "<b>" not in text and "<i>" not in text and "href" not in text


def golden_outputs() -> dict[Path, str]:
    """findings.json and findings.sarif (of an audit of a subfolder) of the findings above; the version of SentryTower is ``<version>``."""
    outputs = {
        GOLDEN_FINDINGS: findings_document(findings(), RUN),
        GOLDEN_SARIF: sarif_document(findings(), RUN, path_prefix="services/api"),
    }
    return {
        path: json.dumps(value, indent=2, ensure_ascii=False).replace(f'"{__version__}"', '"<version>"') + "\n"
        for path, value in outputs.items()
    }


def test_the_outputs_are_the_golden_outputs() -> None:
    for path, text in golden_outputs().items():
        assert path.read_text(encoding="utf-8") == text, f"{path.name} changed (see the docstring of this module)"


def test_the_documented_example_is_what_sentrytower_writes(findings_validator: jsonschema.Draft202012Validator) -> None:
    text = (ROOT / "docs" / "output-format.md").read_text(encoding="utf-8").split("## findings.json\n", 1)[1]
    example = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
    findings_validator.validate(example)
    run = {
        "run_id": example["run"]["id"],
        "route": "funnel",
        "started_at": example["run"]["started_at"],
        "repository": {"name": "webapp", "files_counted": 412},
        "result": example["run"]["result"],
    }
    items = [
        OutputFinding(
            rank=1,
            title="Command injection in ping",
            severity="critical",
            cwe=["CWE-78"],
            locations=[OutputLocation("app.py", 60, 60), OutputLocation("app.py", 57, 59, "the route takes the host")],
            evidence="The host parameter goes to os.system without a check.",
            exploit_conditions="The attacker controls the host parameter.",
            engine=ENGINE_FREE,
            route="funnel",
        ),
        OutputFinding(
            rank=2,
            title="Path traversal in read",
            severity="high",
            cwe=["CWE-22"],
            locations=[OutputLocation("files.py", 51, 53)],
            evidence="open(os.path.join(BASE, name)) takes the name of the request.",
            exploit_conditions="The attacker sends ../ in the name.",
            engine=ENGINE_DEEP,
            route="funnel",
            confidence=0.84,
            verification={"verdict": "exploitable", "keep_score": 0.84},
            verification_status="verified",
        ),
    ]
    assert findings_document(items, run) == example


if __name__ == "__main__":
    for path, text in golden_outputs().items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
