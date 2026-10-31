"""The output files: findings.json against its JSON Schema, SARIF 2.1.0 against the OASIS schema, the report."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from sentrytower.audit import write_outputs
from sentrytower.findings import (
    ENGINE_AGENT,
    ENGINE_DEEP,
    ENGINE_FREE,
    OutputFinding,
    OutputLocation,
    at_or_above,
    findings_document,
)
from sentrytower.html_report import html_report, rich_text
from sentrytower.report import markdown_report
from sentrytower.sarif import UNCLASSIFIED, sarif_document

DATA = Path(__file__).resolve().parent / "data"
SCHEMA = Path(__file__).resolve().parents[1] / "src" / "sentrytower" / "schemas" / "findings-v1.schema.json"
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


def test_findings_json_follows_its_schema() -> None:
    document = findings_document(findings(), RUN)
    schema = json.loads(SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(document)
    first = document["findings"][1]
    assert first["location"] == {"path": "app.py", "start_line": 60, "end_line": 60}
    assert first["related_locations"] == [{"path": "app.py", "start_line": 57, "end_line": 59, "note": "the route"}]
    assert first["engine"] == "deep-check" and first["route"] == "funnel" and first["confidence"] == 0.82
    assert first["fingerprint"].startswith("sha256:") and document["summary"]["by_severity"]["critical"] == 1
    assert document["findings"][3]["location"] is None


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


def test_the_report_has_a_table_and_the_details() -> None:
    report = markdown_report(findings(), RUN)
    assert report.startswith("# SentryTower security audit")
    assert "| 2 | critical | CWE-78, CWE-77 | `app.py:60` | Command injection \\| in ping | funnel, deep check |" in report
    assert "### ST-001: Path traversal in read" in report and "**Exploit conditions.** ../ in the name." in report
    assert "$0.3100 (provider)" in report and "7,812,345" in report
    empty = markdown_report([], RUN)
    assert "SentryTower reported no vulnerability. This is not a proof that the code is safe" in empty


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
    # By severity: the critical finding (rank 2) comes before the high one (rank 1).
    assert page.index('id="ST-002"') < page.index('id="ST-001"') < page.index('id="ST-003"') < page.index('id="ST-004"')
    files = write_outputs(items, dict(run), tmp_path / "out", ("json", "html"))
    assert files["html"].name == "report.html" and "<code>findings.json</code>" in files["html"].read_text()


def test_the_html_report_of_a_run_without_findings_and_of_a_failed_run() -> None:
    empty = html_report([], {**RUN, "status": "complete"})
    assert "found no issue in webapp" in empty and "not proof that the code is safe" in empty and "<table>" not in empty
    failed = html_report([], {**RUN, "status": "failed", "failure": "the funnel wrote no findings file"})
    assert "could not finish the audit of webapp" in failed and "the funnel wrote no findings file" in failed


def test_rich_text_never_lets_markup_through() -> None:
    text = rich_text("<img src=x onerror=alert(1)> `<b>` **<i>** [link](javascript:alert(1))")
    assert "<img" not in text and "<b>" not in text and "<i>" not in text and "href" not in text
