"""The funnel engine: each phase with scripted model answers, and whole runs on synthetic repositories."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakes import kind_of
from sentrytower.funnel import protocols
from sentrytower.funnel.inventory import build_inventory
from sentrytower.funnel.pacing import Budget, Clock, Parameters
from sentrytower.funnel.resolve import (
    FREE_SOURCE,
    Finding,
    clean_path,
    configure_root,
    final_locations,
    finding_from_item,
    resolve_first,
    select_output,
)
from sentrytower.funnel.slices import SourceFiles, claim_message, split_lines, unit_card, unit_code
from sentrytower.policies import DEFAULT_MODEL
from synthetic import WEBAPP, line_of, many_modules


def test_the_inventory_finds_units_routes_and_path_classes(write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FUNNEL_INVENTORY_SCANNER", "python")
    repo = write_repo(WEBAPP)
    inventory = build_inventory(repo, deadline_seconds=60)
    units = {(unit["path"], unit["symbol"]): unit for unit in inventory["units"]}
    assert ("app.py", "ping") in units and units[("app.py", "ping")]["kind"] == "route-handler"
    assert any(signal["cwe"] == "CWE-78" for signal in units[("app.py", "ping")]["signals"])
    tags = {item["path"]: item["tags"] for item in inventory["files"]}
    assert "test" in tags["tests/test_app.py"] and "vendor" in tags["vendor/lib.js"]
    assert inventory["routes"] and not inventory["partial"]
    assert inventory["stats"]["semgrep"] == {"ran": False, "seconds": 0.0, "results": 0, "timed_out": False, "reason": "disabled"}
    assert not any(item["path"].startswith(".git/") for item in inventory["files"])


def test_a_unit_slice_has_the_file_header_and_the_numbered_unit(write_repo) -> None:
    repo = write_repo(WEBAPP)
    files = SourceFiles(repo)
    start = line_of(WEBAPP, "app.py", "def ping")
    unit = {
        "id": "u1",
        "path": "app.py",
        "start_line": start - 1,
        "end_line": start + 4,
        "symbol": "ping",
        "kind": "route-handler",
        "language": "python",
        "signals": [{"line": start + 3, "kind": "sink"}],
    }
    values, meta = unit_code(unit, files, max_chars=40_000, header_lines=40)
    assert values is not None and meta["shown"] == [(1, 40), (start - 1, start + 4)]
    assert values["shown"] == f"1 to 40 and {start - 1} to {start + 4}" and values["fence"] == "```" and values["language"] == "python"
    assert f"{start:>5}│def ping():" in values["code"] and "     …│ (lines 41 to" in values["code"]
    message = protocols.render(protocols.read_prompt("funnel-unit-check.txt").strip(), {**values, "lens": ""})
    assert message.startswith("Audit this code for security vulnerabilities.") and "{{" not in message
    card = unit_card(unit, [])
    assert card.startswith(f"[u1] app.py:{start - 1}-{start + 4} ping (route-handler)")


def test_a_claim_message_gives_the_code_and_never_the_reasoning(write_repo) -> None:
    repo = write_repo(WEBAPP)
    line = line_of(WEBAPP, "app.py", "os.system(")
    text, meta = claim_message(
        path="app.py",
        line=line,
        end_line=line,
        cwe="CWE-78",
        files=SourceFiles(repo),
        unit=None,
        routes=[],
        max_chars=20_000,
        header_lines=40,
    )
    assert text is not None and text.startswith(f"Claim: line {line} of app.py has the weakness CWE-78.")
    assert "First lines of the file:" in text and meta["start"] == line - 60 or meta["start"] == 1


def test_lines_split_on_newline_only() -> None:
    assert split_lines("a\r\nb\x0cc d\n") == ["a", "b\x0cc d"]


def test_the_unit_check_parser_reads_lines_quotes_and_confidences() -> None:
    answer = (
        '{"findings": [{"line": "12", "quote": "   12│ os.system(x)", "cwe": "cwe-078", "confidence": "Moderate"},'
        ' {"line": 3, "confidence": "low"}]}'
    )
    parsed = protocols.parse_unit_findings(answer)
    assert [(item["sink_line"], item["sink_quote"], item["cwe"], item["confidence"], item["verdict"]) for item in parsed["candidates"]] == [
        (12, "os.system(x)", "CWE-78", "medium", "vulnerable"),
        (3, "", None, "low", "unsure"),
    ]
    with pytest.raises(protocols.ParseError):
        protocols.parse_unit_findings("I found nothing to report.")


def test_the_verification_parser_reads_a_verdict_and_a_score() -> None:
    parsed = protocols.parse_verify('{"verdict": "Not vulnerable", "keep_score": "85%", "guard_quote": "`if not ok:`"}')
    assert (parsed["verdict"], parsed["keep_score"], parsed["guard_quote"]) == ("safe", 0.85, "if not ok:")
    assert protocols.parse_verify('{"verdict": "exploitable"}')["keep_score"] == 0.75


def test_the_quoted_line_replaces_the_reported_location_in_its_place(write_repo) -> None:
    repo = write_repo(WEBAPP)
    files = SourceFiles(repo)
    line = line_of(WEBAPP, "app.py", "os.system(")
    item = {
        "title": "x",
        "locations": [
            {"path": "app.py", "line_start": line - 4, "line_end": line - 2},
            {"path": "files.py", "line_start": 1, "line_end": 2},
        ],
        "evidence": 'It runs `os.system("ping -c 1 " + host)`.',
        "severity": "high",
        "cwe": ["CWE-78"],
    }
    finding = finding_from_item(item, identifier="t1-1", source="nearby", order=1)
    parameters = Parameters()
    resolution = resolve_first(finding, files, ["app.py", "files.py"], {}, parameters)
    assert resolution is not None and resolution["method"] == "quote" and resolution["line_start"] == line
    locations = final_locations(finding, resolution, files, ["app.py", "files.py"], parameters)
    assert locations[0] == {"path": "app.py", "line_start": line, "line_end": line} and locations[1]["path"] == "files.py"


def test_the_root_of_the_run_is_a_path_prefix() -> None:
    try:
        configure_root("/home/user/project")
        assert clean_path("/home/user/project/app.py") == "app.py"
        assert clean_path("home/user/project/app.py") == "app.py"
        assert clean_path("/workspace/repo/app.py") == "app.py" and clean_path("./a/b.py") == "b.py"
    finally:
        configure_root()


def _finding(identifier: str, source: str, path: str, line: int, *, order: int, score: float | None = None) -> Finding:
    finding = Finding(
        id=identifier,
        source=source,
        order=order,
        title=identifier,
        severity="high",
        evidence="",
        exploit_conditions="",
        cwe=["CWE-78"],
        reported=[{"path": path, "line_start": line, "line_end": line}],
    )
    finding.locations = [{"path": path, "line_start": line, "line_end": line}]
    if score is not None:
        finding.verify = {"verdict": "exploitable", "keep_score": score}
    return finding


def test_one_ranked_list_free_findings_first_then_the_caps() -> None:
    parameters = Parameters()
    findings = [
        _finding("R001", FREE_SOURCE, "a.py", 10, order=1),
        _finding("R002", FREE_SOURCE, "a.py", 12, order=2),
        _finding("t1-1", "deep-check", "a.py", 100, order=3, score=0.9),
        _finding("t2-1", "deep-check", "b.py", 15, order=4, score=0.2),
        _finding("t3-1", "deep-check", "b.py", 18, order=5, score=0.95),
        *[_finding(f"t{9 + n}-1", "nearby", f"c{n}.py", 5, order=10 + n, score=0.5) for n in range(5)],
    ]
    kept, removed = select_output(findings, parameters)
    assert [item.id for item in kept] == ["R001", "R002", "t3-1", "t9-1", "t10-1", "t11-1"]
    reasons = {item["id"]: item["reason"] for item in removed}
    # t1-1: the third finding of a.py; t2-1: within 10 lines of t3-1 in b.py; the rest: the run cap of 6.
    assert reasons["t1-1"] == "file-cap" and reasons["t2-1"] == "duplicate" and reasons["t12-1"] == "run-cap"


def test_the_pools_share_the_spendable_budget() -> None:
    budget = Budget(20_000_000)
    assert budget.stop_level == 18_000_000
    assert budget.allowance == {
        "rating": 900_000,
        "unit_check": 4_500_000,
        "triage": 1_440_000,
        "deep_check": 9_000_000,
        "verify": 900_000,
        "reserve": 1_260_000,
        "free": 12_000_000,
    }
    assert budget.admits("unit_check", 10_000) and not budget.admits("unit_check", 5_000_000)
    budget.start("call", "unit_check", 4_000_000, reserve=4_100_000)
    assert budget.pool_remaining("unit_check") == 500_000 and budget.headroom("deep_check") == 18_000_000 - 4_100_000 - 900_000
    budget.finish("call", 3_000)
    assert budget.used["unit_check"] == 3_000 and budget.move("unit_check", "deep_check", 10**9, "test") == 4_497_000


def test_the_clock_of_the_default_wall_clock() -> None:
    clock = Clock(14_400)
    assert (clock.end, clock.work_end, clock.verify_end, clock.phase0_deadline, clock.free_seconds) == (
        12_960.0,
        12_360.0,
        12_840.0,
        1_440.0,
        12_240,
    )


_PING = line_of(WEBAPP, "app.py", "os.system(")
_READ = line_of(WEBAPP, "files.py", "def read")
FREE_ANSWER = {
    "findings": [
        {
            "title": "Path traversal in read",
            "locations": [{"path": "files.py", "line_start": _READ, "line_end": _READ + 2}],
            "cwe": ["CWE-22"],
            "severity": "high",
            "evidence": "`open(os.path.join(BASE, name))`",
            "exploit_conditions": "../ in the name.",
        },
    ]
}


@pytest.mark.slow
def test_a_whole_funnel_run_on_a_small_repository(rig, write_repo) -> None:
    repo = write_repo(WEBAPP)
    outcome, fake = rig.audit(repo, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(FREE_ANSWER)}, state=rig.base / "state")
    assert outcome.exit_code == 0 and outcome.run["route"] == "funnel" and outcome.run["status"] == "complete"
    kinds = fake.kinds()
    # The queue fits the budget: no rating; one unit check for each unit outside tests, docs and data
    # files; a triage call for each lead; a verification for each deep-check finding.
    assert "rating" not in kinds and kinds.count("unit-check") == 13 and kinds.count("verify") > 5
    work = rig.base / "state" / ".local" / "state" / "review"
    summary = json.loads((work / "summary.json").read_text())
    counts = summary["funnel"]
    assert counts["checked"] == 13 and counts["deep_checked"] >= 5 and counts["triaged"] == counts["leads"] - counts["triage_not_needed"]
    assert summary["stop"]["reason"] == "queue-empty"
    # The output: the free-roaming finding first, then the deep-check findings by their verification score; at most 6.
    findings = outcome.findings
    assert len(findings) == 6 and findings[0].engine == "free-roaming" and findings[0].location is not None
    assert findings[0].location.path == "files.py" and findings[0].confidence is None
    deep = [finding for finding in findings if finding.engine == "deep-check"]
    assert all(finding.confidence is not None for finding in deep)
    assert [finding.confidence for finding in deep] == sorted((finding.confidence for finding in deep), reverse=True)
    assert all(finding.route == "funnel" for finding in findings)
    assert not any(finding.location and finding.location.path.startswith("tests/") for finding in findings)
    # The agent sessions: the free-roaming session and one deep check for each unit with a triaged lead.
    log = rig.pi_log()
    free = [row for row in log if not row["worker"]]
    workers = [row for row in log if row["worker"]]
    assert len(free) == 1 and len(workers) == counts["deep_checked"]
    budget_of = {row["argv"][row["argv"].index("--model") + 1] for row in log}
    assert budget_of == {DEFAULT_MODEL}
    assert all(row["env"]["PI_OFFLINE"] == "1" and row["credential"] for row in log)
    assert all(row["env"]["PI_CODING_AGENT_DIR"].endswith("/pi-agent") for row in log)
    assert outcome.run["usage"]["total"]["calls"] == len(fake.bodies)


@pytest.mark.slow
def test_a_queue_larger_than_the_unit_check_budget_runs_the_rating_and_the_pace(rig, write_repo) -> None:
    repo = write_repo(many_modules(12))
    outcome, fake = rig.audit(repo, max_tokens=600_000, state=rig.base / "state")
    assert outcome.exit_code == 0
    kinds = fake.kinds()
    assert kinds.count("rating") == 2  # 36 units in batches of 30
    record = json.loads((rig.base / "state" / ".local" / "state" / "review" / "funnel-run.json").read_text())
    assert record["rating"]["ran"] is True and record["pacing"]["large_queue"] is True
    assert record["repository"]["large"] is True and record["repository"]["reason"] == "queue"


@pytest.mark.slow
def test_multi_llm_roles_reach_the_calls_and_the_sessions(rig, write_repo, tmp_path: Path) -> None:
    config = tmp_path / "multi.toml"
    config.write_text('[models]\ndefault = "z-ai/glm-5.3-flash"\nunit_check = "vendor/small"\ndeep_check = "vendor/large"\n')
    repo = write_repo(WEBAPP)
    outcome, fake = rig.audit(repo, config_file=config)
    assert outcome.exit_code == 0
    models_by_kind: dict[str, set[str]] = {}
    for body in fake.bodies:
        payload = json.loads(body)
        models_by_kind.setdefault(kind_of(payload), set()).add(payload["model"])
    assert models_by_kind["unit-check"] == {"vendor/small"} and models_by_kind["verify"] == {"z-ai/glm-5.3-flash"}
    # The generic policy of an unknown model: no reasoning effort and no provider route.
    small = next(json.loads(body) for body in fake.bodies if json.loads(body)["model"] == "vendor/small")
    assert "reasoning" not in small and "provider" not in small and small["max_completion_tokens"] == 32_768
    log = rig.pi_log()
    worker_models = {row["model"] for row in log if row["worker"]}
    free_models = {row["model"] for row in log if not row["worker"]}
    assert worker_models == {"vendor/large"} and free_models == {"z-ai/glm-5.3-flash"}
    catalog = log[0]["config"]["models.json"]["providers"]["openrouter"]["models"]
    assert next(entry["id"] for entry in catalog) == "z-ai/glm-5.3-flash"
    assert "benchmarked_configuration" not in outcome.run and outcome.run["models"]["unit_check"] == "vendor/small"
