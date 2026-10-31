"""The rules of the real-model smoke of a release (scripts/release/smoke.py): when a run passes and when it fails."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("release_smoke", ROOT / "scripts" / "release" / "smoke.py")
assert _SPEC is not None and _SPEC.loader is not None
smoke = importlib.util.module_from_spec(_SPEC)
# The dataclasses of the script look up their module.
sys.modules[_SPEC.name] = smoke
_SPEC.loader.exec_module(smoke)
RUNS = {run.name: run for run in smoke.RUNS}


def _out(tmp_path: Path, **changes: Any) -> Path:
    """The outputs of a run that meets each rule of the standard run, with ``changes`` to its record."""
    values: dict[str, Any] = {
        "status": "complete",
        "stop_reason": "token-ceiling",
        "spent_usd": 1.62,
        "cap_usd": 2.0,
        "depth_factor": 1.0,
        "preview": False,
        "calls": {"total": 400, "failed": 8, "failed_share": 0.02},
        "units": {"kind": "code units", "checked": 180, "failed": 0, "total": 251},
        "route": "funnel",
        "provider_error": None,
        "token_ceiling_source": "standard run",
        "soft_stop_usd": None,
    }
    values.update(changes)
    out = tmp_path / "out"
    out.mkdir(parents=True)
    for name in smoke.OUTPUTS:
        (out / name).write_text("{}", encoding="utf-8")
    result = {key: values[key] for key in ("status", "stop_reason", "spent_usd", "cap_usd", "depth_factor", "preview", "calls", "units")}
    record = {
        "route": values["route"],
        "result": result,
        "usage": {"total": {"provider_error": values["provider_error"]}},
        "budget": {"token_ceiling_source": values["token_ceiling_source"], "soft_stop_usd": values["soft_stop_usd"]},
        "findings": {"count": 3},
    }
    (out / "run.json").write_text(json.dumps(record), encoding="utf-8")
    return out


def test_a_standard_run_that_meets_each_rule_passes(tmp_path: Path) -> None:
    problems, notes, summary = smoke.check(RUNS["standard-funnel"], 0, _out(tmp_path))
    assert problems == [] and notes == [] and summary["status"] == "complete"


def test_a_complete_run_without_calls_or_checked_units_is_falsely_clean(tmp_path: Path) -> None:
    out = _out(tmp_path, calls={"total": 0, "failed": 0, "failed_share": 0.0}, units={"kind": "code units", "checked": 0, "total": 251})
    problems, _, _ = smoke.check(RUNS["standard-funnel"], 0, out)
    assert "complete with no model call" in problems and "complete with no checked unit" in problems


def test_a_complete_run_with_failed_calls_or_a_provider_refusal_is_falsely_clean(tmp_path: Path) -> None:
    out = _out(tmp_path, calls={"total": 100, "failed": 30, "failed_share": 0.3}, provider_error={"status": 402})
    problems, _, _ = smoke.check(RUNS["standard-funnel"], 0, out)
    assert any("30% failed calls" in text for text in problems) and any("HTTP 402" in text for text in problems)


def test_a_run_above_its_cap_or_without_a_known_spend_fails(tmp_path: Path) -> None:
    problems, _, _ = smoke.check(RUNS["standard-funnel"], 0, _out(tmp_path / "over", spent_usd=2.01))
    assert any("above the cap" in text for text in problems)
    problems, _, _ = smoke.check(RUNS["standard-funnel"], 0, _out(tmp_path / "unknown", spent_usd=None))
    assert "a run with a cap reports no spend" in problems


def test_two_dollars_is_the_standard_run_and_ten_dollars_buys_a_preview_depth(tmp_path: Path) -> None:
    problems, _, _ = smoke.check(RUNS["standard-funnel"], 0, _out(tmp_path / "a", depth_factor=1.12, soft_stop_usd=1.7))
    assert any("depth factor 1.12" in text for text in problems) and any("not the standard run" in text for text in problems)
    deep = {
        "cap_usd": 10.0,
        "spent_usd": 8.9,
        "depth_factor": 5.0,
        "preview": True,
        "token_ceiling_source": "cost cap",
        "soft_stop_usd": 8.5,
    }
    problems, _, _ = smoke.check(RUNS["deep-funnel"], 0, _out(tmp_path / "b", **deep))
    assert problems == []
    problems, _, _ = smoke.check(RUNS["deep-funnel"], 0, _out(tmp_path / "c", **{**deep, "preview": False}))
    assert any("preview" in text for text in problems)
    # The standard run of the agent route keeps the soft stop at 85% of its cap.
    agent = {"route": "agent", "units": {"kind": "agent sessions", "checked": 1, "failed": 0, "total": 1}, "soft_stop_usd": 1.7}
    problems, _, _ = smoke.check(RUNS["standard-agent"], 0, _out(tmp_path / "d", **agent))
    assert problems == []
    problems, _, _ = smoke.check(RUNS["standard-agent"], 0, _out(tmp_path / "e", **{**agent, "soft_stop_usd": None}))
    assert any("not the standard run" in text for text in problems)


def test_a_refused_key_or_account_must_fail_with_exit_4(tmp_path: Path) -> None:
    refused = {
        "status": "failed",
        "stop_reason": "provider-error",
        "spent_usd": 0.0,
        "provider_error": {"status": 401},
        "calls": {"total": 1, "failed": 1, "failed_share": 1.0},
        "units": {"kind": "code units", "checked": 0, "total": 251},
    }
    problems, notes, _ = smoke.check(RUNS["invalid-key"], 4, _out(tmp_path / "a", **refused))
    assert problems == [] and notes == []
    problems, _, _ = smoke.check(RUNS["invalid-key"], 0, _out(tmp_path / "b", **{**refused, "status": "complete", "stop_reason": "done"}))
    assert any("must fail with exit 4" in text for text in problems)
    # Another refusal status is honest but unexpected: a note.
    _, notes, _ = smoke.check(
        RUNS["no-credit"], 4, _out(tmp_path / "c", **{**refused, "provider_error": {"status": 403}, "spent_usd": 0.004})
    )
    assert notes == ["the provider answered HTTP 403, expected 402"]


def test_the_docker_command_takes_the_key_from_the_environment_only(tmp_path: Path) -> None:
    run = RUNS["expensive-model"]
    argv = smoke.docker_argv(run, "sentrytower:smoke", tmp_path / "repo", tmp_path / "out", tmp_path / "x.toml", None)
    assert argv[argv.index("-e") + 1] == "SENTRYTOWER_API_KEY" and not any("=" in item and "KEY" in item for item in argv)
    assert ["--max-cost-usd", "1", "--model", smoke.EXPENSIVE_MODEL] == argv[argv.index("--max-cost-usd") : argv.index("--model") + 2]
    assert "--base-url" not in argv
    fake = smoke.docker_argv(
        RUNS["standard-funnel"], "sentrytower:smoke", tmp_path / "repo", tmp_path / "out", None, "http://host.docker.internal:1/v1"
    )
    assert fake[-2:] == ["--base-url", "http://host.docker.internal:1/v1"] and "--add-host=host.docker.internal:host-gateway" in fake


def test_all_lanes_start_each_run_at_once_and_one_lane_runs_the_short_runs_first() -> None:
    names = [run.name for run in smoke.RUNS]
    short = ["invalid-key", "no-credit", "standard-funnel", "standard-agent", "expensive-model"]
    assert smoke.lane_plan(names, "all") == [[name] for name in names]
    assert smoke.lane_plan(names, "2") == [["deep-funnel", "deep-agent"], short]
    assert smoke.lane_plan(names, "1") == [[*short, "deep-funnel", "deep-agent"]]
    assert smoke.lane_plan(["standard-funnel", "deep-agent"], "2") == [["deep-agent"], ["standard-funnel"]]
