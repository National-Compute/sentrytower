"""Honest results: provider refusals, failed calls, engine crashes, failed checks, unverified findings and the result sentences."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from fakes import MODEL, FakeModel, kind_of, sse, usage_of
from sentrytower import audit
from sentrytower.audit import AuditRequest, Log, engine_crash, run_audit
from sentrytower.budget import STANDARD_TOKENS
from sentrytower.config import load_config
from sentrytower.gateway import PROVIDER_REFUSED_TYPE, GatewayConfig, ModelGateway, provider_message
from sentrytower.policies import DEFAULT_MODEL, resolve_policies
from sentrytower.result import (
    FAILED_SHARE_MIN_CALLS,
    STOP_DONE,
    calls_record,
    failed_calls_failure,
    phase0_failure,
    provider_failure,
    result_lines,
    sessions_failure,
    stop_text,
    units_failure,
)
from synthetic import WEBAPP, counted_files, line_of

KEY = "provider-key-that-must-never-leak-0123456789"
REQUEST = {"model": MODEL, "messages": [{"role": "user", "content": "Audit this code for security vulnerabilities."}]}
_READ = line_of(WEBAPP, "files.py", "def read")
FREE_ANSWER = {
    "findings": [
        {
            "title": "Path traversal in read",
            "locations": [{"path": "files.py", "line_start": _READ, "line_end": _READ}],
            "cwe": ["CWE-22"],
            "severity": "high",
            "evidence": "open(name)",
            "exploit_conditions": "../",
        }
    ]
}


def _gateway(transport: Any) -> ModelGateway:
    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    return ModelGateway(config, transport=transport, sleep=lambda _: None)


def _call(gateway: ModelGateway) -> tuple[int, dict[str, Any]]:
    status, _, body, _ = gateway.handle("/chat/completions", {"authorization": f"Bearer {gateway.token}"}, json.dumps(REQUEST).encode())
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {}


@pytest.mark.parametrize("status", [401, 402, 403, 404])
def test_a_provider_refusal_ends_the_upstream_calls_of_the_run(status: int) -> None:
    fake = FakeModel(statuses=[status])
    with _gateway(fake.transport) as gateway:
        first, _ = _call(gateway)
        second, answer = _call(gateway)
        third, _ = _call(gateway)
        totals = gateway.totals()["total"]
    # The refused attempt gets no retry, and each later request gets the status at once, with no upstream call.
    assert first == second == third == status and len(fake.bodies) == 1
    assert answer["error"]["type"] == PROVIDER_REFUSED_TYPE
    assert (totals["upstream_calls"], totals["failures"], totals["blocked"]) == (1, 1, 2)
    # An upstream 402 (no credit) is not a budget refusal of the gateway.
    assert totals["budget_refusals"] == 0 and totals["provider_error"]["status"] == status
    assert totals["failed_by"] == {f"HTTP {status}": 1}


def test_the_provider_message_is_short_and_holds_no_key_and_no_request_text() -> None:
    body = json.dumps({"error": {"message": f"Invalid key {KEY}\nfor this\x07 account " + "x" * 300}}).encode()
    message = provider_message(body, KEY, "the code of the request")
    assert message is not None and KEY not in message and "\x07" not in message and "\n" not in message and len(message) <= 200
    assert message.startswith("Invalid key [key] for this account")
    # A message that repeats a part of the request could hold code: it is left out.
    echo = json.dumps({"error": {"message": "flagged input: def secret_function(argument_one, argument_two)"}}).encode()
    assert provider_message(echo, KEY, "line 7: def secret_function(argument_one, argument_two):") is None
    assert provider_message(b"not json", KEY, "") is None


def test_a_failed_call_is_counted_by_the_outcome_of_its_last_attempt() -> None:
    outcomes = iter([(400, "text/plain", b"bad request"), *[(500, "application/json", b'{"error": {"message": "x"}}')] * 3])

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        return next(outcomes)

    with _gateway(transport) as gateway:
        assert _call(gateway)[0] == 400
        assert _call(gateway)[0] == 500
        totals = gateway.totals()["total"]
    assert totals["failed_by"] == {"HTTP 400": 1, "HTTP 500": 1} and totals["upstream_calls"] == 2 and totals["attempts"] == 4
    assert totals["provider_error"] is None


def test_more_than_a_fifth_of_failed_calls_from_ten_calls_on_makes_a_run_incomplete() -> None:
    assert calls_record({"upstream_calls": 40, "failures": 12}) == {"total": 40, "failed": 12, "failed_share": 0.3}
    failure = failed_calls_failure({"total": 40, "failed": 12}, {"HTTP 429": 9, "HTTP 500": 2, "malformed answer": 1})
    assert failure == "12 of 40 model calls failed (30%, more than 20%): HTTP 429 (9), HTTP 500 (2), malformed answer (1)."
    assert failed_calls_failure({"total": 40, "failed": 8}, {}) is None
    # A small run does not trip on one failure.
    assert failed_calls_failure({"total": FAILED_SHARE_MIN_CALLS - 1, "failed": 3}, {}) is None
    assert failed_calls_failure({"total": 0, "failed": 0}, {}) is None


def test_a_run_whose_calls_all_failed_is_incomplete_from_one_call_on() -> None:
    assert failed_calls_failure({"total": 4, "failed": 4}, {"HTTP 400": 4}) == "4 of 4 model calls failed: HTTP 400 (4)."
    assert failed_calls_failure({"total": 1, "failed": 1}, {}) == "1 of 1 model call failed."
    assert failed_calls_failure({"total": 20, "failed": 20}, {"HTTP 400": 20}) == (
        "20 of 20 model calls failed (100%, more than 20%): HTTP 400 (20)."
    )


def test_a_funnel_that_did_not_check_its_units_or_lost_its_sessions_is_incomplete() -> None:
    # No unit checked of the units to check: the checks failed, or none ran (the budget refused each one).
    assert units_failure({"checked": 0, "failed": 13, "total": 13}) == "No code unit was checked: 13 of 13 unit checks failed."
    assert units_failure({"checked": 0, "failed": 0, "total": 13}) == "No code unit was checked: the run had 13 code units to check."
    # More than 20% of the tried unit checks failed, from 10 tried checks on.
    assert units_failure({"checked": 8, "failed": 3, "total": 400}) == "3 of 11 unit checks failed (27%, more than 20%)."
    assert units_failure({"checked": 8, "failed": 2, "total": 400}) is None
    assert units_failure({"checked": 5, "failed": 4, "total": 400}) is None
    assert units_failure({"checked": 0, "failed": 0, "total": 0}) is None
    assert units_failure({"checked": 0, "failed": 0, "total": None}) is None
    # More than half of the agent sessions ended without an answer.
    assert sessions_failure({"answered": 1, "failed": 12}) == "12 of 13 agent sessions ended without an answer."
    assert sessions_failure({"answered": 0, "failed": 1}) == "1 of 1 agent session ended without an answer."
    assert sessions_failure({"answered": 2, "failed": 2}) is None
    assert sessions_failure({"answered": 0, "failed": 0}) is None
    # Phase 0: "failed" (also after a kill at its deadline) is no inventory; a partial inventory holds units.
    assert phase0_failure({"status": "failed", "error": "deadline"}) == "Phase 0, the inventory of the code units, failed (deadline)."
    assert phase0_failure({"status": "failed"}) == "Phase 0, the inventory of the code units, failed."
    assert phase0_failure({"status": "complete"}) is phase0_failure({"status": "partial"}) is phase0_failure({}) is None
    # An engine that ended on its own does not say that it finished the work of an incomplete run.
    done: dict[str, Any] = {
        "route": "funnel",
        "detail": "queue-empty",
        "cap_usd": 2.0,
        "tokens": STANDARD_TOKENS,
        "wall_clock_seconds": 3600,
    }
    assert stop_text(STOP_DONE, **done).startswith("The run finished its work")
    assert stop_text(STOP_DONE, **done, incomplete=True) == "The engine ended, but its work is incomplete."


def test_the_failure_of_a_provider_refusal_says_what_to_do() -> None:
    assert provider_failure(401, MODEL, "SENTRYTOWER_API_KEY") == "The provider refused the key (HTTP 401): check SENTRYTOWER_API_KEY."
    assert provider_failure(402, MODEL, None) == "The provider account has no credit (HTTP 402): add credit, then run again."
    # HTTP 404: a wrong base URL or model, or on OpenRouter a route that no provider serves under its data policy.
    assert provider_failure(404, MODEL, None) == (
        f"The endpoint answered HTTP 404 for {MODEL}: check the model and --base-url; "
        "on OpenRouter, no provider of the route may serve the model under its data policy."
    )
    assert "keychain" in provider_failure(403, MODEL, "keychain")


def test_an_engine_crash_is_an_exit_or_a_record_that_the_stop_does_not_explain() -> None:
    record = {"stop": {"reason": "queue-empty"}}
    assert engine_crash(0, None, kind="funnel", record=record) is None
    assert engine_crash(-9, None, kind="funnel", record=record) == "the funnel engine ended with exit code -9"
    assert "wrote no readable record" in str(engine_crash(1, None, kind="funnel", record=None))
    # The parent stopped the engine: the exit code and a missing record are no crash.
    assert engine_crash(-9, "wall-clock", kind="funnel", record=None) is None
    assert engine_crash(143, "provider-error", kind="deep", record=None) is None
    # The agent runner exits with the code of its last Pi process (-15 after a stop at a limit is 241).
    assert engine_crash(241, None, kind="agent", record={"exit": -15, "stopped": "token-limit"}) is None
    assert engine_crash(1, None, kind="agent", record={"exit": 0}) == "the agent runner ended with exit code 1"
    assert "did not start" in str(engine_crash(70, None, kind="agent", record={"exit": 70, "error": "FileNotFoundError: pi"}))


def test_the_result_sentences_state_the_spend_the_stop_and_the_units() -> None:
    result = {
        "status": "incomplete",
        "stop_text": "The run finished its work: no code unit, lead or finding was left to check.",
        "failure": "12 of 40 model calls failed (30%, more than 20%): HTTP 429 (12).",
        "spent_usd": 1.234,
        "cap_usd": 2.0,
        "units": {"kind": "code units", "checked": 120, "failed": 3, "total": 400},
        "depth_factor": 1.0,
        "preview": False,
    }
    assert result_lines(result) == [
        "Spent $1.23 of the $2.00 cost cap.",
        "The run finished its work: no code unit, lead or finding was left to check.",
        "Checked 120 of 400 code units; 3 could not be checked.",
        "The run is incomplete. 12 of 40 model calls failed (30%, more than 20%): HTTP 429 (12).",
    ]
    agent = {
        **result,
        "status": "complete",
        "failure": None,
        "spent_usd": None,
        "cap_usd": None,
        "preview": True,
        "depth_factor": 5.0,
        "units": {"kind": "agent sessions", "checked": 4, "failed": 1, "total": 6, "files_read": 87},
    }
    lines = result_lines(agent)
    assert lines[0] == "The provider reported no cost and the prices are not known; the run had no cost cap."
    assert lines[2] == "4 of 6 agent sessions gave an answer; 1 ended without one; the agents read 87 files."
    assert lines[3] == "Depth 5 times the standard run (preview: more checks; effect on findings not yet measured)."


class Refusing:
    """An upstream that answers each call with one status, and records when each call arrived."""

    def __init__(self, status: int) -> None:
        self.status = status
        self.times: list[float] = []
        self.lock = threading.Lock()

    def transport(self, url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        with self.lock:
            self.times.append(time.time())
        return self.status, "application/json", json.dumps({"error": {"message": "refused", "code": self.status}}).encode()


@pytest.mark.slow
@pytest.mark.parametrize("status", [401, 402])
def test_a_refused_key_or_an_empty_account_fails_the_run_with_exit_4(rig, write_repo, status: int) -> None:
    upstream = Refusing(status)
    environment = rig.env()
    config = load_config(None, environment=environment)
    request = AuditRequest(repository=write_repo(WEBAPP), out_dir=rig.base / "out")
    started = time.monotonic()
    outcome = run_audit(config, request, log=Log(quiet=True), environment=environment, transport=upstream.transport)
    assert outcome.exit_code == 4 and time.monotonic() - started < 60
    result = outcome.run["result"]
    assert result["status"] == outcome.run["status"] == "failed" and result["stop_reason"] == "provider-error"
    assert f"(HTTP {status})" in result["failure"] and f"(HTTP {status})" in result["stop_text"]
    # The refused calls counted no token: the run spent nothing, and the report says so.
    assert result["spent_usd"] == 0.0 and "Spent $0.00 of the $2.00 cost cap." in (rig.base / "out" / "report.md").read_text()
    # The calls that were in flight at the refusal reached the provider; no call after it did.
    refused_at = outcome.run["usage"]["total"]["provider_error"]["at"]
    assert upstream.times and all(moment <= refused_at + 0.5 for moment in upstream.times)
    assert len(upstream.times) <= 8 and outcome.run["usage"]["total"]["blocked"] >= 0
    report = (rig.base / "out" / "report.md").read_text()
    assert "The run failed." in report and f"HTTP {status}" in report
    assert json.loads((rig.base / "out" / "findings.json").read_text())["run"]["result"]["status"] == "failed"


@pytest.mark.slow
def test_an_endpoint_that_answers_404_fails_the_run_with_both_causes(rig, write_repo) -> None:
    # For example a local endpoint with a wrong base URL: each call gets HTTP 404.
    outcome, _ = rig.audit(write_repo(WEBAPP), fake=Refusing(404))  # type: ignore[arg-type]
    result = outcome.run["result"]
    assert outcome.exit_code == 4 and result["status"] == "failed" and result["stop_reason"] == "provider-error"
    assert result["failure"] == provider_failure(404, DEFAULT_MODEL, None) and "--base-url" in result["failure"]
    assert "The run failed. The endpoint answered HTTP 404 for" in (rig.base / "out" / "report.md").read_text()


class Flaky:
    """An upstream that fails some calls for good (HTTP 400 without an error body: no retry) and answers the rest."""

    def __init__(self, fails: Any) -> None:
        self.fake = FakeModel()
        self.fails = fails
        self.count = 0
        self.lock = threading.Lock()
        self.failed: list[dict[str, Any]] = []

    def transport(self, url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        payload = json.loads(body)
        with self.lock:
            self.count += 1
            fail = self.fails(self.count, payload)
            if fail:
                self.failed.append(payload)
        if fail:
            return 400, "text/plain", b"bad request"
        return self.fake.transport(url, body, headers, timeout)


@pytest.mark.slow
def test_a_run_with_30_percent_failed_calls_is_incomplete(rig, write_repo) -> None:
    upstream = Flaky(lambda count, _: count % 10 in (1, 4, 7))
    outcome, _ = rig.audit(write_repo(WEBAPP), fake=upstream, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(FREE_ANSWER)})  # type: ignore[arg-type]
    result = outcome.run["result"]
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and result["calls"]["total"] >= 10
    assert result["calls"]["failed_share"] > 0.2 and "model calls failed" in result["failure"] and "HTTP 400" in result["failure"]


class Prose(FakeModel):
    """A model that answers each unit check in prose (a refusal or a format slip): HTTP 200 and a usage report, no JSON."""

    def respond(self, body: bytes) -> tuple[int, str, bytes]:
        payload = json.loads(body)
        if kind_of(payload) != "unit-check":
            return super().respond(body)
        with self.lock:
            self.bodies.append(body)
        text = "I cannot help with this code."
        return 200, "text/event-stream", sse(payload["model"], text, usage_of(body, text))


@pytest.mark.slow
def test_a_funnel_run_that_checked_no_code_unit_is_incomplete(rig, write_repo) -> None:
    outcome, _ = rig.audit(write_repo(WEBAPP), fake=Prose())
    result = outcome.run["result"]
    # The calls succeeded, but no answer of a unit check can be read.
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and result["calls"]["failed"] == 0
    assert result["failure"] == "No code unit was checked: 13 of 13 unit checks failed."
    # The engine ended on its own: the stop stays "done", and no output says that the run finished its work.
    assert result["stop_reason"] == "done" and result["stop_text"] == "The engine ended, but its work is incomplete."
    report = (rig.base / "out" / "report.md").read_text()
    assert "The run finished its work" not in report and "The run is incomplete. No code unit was checked" in report


@pytest.mark.slow
def test_a_funnel_run_whose_agent_sessions_gave_no_answer_is_incomplete(rig, write_repo) -> None:
    outcome, _ = rig.audit(write_repo(WEBAPP), extra_env={"FAKE_PI_MODE": "silent"})
    result = outcome.run["result"]
    failed = result["sessions"]["failed"]
    # Each unit is checked, but the free-roaming session and each deep check end without an answer.
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and result["units"]["checked"] == 13
    assert result["sessions"]["answered"] == 0 and failed >= 2
    assert result["failure"] == f"{failed} of {failed} agent sessions ended without an answer."


@pytest.mark.slow
def test_a_funnel_run_whose_inventory_failed_is_incomplete(rig, write_repo, tmp_path: Path) -> None:
    settings = tmp_path / "phase0.toml"
    # Phase 0 gets no time: the funnel stops it at its deadline.
    settings.write_text("[funnel]\nphase0_max_seconds = 0\nphase0_grace_seconds = 0\n")
    outcome, _ = rig.audit(write_repo(WEBAPP), config_file=settings)
    result = outcome.run["result"]
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and outcome.run["engine"]["phase0"]["status"] == "failed"
    assert result["failure"] == "Phase 0, the inventory of the code units, failed (deadline)."


@pytest.mark.slow
def test_a_small_run_whose_calls_all_failed_is_incomplete(rig, write_repo) -> None:
    upstream = Flaky(lambda count, _: True)
    outcome, _ = rig.audit(write_repo({"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"}), fake=upstream)  # type: ignore[arg-type]
    result = outcome.run["result"]
    calls = result["calls"]["total"]
    # Fewer than 10 calls: the failed share does not apply, but no call succeeded.
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and 0 < calls < FAILED_SHARE_MIN_CALLS
    assert result["failure"] == f"{calls} of {calls} model call{'s' if calls != 1 else ''} failed: HTTP 400 ({calls})."


@pytest.mark.slow
def test_a_unit_check_that_fails_twice_is_not_a_checked_unit(rig, write_repo) -> None:
    upstream = Flaky(lambda _, payload: kind_of(payload) == "unit-check" and "File: files.py" in payload["messages"][-1]["content"])
    state = rig.base / "state"
    outcome, _ = rig.audit(write_repo(WEBAPP), fake=upstream, state=state)  # type: ignore[arg-type]
    counts = json.loads((state / ".local" / "state" / "review" / "summary.json").read_text())["funnel"]
    failed = counts["unit_checks_failed"]
    # Each unit of files.py: its call and the one requeue failed, so it is not checked.
    assert failed >= 1 and len(upstream.failed) == 2 * failed
    assert counts["checked"] + failed == counts["units_to_check"] == 13
    units = outcome.run["result"]["units"]
    assert units == {"kind": "code units", "checked": 13 - failed, "failed": failed, "total": 13}
    assert f"Checked {13 - failed} of 13 code units; {failed} could not be checked." in (rig.base / "out" / "report.md").read_text()


@pytest.mark.slow
def test_an_engine_crash_makes_the_run_incomplete(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    real = audit._run_engine

    def killed(*args: Any, **kwargs: Any) -> tuple[int | None, str | None]:
        _, stopped = real(*args, **kwargs)
        return -9, stopped

    monkeypatch.setattr(audit, "_run_engine", killed)
    outcome, _ = rig.audit(write_repo(WEBAPP))
    result = outcome.run["result"]
    assert outcome.exit_code == 4 and result["status"] == "incomplete" and result["stop_reason"] == "engine-error"
    assert result["failure"] == "the funnel engine ended with exit code -9"


@pytest.mark.slow
def test_a_finding_whose_verification_failed_stays_with_a_label(rig, write_repo) -> None:
    upstream = Flaky(lambda _, payload: kind_of(payload) == "verify")
    outcome, _ = rig.audit(write_repo(WEBAPP), fake=upstream, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(FREE_ANSWER)})  # type: ignore[arg-type]
    deep = [finding for finding in outcome.findings if finding.engine == "deep-check"]
    assert deep and all(finding.verification_status == "unverified" for finding in deep)
    assert all(finding.verification_reason == "the verification call failed" for finding in deep)
    free = [finding for finding in outcome.findings if finding.engine == "free-roaming"]
    assert free and free[0].verification_status == "none"
    document = json.loads((rig.base / "out" / "findings.json").read_text())
    entry = next(item for item in document["findings"] if item["engine"] == "deep-check")
    assert entry["verification"]["status"] == "unverified" and entry["verification"]["reason"] == "the verification call failed"
    assert "- Verification: unverified: the verification call failed" in (rig.base / "out" / "report.md").read_text()
    assert "unverified: the verification call failed" in (rig.base / "out" / "report.html").read_text()
    sarif = json.loads((rig.base / "out" / "findings.sarif").read_text())
    properties = [result["properties"] for result in sarif["runs"][0]["results"]]
    assert any(item["verification"] == "unverified" and item["verificationReason"] for item in properties)


SLICE_ANSWER = {
    "findings": [
        {
            "title": "Command injection in the runner",
            "locations": [{"path": "api/app.js", "line_start": 3, "line_end": 3}],
            "cwe": ["CWE-78"],
            "severity": "critical",
            "evidence": "runner.exec(dir)",
            "exploit_conditions": "The dir.",
        },
    ]
}


@pytest.mark.slow
def test_ctrl_c_during_a_deep_agent_run_keeps_the_finished_slice_findings(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    files = {**counted_files(1001), "api/app.js": WEBAPP["static/app.js"], "lib/files.py": WEBAPP["files.py"]}
    base = {"findings": [{**FREE_ANSWER["findings"][0], "locations": [{"path": "lib/files.py", "line_start": 52, "line_end": 52}]}]}
    state = rig.base / "state"
    record_file = state / ".local" / "state" / "review" / "deep.json"
    totals, raised = ModelGateway.totals, []

    def interrupting(self: ModelGateway) -> dict[str, Any]:
        # Ctrl-C while the verification of a finished slice waits for the model.
        try:
            entries = json.loads(record_file.read_text()).get("findings") or []
        except (OSError, ValueError):
            entries = []
        if not raised and any(entry.get("status") in ("waiting", "verifying") for entry in entries):
            raised.append(1)
            raise KeyboardInterrupt
        return totals(self)

    monkeypatch.setattr(audit, "PROGRESS_SECONDS", 0.3)
    monkeypatch.setattr(ModelGateway, "totals", interrupting)
    # No cost cap (0): the token ceiling of three standard runs buys the slices.
    outcome, _ = rig.audit(
        write_repo(files),
        fake=FakeModel(delays={"verify": 30}),
        max_tokens=3 * STANDARD_TOKENS,
        max_cost_usd=0,
        wall_clock_seconds=3600,
        state=state,
        extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(base), "FAKE_PI_SLICE_ANSWER": json.dumps(SLICE_ANSWER)},
    )
    assert raised and outcome.exit_code == 130 and outcome.run["result"]["status"] == "interrupted"
    assert [finding.title for finding in outcome.findings] == ["Path traversal in read", "Command injection in the runner"]
    kept = outcome.findings[1]
    assert kept.verification_status == "unverified" and kept.verification_reason


@pytest.mark.slow
def test_each_output_states_the_spend_the_stop_and_the_checked_units(rig, write_repo) -> None:
    environment = rig.env(FAKE_PI_FREE_ANSWER=json.dumps(FREE_ANSWER))
    stream = io.StringIO()
    config = load_config(None, environment=environment, max_cost_usd=2.0)
    request = AuditRequest(repository=write_repo(WEBAPP), out_dir=rig.base / "out")
    outcome = run_audit(config, request, log=Log(stream=stream), environment=environment, transport=FakeModel(cost=0.001).transport)
    result = outcome.run["result"]
    assert outcome.exit_code == 0 and result["status"] == "complete" and result["stop_reason"] == "done"
    assert result["cap_usd"] == 2.0 and result["spent_usd"] == pytest.approx(0.001 * result["calls"]["total"], rel=1e-6)
    assert result["units"] == {"kind": "code units", "checked": 13, "failed": 0, "total": 13} and result["failure"] is None
    lines = result_lines(result)
    assert lines[0].startswith("Spent $0.") and lines[0].endswith("of the $2.00 cost cap.") and lines[2] == "Checked 13 of 13 code units."
    out = rig.base / "out"
    report, page = (out / "report.md").read_text(), (out / "report.html").read_text()
    assert all(f"- {line}" in report for line in lines) and all(line in page for line in lines)
    assert (
        json.loads((out / "findings.json").read_text())["run"]["result"] == result == json.loads((out / "run.json").read_text())["result"]
    )
    # The last lines of the plain log.
    assert [line.split("] ", 1)[1] for line in stream.getvalue().splitlines()[-3:]] == lines
