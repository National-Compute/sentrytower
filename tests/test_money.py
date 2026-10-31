"""Money buys depth: the hold waits, the soft stop at 85% of the cap, dollars end the run, the default cap and the tiers."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import fakes
from fakes import MODEL, FakeModel, fake_pi_package, fake_tools, read_jsonl
from sentrytower import audit
from sentrytower.agent import pi
from sentrytower.budget import price_per_million
from sentrytower.cli import main
from sentrytower.findings import ENGINE_DEEP, OutputFinding, OutputLocation
from sentrytower.funnel.pacing import Parameters
from sentrytower.funnel.resolve import FOCUS_SOURCE, FREE_SOURCE, SWEEP_SOURCE, Finding, select_output
from sentrytower.gateway import GatewayConfig, ModelGateway
from sentrytower.policies import DEEPSEEK_V41_FLASH, resolve_policies
from sentrytower.report import markdown_report
from sentrytower.result import PREVIEW_LABEL
from synthetic import WEBAPP, counted_files, many_modules

REQUEST = {"model": MODEL, "messages": [{"role": "user", "content": "Audit this code for security vulnerabilities."}]}


def _post(gateway: ModelGateway) -> int:
    status, _, _, _ = gateway.handle("/chat/completions", {"authorization": f"Bearer {gateway.token}"}, json.dumps(REQUEST).encode())
    return status


def test_the_hold_waits_for_the_calls_in_flight_and_refuses_only_near_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = resolve_policies([MODEL])[MODEL]
    # The worst case of one attempt (131,072 output tokens of GLM 5.3 Flash) is about $0.018; its real cost is $0.002.
    worst = policy.cost_estimate(len(json.dumps(REQUEST)) // 3 + 100, policy.max_completion_tokens) or 0.0
    cap = 0.1
    calls, seen, lock = [0], [], threading.Lock()

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        with lock:
            calls[0] += 1
            number = calls[0]
        time.sleep(0.05)
        if number % 7 == 0:
            # A transient failure: the retry releases its reservation before it waits again.
            return 503, "application/json", b'{"error": {"message": "busy"}}'
        answer = {
            "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60, "cost": 0.002},
        }
        return 200, "application/json", json.dumps(answer).encode()

    refuse = ModelGateway._refuse

    def recording(self: ModelGateway, policy: Any, reason: str) -> Any:
        seen.append(self.budget_state()["spent_usd"])
        return refuse(self, policy, reason)

    monkeypatch.setattr(ModelGateway, "_refuse", recording)
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key="k", policies=resolve_policies([MODEL]), max_cost_usd=cap, max_parallel_requests=40
    )
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as gateway:
        threads = [threading.Thread(target=_post, args=(gateway,)) for _ in range(70)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        totals = gateway.totals()["total"]
    # Forty calls at once fit five worst cases: the others waited, none was refused while money was left for one.
    assert not any(thread.is_alive() for thread in threads)
    assert seen and min(seen) >= cap - worst - 1e-9 and totals["budget_refusals"] == len(seen)
    assert totals["cost_usd"] < cap and totals["cost_usd"] >= cap - worst - 0.002


def test_the_hold_waits_at_most_its_limit() -> None:
    def slow(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        time.sleep(1.0)
        answer = {
            "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
        }
        return 200, "application/json", json.dumps(answer).encode()

    policy = resolve_policies([MODEL])[MODEL]
    worst = policy.cost_estimate(100, policy.max_completion_tokens) or 0.0
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1",
        api_key="k",
        policies=resolve_policies([MODEL]),
        max_cost_usd=worst * 1.5,
        hold_wait_seconds=0.2,
    )
    with ModelGateway(config, transport=slow) as gateway:
        first = threading.Thread(target=_post, args=(gateway,))
        first.start()
        time.sleep(0.1)
        started = time.monotonic()
        # One worst case fits; the second waits for the first, at most 0.2 s, then the budget refuses it.
        assert _post(gateway) == 402 and time.monotonic() - started < 0.9
        first.join()


def test_the_hold_ends_before_a_client_gives_up_on_its_call() -> None:
    from sentrytower.agent.deep import VERIFY_TIMEOUT_SECONDS
    from sentrytower.gateway import HOLD_WAIT_SECONDS

    # Else a call that waits in the hold goes upstream after its client gave up, and its retry pays a second time.
    assert HOLD_WAIT_SECONDS < min(Parameters().call_timeout_seconds, VERIFY_TIMEOUT_SECONDS)


DEEPSEEK = {DEEPSEEK_V41_FLASH.model_id: DEEPSEEK_V41_FLASH}
# A unit check, and an agent call with a context of about 400,000 tokens (1.2 MB of session JSON).
SMALL = json.dumps({"model": DEEPSEEK_V41_FLASH.model_id, "messages": [{"role": "user", "content": "unit check " * 300}]}).encode()
BIG = json.dumps({"model": DEEPSEEK_V41_FLASH.model_id, "messages": [{"role": "user", "content": "x" * 1_200_000}]}).encode()


def _answer(cost: float) -> tuple[int, str, bytes]:
    usage = {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100, "cost": cost}
    return (
        200,
        "application/json",
        json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}], "usage": usage}).encode(),
    )


def _send(gateway: ModelGateway, body: bytes) -> int:
    status, _, _, _ = gateway.handle("/chat/completions", {"authorization": f"Bearer {gateway.token}"}, body)
    return status


def _worst(body: bytes) -> float:
    return DEEPSEEK_V41_FLASH.cost_estimate(-(-len(body) // 3), DEEPSEEK_V41_FLASH.max_completion_tokens) or 0.0


def test_the_hold_serves_the_waiting_calls_in_the_order_of_arrival() -> None:
    order: list[str] = []
    entered, release = threading.Event(), threading.Event()

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        order.append("big" if len(body) > 100_000 else "small")
        if len(order) == 1:
            entered.set()
            release.wait(30)
        return _answer(0.001)

    # Two unit checks fit together; the agent call fits only alone, and nothing fits next to it.
    cap = _worst(SMALL) + _worst(BIG) - 0.01
    assert 2 * _worst(SMALL) < cap and _worst(BIG) + 0.001 < cap
    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key="k", policies=DEEPSEEK, max_cost_usd=cap)
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as gateway:
        statuses: dict[str, int] = {}

        def send(name: str, body: bytes) -> threading.Thread:
            thread = threading.Thread(target=lambda: statuses.__setitem__(name, _send(gateway, body)))
            thread.start()
            return thread

        first = send("first", SMALL)
        assert entered.wait(10)
        big = send("big", BIG)
        time.sleep(0.2)
        # A later unit check that fits next to the first one queues behind the agent call that waits.
        late = send("late", SMALL)
        time.sleep(0.2)
        assert order == ["small"]
        release.set()
        for thread in (first, big, late):
            thread.join(30)
    assert order == ["small", "big", "small"] and statuses == {"first": 200, "big": 200, "late": 200}


def test_a_long_agent_call_is_served_in_order_and_a_deep_run_spends_to_its_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    # The probe of the review: a $10 run, 24 unit-check loops in parallel and agent calls with a long context.
    # Before the order of arrival, an agent call starved in the hold, and its refusal stopped the run far below the cap.
    cap = 10.0
    costs = iter([9.2])
    fast = threading.Event()
    refused_at: list[float] = []
    refuse = ModelGateway._refuse

    def recording(self: ModelGateway, policy: Any, reason: str) -> Any:
        refused_at.append(self.budget_state()["spent_usd"])
        return refuse(self, policy, reason)

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        time.sleep(0.02)
        return _answer(next(costs, 0.005 if fast.is_set() else 0.0002))

    monkeypatch.setattr(ModelGateway, "_refuse", recording)
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1",
        api_key="k",
        policies=DEEPSEEK,
        max_cost_usd=cap,
        max_parallel_requests=24,
        hold_wait_seconds=2.0,
    )
    agent: list[tuple[int, float]] = []
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as gateway:
        assert _send(gateway, SMALL) == 200

        def unit_checks() -> None:
            while _send(gateway, SMALL) == 200:
                pass

        threads = [threading.Thread(target=unit_checks) for _ in range(24)]
        for thread in threads:
            thread.start()
        # The unit checks in flight hold more than the cap leaves ($9.20 is spent): the hold binds from here on.
        time.sleep(0.3)
        for _ in range(5):
            started = time.monotonic()
            agent.append((_send(gateway, BIG), time.monotonic() - started))
        # Then the unit checks spend the rest of the cap.
        fast.set()
        for thread in threads:
            thread.join(60)
        spent = gateway.budget_state()["spent_usd"]
    assert not any(thread.is_alive() for thread in threads)
    # Each agent call got its turn in the hold at once, long before the hold limit.
    assert all(status == 200 and waited < 1.0 for status, waited in agent), agent
    # The first refusal came only at the cap, less one agent call: the run spent its cap.
    assert refused_at and min(refused_at) >= cap - _worst(BIG) - 1e-9 and cap - _worst(BIG) - 0.01 <= spent < cap


def test_a_provider_refusal_refuses_each_waiting_call_at_once() -> None:
    calls, release = [], threading.Event()

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        calls.append(time.monotonic())
        release.wait(30)
        return 401, "application/json", b'{"error": {"message": "invalid key"}}'

    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key="k", policies=DEEPSEEK, max_cost_usd=1.5 * _worst(SMALL), hold_wait_seconds=30
    )
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as gateway:
        statuses: list[int] = []
        first = threading.Thread(target=lambda: statuses.append(_send(gateway, SMALL)))
        first.start()
        time.sleep(0.2)
        # The second call waits in the hold for the first one, which the provider refuses.
        waiting = threading.Thread(target=lambda: statuses.append(_send(gateway, SMALL)))
        waiting.start()
        time.sleep(0.2)
        released = time.monotonic()
        release.set()
        first.join(10)
        waiting.join(10)
        totals = gateway.totals()["total"]
    assert statuses == [401, 401] and time.monotonic() - released < 5
    # The waiting call never went upstream: one call reached the provider, the other was blocked.
    assert len(calls) == 1 and (totals["upstream_calls"], totals["blocked"], totals["budget_refusals"]) == (1, 1, 0)


def test_the_stop_of_the_gateway_refuses_each_waiting_call() -> None:
    calls, release = [], threading.Event()

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        calls.append(time.monotonic())
        release.wait(30)
        return _answer(0.001)

    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key="k", policies=DEEPSEEK, max_cost_usd=1.5 * _worst(SMALL), hold_wait_seconds=30
    )
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as gateway:
        statuses: list[int] = []
        first = threading.Thread(target=lambda: statuses.append(_send(gateway, SMALL)))
        first.start()
        time.sleep(0.2)
        waiting = threading.Thread(target=lambda: statuses.append(_send(gateway, SMALL)))
        waiting.start()
        time.sleep(0.2)
        # The run ends while a call waits in the hold: it is refused at once, and it never goes upstream later.
        gateway.stop()
        waiting.join(5)
        assert statuses == [503] and not waiting.is_alive()
        release.set()
        first.join(10)
    assert statuses == [503, 200] and len(calls) == 1


def test_the_budget_endpoint_gives_the_money_and_the_soft_stop_with_the_credential_only() -> None:
    fake = FakeModel(cost=0.03)
    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key="k", policies=resolve_policies([MODEL]), max_cost_usd=0.1)
    with ModelGateway(config, transport=fake.transport, sleep=lambda _: None) as gateway:
        import urllib.error
        import urllib.request

        from sentrytower.limits import read_budget

        before = read_budget(gateway.url, gateway.token)
        for _ in range(3):
            _post(gateway)
        after = read_budget(gateway.url, gateway.token)
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(gateway.url + "/budget", timeout=5)
    assert refused.value.code == 401
    assert before is not None and before["stop"] is False and before["cap_usd"] == 0.1 and before["soft_stop_usd"] == pytest.approx(0.085)
    # 3 x $0.03 is past 85% of $0.10: no new work may start.
    assert after is not None and after["spent_usd"] == pytest.approx(0.09) and after["stop"] is True and after["reason"] == "budget"


def test_a_run_that_its_token_ceiling_ends_has_no_soft_stop() -> None:
    fake = FakeModel(cost=0.03)
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key="k", policies=resolve_policies([MODEL]), max_cost_usd=0.1, soft_stop_fraction=None
    )
    with ModelGateway(config, transport=fake.transport, sleep=lambda _: None) as gateway:
        for _ in range(3):
            _post(gateway)
        state = gateway.budget_state()
    # 3 x $0.03 is past 85% of $0.10, but only the cap itself limits this run.
    assert state["stop"] is False and state["soft_stop_usd"] is None and state["spent_usd"] == pytest.approx(0.09)


def test_the_standard_run_keeps_the_measured_pacing_under_the_default_cap(rig, write_repo) -> None:
    outcome, _ = rig.audit(write_repo(WEBAPP))
    budget, result = outcome.run["budget"], outcome.run["result"]
    assert result["cap_usd"] == 2.0 and result["depth_factor"] == 1.0 and result["preview"] is False
    assert budget["token_ceiling_source"] == "standard run" and budget["gateway_token_ceiling"] == 20_000_000
    # No soft stop: the funnel stops new work at 90% of the 20M ceiling, as in the measured run; $2 is an upper limit.
    assert budget["soft_stop_usd"] is None


@pytest.mark.slow
def test_the_agent_route_keeps_the_soft_stop_at_each_cap(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    gateways: list[GatewayConfig] = []

    class Recording(ModelGateway):
        def __init__(self, config: GatewayConfig, **options: Any) -> None:
            gateways.append(config)
            super().__init__(config, **options)

    monkeypatch.setattr(audit, "ModelGateway", Recording)
    # --depth quick on a large repository: the standard run of the agent route (20M tokens, about $0.47 at the estimate).
    # When the real price is higher, the soft stop lets the agent write its answer before the cap refuses its calls.
    outcome, _ = rig.audit(write_repo(counted_files(1001), name="large"), max_cost_usd=0.5)
    budget = outcome.run["budget"]
    assert outcome.run["route"] == "agent" and budget["token_ceiling_source"] == "standard run" and outcome.exit_code == 0
    assert gateways[-1].soft_stop_fraction == 0.85 and budget["soft_stop_usd"] == pytest.approx(0.425)
    # The standard run of the funnel keeps the measured pacing: no soft stop.
    outcome, _ = rig.audit(write_repo(WEBAPP, name="small"))
    assert outcome.run["route"] == "funnel" and outcome.run["budget"]["token_ceiling_source"] == "standard run"
    assert gateways[-1].soft_stop_fraction is None and outcome.run["budget"]["soft_stop_usd"] is None


class _Budget(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        pass

    def do_GET(self) -> None:
        body = json.dumps({"stop": True, "reason": "budget", "spent_usd": 1.7, "cap_usd": 2.0, "soft_stop_usd": 1.7}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_at_the_soft_stop_a_running_agent_session_gets_its_final_turn(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Budget)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cli = fake_pi_package(tmp_path / "pi")
        agent, sessions = tmp_path / "home" / "pi-agent", tmp_path / "home" / "pi-sessions"
        pi.write_agent_config(agent, "http://127.0.0.1:9", list(resolve_policies([MODEL]).values()))
        pi.prepare_agent_directory(agent, pi_cli=cli, tools=fake_tools(tmp_path / "tools"))
        command = pi.agent_command(
            pi_cli=cli,
            session_directory=sessions,
            agent_directory=agent,
            model=MODEL,
            prompt=pi.audit_prompt(),
            final=pi.final_message(),
            token_budget=1_000_000,
            wall_clock_seconds=600,
            budget_url=f"http://127.0.0.1:{server.server_address[1]}",
        )
        environment = {
            "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
            "FAKE_PI_LOG": str(tmp_path / "log.jsonl"),
            "FAKE_PI_SLEEP": "4",
            **pi.agent_environment(agent, agent / "pi-package", "c"),
        }
        started = time.monotonic()
        subprocess.run(command, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=120, check=False)
        runner = json.loads((sessions / "runner.json").read_text())
    finally:
        server.shutdown()
    # The first turn stops at the first reading of the money; the final turn writes the answer.
    assert runner["stopped"] == "budget" and runner["final_turn"] == "budget" and time.monotonic() - started < 60
    assert [row["final"] for row in read_jsonl(tmp_path / "log.jsonl")] == [False, True]


@pytest.mark.slow
def test_a_deep_run_with_cheap_tokens_spends_to_about_85_percent_of_the_cap(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    # Each direct call reports one million tokens at 2.5 times less than the token-mix estimate of the default model.
    estimate = price_per_million(DEEPSEEK_V41_FLASH, "funnel") or 0.0
    real = estimate / 2.5

    def usage(body_bytes: bytes, text: str) -> dict[str, Any]:
        return {"prompt_tokens": 900_000, "completion_tokens": 100_000, "total_tokens": 1_000_000, "cost": real}

    monkeypatch.setattr(fakes, "usage_of", usage)
    cap = 5.0
    state = rig.base / "state"
    # 90 units: more work than the cap buys, so the money ends the run.
    outcome, _ = rig.audit(write_repo(many_modules(30)), max_cost_usd=cap, wall_clock_seconds=3600, state=state)
    result = outcome.run["result"]
    # m = 2.5: the plan of 50M tokens costs 40% of the cap at the real price; the money ends the run at about 85%.
    assert result["depth_factor"] == 2.5 and result["preview"] is True and outcome.run["budget"]["gateway_token_ceiling"] is None
    assert 0.8 * cap <= result["spent_usd"] < cap and result["stop_reason"] == "budget"
    record = json.loads((state / ".local" / "state" / "review" / "funnel-run.json").read_text())
    assert record["counts"]["money_extensions"] >= 1 and record["budget"]["total_used"] > 50_000_000
    assert outcome.run["usage"]["total"]["budget_refusals"] == 0
    assert PREVIEW_LABEL in (rig.base / "out" / "report.md").read_text()


@pytest.mark.slow
def test_an_explicit_cap_without_prices_exits_2_before_the_run(
    rig, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name, value in rig.environment.items():
        monkeypatch.setenv(name, value)
    out = rig.base / "out"
    code = main(["audit", str(write_repo(WEBAPP)), "--out", str(out), "--model", "local/qwen", "--max-cost-usd", "3", "-q"])
    error = capsys.readouterr().err
    assert code == 2 and "local/qwen" in error and "[policies" in error and "--max-cost-usd 0" in error
    assert not rig.pi_log() and not (out / "run.json").exists()


@pytest.mark.slow
def test_a_cap_that_cannot_pay_for_one_call_exits_2_before_the_run(
    rig, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name, value in rig.environment.items():
        monkeypatch.setenv(name, value)
    out = rig.base / "out"
    # $0.03 is below one call of the default model at its completion ceiling (about $0.04): the gateway would refuse each call.
    code = main(["audit", str(write_repo(WEBAPP)), "--out", str(out), "--max-cost-usd", "0.03", "-q"])
    error = capsys.readouterr().err
    assert code == 2 and "cannot pay for one model call" in error and "at least $0.04" in error
    assert not rig.pi_log() and not (out / "run.json").exists()


def _candidate(identifier: str, source: str, path: str, line: int, votes: list[tuple[str, float]], *, order: int) -> Finding:
    finding = Finding(
        id=identifier,
        source=source,
        order=order,
        title=identifier,
        severity="high",
        evidence="",
        exploit_conditions="",
        cwe=["CWE-78"],
        reported=[],
        locations=[{"path": path, "line_start": line, "line_end": line}],
    )
    if votes:
        first, *_ = votes
        finding.first_verify = {"verdict": first[0], "keep_score": first[1]}
        verdicts = [verdict for verdict, _ in votes]
        majority = max(set(verdicts), key=verdicts.count)
        finding.verify = {
            "verdict": majority if 2 * verdicts.count(majority) > len(votes) else "unclear",
            "keep_score": sum(score for _, score in votes) / len(votes),
        }
    return finding


def _candidates() -> list[Finding]:
    findings = [
        _candidate("R001", FREE_SOURCE, "a.py", 10, [], order=1),
        _candidate("R002", FREE_SOURCE, "a.py", 40, [], order=2),
        # The first vote ranks tier 1; the mean of the votes ranks tier 2.
        _candidate("t1-1", "deep-check", "a.py", 100, [("exploitable", 0.9), ("safe", 0.1), ("safe", 0.1)], order=3),
        _candidate("t2-1", "deep-check", "b.py", 15, [("unclear", 0.4), ("exploitable", 0.95), ("exploitable", 0.95)], order=4),
        _candidate("t3-1", "nearby", "c.py", 5, [("exploitable", 0.7)] * 3, order=5),
        _candidate("t4-1", "deep-check", "d.py", 5, [("exploitable", 0.8)] * 3, order=6),
        _candidate("t5-1", "deep-check", "e.py", 5, [("exploitable", 0.6)] * 3, order=7),
        _candidate("t6-1", "deep-check", "f.py", 5, [("exploitable", 0.5)] * 3, order=8),
        _candidate("t7-1", "deep-check", "b.py", 60, [("exploitable", 0.99)] * 3, order=9),
        _candidate("t8-1", "deep-check", "b.py", 90, [("exploitable", 0.98)] * 3, order=10),
        _candidate("t9-1", "deep-check", "g.py", 5, [], order=11),
        # The passes of a deeper run: never tier 1, even with the best score.
        _candidate("f1-1", FOCUS_SOURCE, "h.py", 5, [("exploitable", 1.0)] * 3, order=12),
        _candidate("s1-1", SWEEP_SOURCE, "i.py", 5, [("exploitable", 0.99)] * 3, order=13),
        _candidate("s2-1", SWEEP_SOURCE, "j.py", 5, [("safe", 0.1)] * 3, order=14),
    ]
    return findings


def test_tier_1_is_the_standard_selection_of_the_same_candidates() -> None:
    deep = Parameters(extra_findings_total=6, extra_findings_per_file=1, verify_votes=3)
    kept, _ = select_output(_candidates(), deep)
    tier1 = [item.id for item in kept if item.output_tier == 1]
    tier2 = [item.id for item in kept if item.output_tier == 2]
    # The standard run: the same candidates without the passes, with the verdict of the first vote only.
    standard = []
    for item in _candidates():
        if item.source in (FOCUS_SOURCE, SWEEP_SOURCE):
            continue
        item.verify = item.first_verify
        standard.append(item)
    expected, _ = select_output(standard, Parameters())
    assert tier1 == [item.id for item in expected] and len(tier1) == 6
    # Tier 2 comes after tier 1 with further exploitable findings: the passes, and what the caps of tier 1 left.
    assert tier2 and set(tier2).isdisjoint(tier1) and [item.output_tier for item in kept] == [1] * len(tier1) + [2] * len(tier2)
    assert "f1-1" in tier2 and "s2-1" not in tier2 and "t1-1" not in tier2
    # The extra work never changes tier 1: the same selection without the extra slots.
    plain, _ = select_output(_candidates(), Parameters(verify_votes=3))
    assert [item.id for item in plain] == tier1


def test_the_reports_show_tier_2_after_tier_1_under_the_preview_label() -> None:
    def finding(rank: int, tier: int) -> OutputFinding:
        return OutputFinding(
            rank=rank,
            title=f"Finding {rank}",
            severity="high",
            cwe=["CWE-78"],
            locations=[OutputLocation("a.py", rank, rank)],
            evidence="e",
            exploit_conditions="",
            engine=ENGINE_DEEP,
            route="funnel",
            tier=tier,
            verification_status="verified",
        )

    run = {"route": "funnel", "status": "complete", "repository": {"name": "r", "files_counted": 3, "counted_up_to": 1001}}
    report = markdown_report([finding(1, 1), finding(2, 2)], run)
    assert report.index("### ST-001") < report.index(f"## More findings ({PREVIEW_LABEL})") < report.index("### ST-002")


def test_the_money_left_plans_the_slices_of_the_agent_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sentrytower.agent import deep

    command = pi.agent_command(
        pi_cli=tmp_path / "pi",
        session_directory=tmp_path / "sessions",
        agent_directory=tmp_path / "agent",
        model=MODEL,
        prompt="p",
        final="f",
        token_budget=20_000_000,
        wall_clock_seconds=3600,
    )
    spec = deep.Spec(
        repository=tmp_path,
        work_dir=tmp_path,
        base_session_dir=tmp_path / "sessions",
        token_ceiling=100_000_000,
        wall_clock_seconds=3600,
        session_tokens=20_000_000,
        max_sessions=4,
        agent_command=command,
        agent_env=[],
        model_base_url="http://127.0.0.1:9",
        agent_model=MODEL,
        verify_model=MODEL,
        completion_ceilings={MODEL: 1},
        verify_votes=3,
        dedup_radius_lines=10,
        money={"cap_usd": 10.0, "soft_stop_usd": 8.5, "price_per_million": 0.025, "extend": True},
    )
    state = {"spent_usd": 0.5, "tokens": 20_000_000, "soft_stop_usd": 8.5, "stop": False}
    monkeypatch.setattr(deep, "read_budget", lambda *_: dict(state))
    # $8 left before the soft stop, at the observed price ($0.50 for a session of 20M tokens): 15 slices with the verifications.
    assert deep.Deep(spec).slice_count(20_000_000) == 15
    # A price 2.5 times lower buys 2.5 times more slices: the money left sets the count.
    state.update(spent_usd=0.2)
    assert deep.Deep(spec).slice_count(20_000_000) == 39
    # Without the dollars at the end, the tokens left (80M, less the verifications) set the count, and at most the money.
    spec.money = {**(spec.money or {}), "extend": False}
    assert deep.Deep(spec).slice_count(20_000_000) == 3
    # At the soft stop no slice and no verification starts.
    state.update(stop=True)
    assert deep.Deep(spec).money_stopped() is True
