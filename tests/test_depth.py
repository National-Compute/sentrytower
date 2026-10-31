"""A budget of more than one standard run buys depth: the ceilings, the counts, the passes, the votes and the slices."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from sentrytower.agent import deep, pi
from sentrytower.agent.answer import read_findings
from sentrytower.agent.deep import Scope, answer_places, make_slices, same_place, source_files
from sentrytower.budget import STANDARD_TOKENS, depth_factor, funnel_parameters, parallel_sessions
from sentrytower.findings import ENGINE_AGENT, from_agent
from sentrytower.funnel.pacing import Parameters
from sentrytower.funnel.protocols import combine_votes
from sentrytower.funnel.resolve import Finding, select_output
from sentrytower.funnel.workers import SessionOutcome
from sentrytower.gateway import GatewayConfig, ModelGateway, http_transport
from sentrytower.policies import DEEPSEEK_V41_FLASH, canonical_json
from synthetic import WEBAPP, counted_files, line_of


def test_the_depth_factor_counts_standard_runs_and_never_goes_below_one() -> None:
    assert depth_factor(5_000_000) == depth_factor(STANDARD_TOKENS) == 1.0
    assert depth_factor(3 * STANDARD_TOKENS) == 3.0


def test_a_standard_budget_keeps_the_funnel_parameters_and_a_larger_one_scales_them() -> None:
    assert funnel_parameters(STANDARD_TOKENS, {}) == {}
    base = Parameters()
    scaled = funnel_parameters(4 * STANDARD_TOKENS, {})
    assert scaled["max_unit_checks"] == 4 * base.max_unit_checks and scaled["verify_max_findings"] == 4 * base.verify_max_findings
    # The size of one deep check grows with the square root; the counts with the factor.
    assert scaled["worker_tokens"] == 2 * base.worker_tokens and scaled["worker_seconds"] == 2 * base.worker_seconds
    assert scaled["extra_findings_total"] == 18 and scaled["extra_findings_per_file"] == 2
    assert scaled["depth_passes"] is True and scaled["verify_votes"] == 3 and scaled["focus_tokens"] == 12_000_000
    assert scaled["max_concurrency"] > scaled["max_workers"] >= base.max_workers
    # A value of the [funnel] settings stays.
    assert "max_unit_checks" not in funnel_parameters(4 * STANDARD_TOKENS, {"max_unit_checks": 10})
    Parameters.from_record({**base.record(), **scaled}).check()


def test_parallel_sessions_grow_with_the_budget_within_the_computer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.cpu_count", lambda: 10)
    assert parallel_sessions(STANDARD_TOKENS) == 4
    assert parallel_sessions(2 * STANDARD_TOKENS) == 8
    assert parallel_sessions(50 * STANDARD_TOKENS) == 10


def test_the_votes_give_the_majority_verdict_and_the_mean_score() -> None:
    exploitable = {"verdict": "exploitable", "keep_score": 0.9, "guard_quote": ""}
    safe = {"verdict": "safe", "keep_score": 0.1, "guard_quote": "if ok:"}
    combined = combine_votes([exploitable, exploitable, safe])
    assert combined["verdict"] == "exploitable" and combined["keep_score"] == pytest.approx(0.6333, abs=1e-4)
    assert combined["votes"] == ["exploitable", "exploitable", "safe"]
    assert combine_votes([exploitable, safe])["verdict"] == "unclear"
    assert combine_votes([safe]) == {**safe, "votes": ["safe"]}


def _finding(identifier: str, path: str, line: int, verdict: str, score: float) -> Finding:
    finding = Finding(
        id=identifier,
        source="deep-check",
        order=line,
        title="t",
        severity="high",
        evidence="",
        exploit_conditions="",
        cwe=["CWE-78"],
        reported=[],
        locations=[{"path": path, "line_start": line, "line_end": line}],
    )
    finding.verify = {"verdict": verdict, "keep_score": score}
    return finding


def test_only_an_exploitable_majority_takes_the_extra_output_slots() -> None:
    # Eight unclear findings rank first (a higher score); six exploitable ones come after them.
    findings = [_finding(f"U{index}", f"u{index}.py", 100, "unclear", 0.95) for index in range(8)]
    findings += [_finding(f"E{index}", f"e{index}.py", 100, "exploitable", 0.6) for index in range(6)]
    standard, _ = select_output(findings, Parameters())
    assert [item.id for item in standard] == [f"U{index}" for index in range(6)]
    deep, removed = select_output(findings, Parameters(extra_findings_total=4, extra_findings_per_file=1))
    # The first 6 slots go by rank; the 4 extra slots only to findings that the votes call exploitable.
    assert [item.id for item in deep] == [*(f"U{index}" for index in range(6)), "E0", "E1", "E2", "E3"]
    assert {entry["id"] for entry in removed} == {"U6", "U7", "E4", "E5"}
    one_file = [_finding(f"G{index}", "app.py", 100 * (index + 1), "exploitable", 0.9) for index in range(5)]
    kept, _ = select_output(one_file, Parameters(extra_findings_total=4, extra_findings_per_file=1))
    assert len(kept) == 3


def test_slices_split_the_largest_folders_and_merge_to_the_count() -> None:
    files = [(f"src/api/h{index}.py", 1000) for index in range(6)] + [(f"src/core/c{index}.py", 1000) for index in range(3)]
    files += [("src/main.py", 500), ("lib/util.py", 400), ("setup.py", 100)]
    assert make_slices(files, 1) == [[Scope("", True)]]
    slices = make_slices(files, 4)
    assert len(slices) == 4
    scopes = [scope for group in slices for scope in group]
    # Each file is in exactly one scope of exactly one slice.
    for path, _ in files:
        owners = [
            scope
            for scope in scopes
            if (scope.recursive and (not scope.path or path.startswith(scope.path + "/")))
            or (not scope.recursive and path.rsplit("/", 1)[0] == scope.path if "/" in path else not scope.recursive and scope.path == "")
        ]
        assert len(owners) == 1, path
    assert len(make_slices(files, 50)) < 50 and make_slices([], 3) == [] and make_slices(files, 0) == []


def test_source_files_leave_out_tests_docs_and_vendored_code(write_repo) -> None:
    files = {"src/app.py": "x = 1\n", "tests/test_app.py": "x = 1\n", "docs/index.md": "# docs\n", "vendor/lib.js": "x\n"}
    repo = write_repo({**files, "README.md": "# r\n", "src/web/view.js": "x\n"})
    assert sorted(path for path, _ in source_files(repo)) == ["src/app.py", "src/web/view.js"]


def test_same_place_is_one_file_within_the_radius() -> None:
    assert same_place(("a.py", 10, 12), ("a.py", 20, 20), 10) and not same_place(("a.py", 10, 12), ("a.py", 30, 30), 10)
    assert not same_place(("a.py", 10, 10), ("b.py", 10, 10), 10)


class _Slow(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        try:
            if self.path == "/stall":
                time.sleep(1.5)
            for _ in range(6):
                self.wfile.write(b'data: {"choices": [{"delta": {"content": "x"}}]}\n\n')
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"data: [DONE]\n\n")
        except OSError:
            # The client gave up (the timeout of the test).
            pass


@pytest.fixture
def slow_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_the_timeout_is_the_longest_wait_for_a_byte_not_the_whole_answer(slow_server: str) -> None:
    # The answer takes about 1.2 s, with a byte every 0.2 s: a timeout of 0.6 s does not end it.
    status, kind, body = http_transport(slow_server + "/stream", b"{}", {"content-type": "application/json"}, 0.6)
    assert status == 200 and "event-stream" in kind and body.count(b"data:") == 7
    with pytest.raises(TimeoutError):
        http_transport(slow_server + "/stall", b"{}", {"content-type": "application/json"}, 0.6)


def test_the_gateway_counts_the_calls_that_end_at_the_ceiling() -> None:
    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        answer = {
            "choices": [{"finish_reason": "length", "message": {"content": "x"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 65_536, "total_tokens": 65_546},
        }
        return 200, "application/json", canonical_json(answer)

    config = GatewayConfig(base_url="https://example.invalid/v1", api_key="k", policies={DEEPSEEK_V41_FLASH.model_id: DEEPSEEK_V41_FLASH})
    with ModelGateway(config, transport=transport) as gateway:
        body = json.dumps({"model": DEEPSEEK_V41_FLASH.model_id, "messages": []}).encode()
        gateway.handle("/chat/completions", {"authorization": f"Bearer {gateway.token}"}, body)
        totals = gateway.totals()
    assert totals["total"]["length_stops"] == 1 and totals["models"][DEEPSEEK_V41_FLASH.model_id]["length_stops"] == 1


FREE = {
    "findings": [
        {
            "title": "Path traversal in read",
            "locations": [{"path": "files.py", "line_start": 52, "line_end": 52}],
            "cwe": ["CWE-22"],
            "severity": "high",
            "evidence": "open(name)",
            "exploit_conditions": "../ in the name.",
        },
    ]
}


@pytest.mark.slow
def test_a_deep_funnel_run_starts_the_focus_sessions_the_sweep_and_the_votes(rig, write_repo) -> None:
    repo = write_repo(WEBAPP)
    state = rig.base / "state"
    # $8 buys four standard runs of the default model.
    outcome, fake = rig.audit(
        repo, max_cost_usd=8.0, wall_clock_seconds=3600, state=state, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(FREE)}
    )
    assert outcome.exit_code == 0 and outcome.run["route"] == "funnel"
    record = json.loads((state / ".local" / "state" / "review" / "funnel-run.json").read_text())
    assert record["parameters"]["depth_passes"] is True and record["parameters"]["verify_votes"] == 3
    counts = record["counts"]
    # The seven lenses, and a deep check for each checked unit without a lead.
    assert counts["focus_started"] == 7 and counts["sweep_started"] >= 1
    assert counts["verify_votes"] >= 2 * counts["verified"] > 0
    log = rig.pi_log()
    focus = [row for row in log if not row["worker"] and row["argv"][-1].startswith("This session has one focus")]
    assert len(focus) == 7 and all(row["argv"][-1].count("Inspect this repository for security vulnerabilities") == 1 for row in focus)
    assert outcome.run["budget"]["depth_factor"] == 4.0
    # The completion ceiling of a call is the ceiling of its policy at every depth.
    assert outcome.run["budget"]["completion_ceilings"] == {DEEPSEEK_V41_FLASH.model_id: 65_536}
    bodies = [json.loads(body) for body in fake.bodies]
    verify = [body for body in bodies if body["messages"][0]["content"].startswith("You examine one claim")]
    assert verify and all(body["max_completion_tokens"] == 65_536 for body in bodies)
    agent = json.loads((state / ".local" / "share" / "pi-agent" / "models.json").read_text())
    assert [model["maxTokens"] for model in agent["providers"]["openrouter"]["models"]] == [65_536]


@pytest.mark.slow
def test_a_deep_agent_run_audits_slices_and_keeps_the_verified_new_findings(rig, write_repo) -> None:
    # The code is in two folders: two slices.
    files = {**counted_files(1001), "api/app.js": WEBAPP["static/app.js"], "lib/files.py": WEBAPP["files.py"]}
    exec_line = line_of(WEBAPP, "static/app.js", "runner.exec(")
    repo = write_repo(files)
    other = {
        "findings": [
            {
                "title": "Command injection in the runner",
                "locations": [{"path": "api/app.js", "line_start": exec_line, "line_end": exec_line}],
                "cwe": ["CWE-78"],
                "severity": "critical",
                "evidence": "runner.exec(dir)",
                "exploit_conditions": "The dir.",
            },
            {
                "title": "The same traversal",
                "locations": [{"path": "lib/files.py", "line_start": 54, "line_end": 54}],
                "cwe": ["CWE-22"],
                "severity": "high",
                "evidence": "open(name)",
                "exploit_conditions": "../",
            },
        ]
    }
    base = {"findings": [{**FREE["findings"][0], "locations": [{"path": "lib/files.py", "line_start": 52, "line_end": 52}]}]}
    state = rig.base / "state"
    # $6 buys three standard runs; the money plans the slices, and the repository has code in two folders.
    outcome, _ = rig.audit(
        repo,
        max_cost_usd=6.0,
        wall_clock_seconds=3600,
        state=state,
        extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(base), "FAKE_PI_SLICE_ANSWER": json.dumps(other)},
    )
    assert outcome.exit_code == 0 and outcome.run["route"] == "agent"
    record = json.loads((state / ".local" / "state" / "review" / "deep.json").read_text())
    # The whole-repository session, then one slice session for each folder with code.
    assert record["planned_slices"] == 2 and len(record["slices"]) == 2 and outcome.run["result"]["depth_factor"] == 3.0
    assert outcome.run["budget"]["completion_ceilings"] == {DEEPSEEK_V41_FLASH.model_id: 65_536}
    statuses = [entry["status"] for entry in record["findings"]]
    # The second slice repeats the findings of the first; the traversal repeats the base session.
    assert statuses.count("duplicate") == 3 and statuses.count("kept") == 1
    titles = [finding.title for finding in outcome.findings]
    assert titles == ["Path traversal in read", "Command injection in the runner"]
    assert outcome.findings[1].confidence is not None and outcome.findings[1].verification["votes"] == ["exploitable"] * 3
    assert outcome.run["engine"]["slices"]["ran"] == 2 and outcome.run["engine"]["slices"]["findings"]["kept"] == 1
    slice_prompts = [row["argv"][-1] for row in rig.pi_log() if row["argv"][-1].startswith("This session audits one slice")]
    assert len(slice_prompts) == 2


def test_a_slice_finding_keeps_each_location_that_the_output_reads(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    forms: dict[str, dict[str, Any]] = {
        "schema": {"locations": [{"path": "app/views.py", "line_start": 12, "line_end": 14}]},
        "line alias": {"locations": [{"path": "app/views.py", "line": 12}]},
        "file alias": {"locations": [{"file": "app/views.py", "line_start": 12}]},
        "line as text": {"locations": [{"path": "app/views.py", "line_start": "12"}]},
        "path:N": {"locations": [{"path": "app/views.py:12"}]},
        "one object": {"locations": {"path": "app/views.py", "line_start": 12}},
        "top level": {"path": "app/views.py", "line_start": 12},
        "absolute": {"locations": [{"path": f"{repository}/app/views.py", "line_start": 12}]},
        "dot folder": {"locations": [{"path": "./.github/workflows/ci.yml", "line_start": 7}]},
        "no location": {"locations": [{"path": "app/views.py"}]},
    }
    document = {"findings": [{"title": name, **form} for name, form in forms.items()]}
    places = answer_places(document, repository)
    # Each form that the output reads gives the same place; a path keeps its leading dot.
    assert places == {
        0: ("app/views.py", 12, 14),
        **dict.fromkeys(range(1, 8), ("app/views.py", 12, 12)),
        8: (".github/workflows/ci.yml", 7, 7),
    }
    found, _ = read_findings(document, cwd=str(repository), roots=(str(repository),))
    output = [from_agent(item, rank=1, route="agent", engine=ENGINE_AGENT).locations for item in found]
    assert places == {index: (spots[0].path, spots[0].start_line, spots[0].end_line) for index, spots in enumerate(output) if spots}


SLICE_ALIASES = {
    "findings": [
        {
            "title": "Command injection in the runner",
            "locations": {"file": "./api/app.js", "line": str(line_of(WEBAPP, "static/app.js", "runner.exec("))},
            "cwe": ["CWE-78"],
            "severity": "critical",
            "evidence": "runner.exec(dir)",
            "exploit_conditions": "The dir.",
        }
    ]
}


def _deep_audit(
    rig, write_repo, *, wall_clock_seconds: int = 3600, slice_answer: dict[str, Any] | None = None
) -> tuple[Any, dict[str, Any]]:
    """A deep run of the agent route: no cost cap, the token ceiling of three standard runs, two folders with code."""
    files = {**counted_files(1001), "api/app.js": WEBAPP["static/app.js"], "lib/files.py": WEBAPP["files.py"]}
    base = {"findings": [{**FREE["findings"][0], "locations": [{"path": "lib/files.py", "line_start": 52, "line_end": 52}]}]}
    state = rig.base / "state"
    answers = {"FAKE_PI_FREE_ANSWER": json.dumps(base), "FAKE_PI_SLICE_ANSWER": json.dumps(slice_answer or SLICE_ALIASES)}
    outcome, _ = rig.audit(
        write_repo(files),
        max_tokens=3 * STANDARD_TOKENS,
        max_cost_usd=0,
        wall_clock_seconds=wall_clock_seconds,
        state=state,
        extra_env=answers,
    )
    return outcome, json.loads((state / ".local" / "state" / "review" / "deep.json").read_text())


@pytest.mark.slow
def test_a_deep_agent_run_keeps_a_slice_finding_with_location_aliases(rig, write_repo) -> None:
    outcome, record = _deep_audit(rig, write_repo)
    # The first slice keeps the finding (one location object, a file alias, a line as text); the second repeats it.
    assert [entry["status"] for entry in record["findings"]] == ["kept", "duplicate"]
    assert record["findings"][0]["location"][0] == "api/app.js"
    slice_finding = outcome.findings[-1]
    assert slice_finding.title == "Command injection in the runner" and slice_finding.tier == 2
    assert slice_finding.verification_status == "verified" and slice_finding.locations[0].path == "api/app.js"


@pytest.mark.slow
def test_a_deep_agent_run_that_skipped_slices_for_lack_of_time_stops_on_the_wall_clock(rig, write_repo) -> None:
    # Ten minutes: no slice session starts with less time than that left.
    outcome, record = _deep_audit(rig, write_repo, wall_clock_seconds=600)
    assert record["planned_slices"] == 2 and [entry.get("skipped") for entry in record["slices"]] == ["time", "time"]
    result = outcome.run["result"]
    assert record["stop"] == "time-stop" and result["stop_reason"] == "wall-clock" and result["status"] == "complete"
    assert "finished its work" not in result["stop_text"] and "each slice session ended" not in result["stop_text"]


class _EndedSlice:
    """A slice session that ended; a SIGTERM cuts the first reading of its outcome."""

    def __init__(self, folder: Path, document: dict[str, Any]) -> None:
        self.name = "slice-001"
        self.session_dir = folder
        self.extra: dict[str, Any] = {}
        self.process = type("Ended", (), {"poll": staticmethod(lambda: 0)})()
        self.document = document
        self.reads = 0

    def outcome(self) -> SessionOutcome:
        self.reads += 1
        if self.reads == 1:
            raise deep.Terminated
        return SessionOutcome(exit=0, tokens=10, seconds=1.0, runner=None, document=self.document)

    def running(self) -> bool:
        return False


def test_a_sigterm_while_a_slice_is_collected_keeps_its_findings(tmp_path: Path) -> None:
    command = pi.agent_command(
        pi_cli=tmp_path / "pi",
        session_directory=tmp_path / "sessions",
        agent_directory=tmp_path / "agent",
        model=DEEPSEEK_V41_FLASH.model_id,
        prompt="p",
        final="f",
        token_budget=STANDARD_TOKENS,
        wall_clock_seconds=3600,
    )
    spec = deep.Spec(
        repository=tmp_path,
        work_dir=tmp_path,
        base_session_dir=tmp_path / "sessions",
        token_ceiling=3 * STANDARD_TOKENS,
        wall_clock_seconds=3600,
        session_tokens=STANDARD_TOKENS,
        max_sessions=4,
        agent_command=command,
        agent_env=[],
        model_base_url="http://127.0.0.1:9",
        agent_model=DEEPSEEK_V41_FLASH.model_id,
        verify_model=DEEPSEEK_V41_FLASH.model_id,
        completion_ceilings={DEEPSEEK_V41_FLASH.model_id: 65_536},
        verify_votes=3,
        dedup_radius_lines=10,
    )
    engine = deep.Deep(spec)
    session = _EndedSlice(tmp_path / "slice", {"findings": [{"title": "t", "locations": [{"path": "app.py", "line": 3}]}]})
    engine.sessions.append(session)  # type: ignore[arg-type]
    engine.record["slices"].append({"name": session.name, "status": "running"})
    with pytest.raises(deep.Terminated):
        engine.slice_ended(session)  # type: ignore[arg-type]
    # The stop collects the slice that the signal cut: its finding stays.
    engine.stop()
    assert [(entry["status"], entry.get("location")) for entry in engine.record["findings"]] == [("waiting", ["app.py", 3, 3])]
    assert engine.record["slices"][0]["status"] == "ended" and engine.record["stop"] == "terminated"
    # A signal after the entries reached the record, before the session counted as collected: no second entry.
    session.extra.pop("collected")
    engine.slice_ended(session, verify=False)  # type: ignore[arg-type]
    assert len(engine.record["findings"]) == 1


def _option(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


@pytest.mark.slow
@pytest.mark.parametrize("route", ["funnel", "agent"])
def test_each_task_session_is_the_agent_command_with_its_own_folders(route: str, rig, write_repo) -> None:
    state = rig.base / "state"
    if route == "funnel":
        repo = write_repo(WEBAPP)
        answer = {"FAKE_PI_FREE_ANSWER": json.dumps(FREE)}
        outcome, _ = rig.audit(repo, max_cost_usd=8.0, wall_clock_seconds=3600, state=state, extra_env=answer)
        parameters = json.loads((state / ".local" / "state" / "review" / "funnel-run.json").read_text())["parameters"]
        budgets = {"t": parameters["worker_tokens"], "s": parameters["worker_tokens"], "f": parameters["focus_tokens"]}
    else:
        repo = write_repo({**counted_files(1001), "api/app.js": WEBAPP["static/app.js"], "lib/files.py": WEBAPP["files.py"]})
        outcome, _ = rig.audit(repo, max_cost_usd=6.0, wall_clock_seconds=3600, state=state)
        budgets = {"slice": STANDARD_TOKENS}
    assert outcome.exit_code == 0 and outcome.run["route"] == route
    rows = [row for row in rig.pi_log() if not row["final"]]
    # The whole-repository session runs the command of the single agent in the folders of the run.
    [whole] = [row for row in rows if _option(row["argv"], "--session-dir").endswith("/.local/share/pi-sessions")]
    plain_sessions, agent = _option(whole["argv"], "--session-dir"), whole["env"]["PI_CODING_AGENT_DIR"]
    kinds = []
    for row in rows:
        if row is whole:
            continue
        # A task session: the same command with its own session folder, its own copy of the agent folder and its prompt.
        sessions = Path(_option(row["argv"], "--session-dir"))
        folder = sessions.parent
        copy = str(folder / "pi-agent")
        expected = [str(sessions) if part == plain_sessions else part.replace(agent + "/", copy + "/", 1) for part in whole["argv"][:-1]]
        assert row["argv"][:-1] == expected and row["cwd"] == whole["cwd"] == str(repo)
        assert row["env"] == {"PI_CODING_AGENT_DIR": copy, "PI_PACKAGE_DIR": copy + "/pi-package", "PI_OFFLINE": "1"}
        assert all(row["extension_exists"]) and row["credential"] and row["path"] == whole["path"]
        kind = folder.name[0] if folder.parent.name == "tasks" else folder.parent.name[:-1]
        limits = json.loads((sessions / "runner.json").read_text())["limits"]
        assert limits["token_budget"] == budgets[kind] and limits["wall_clock_seconds"] > 0
        kinds.append(kind)
    assert len({str(Path(_option(row["argv"], "--session-dir"))) for row in rows}) == len(rows)
    assert set(kinds) == set(budgets)
