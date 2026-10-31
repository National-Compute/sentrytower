"""Hardening: the repository guard, the scrubbed environment, robust parsing of untrusted input, interrupts and SARIF paths."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fakes import MODEL, FakeModel
from sentrytower import audit
from sentrytower.agent import pi
from sentrytower.agent.answer import read_findings
from sentrytower.audit import AuditError, engine_environment, write_outputs
from sentrytower.cli import main
from sentrytower.config import ConfigError, load_config
from sentrytower.findings import OutputFinding, OutputLocation
from sentrytower.gateway import GatewayConfig, ModelGateway, http_transport, proxy_problem
from sentrytower.policies import resolve_policies
from sentrytower.programs import program_environment, search_path, which
from sentrytower.sarif import sarif_document
from synthetic import counted_files

KEY = "provider-key-that-must-never-leak-0123456789"
REQUEST = {"model": MODEL, "messages": [{"role": "user", "content": "Audit this code for security vulnerabilities."}]}
SARIF_SCHEMA = Path(__file__).resolve().parent / "data" / "sarif-schema-2.1.0.json"
GUARD = Path(pi.__file__).resolve().parent / pi.GUARD_SOURCE


def _post(url: str, body: bytes, token: str) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url + "/chat/completions",
        data=body,
        method="POST",
        headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _raw(port: int, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def test_a_malformed_usage_report_releases_the_reservation_and_counts_nothing_wrong() -> None:
    answer = (
        b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],'
        b'"usage":{"prompt_tokens":"abc","completion_tokens":[1],"total_tokens":1e400,"cost":NaN}}'
    )
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]), max_total_tokens=400_000, max_cost_usd=1.0
    )
    with ModelGateway(config, transport=lambda *_: (200, "application/json", answer), sleep=lambda _: None) as server:
        for _ in range(4):
            code, _ = _post(server.url, json.dumps(REQUEST).encode(), server.token)
            assert code == 200
    # Each call reserves about 131,000 tokens: four calls fit only when each reservation is released.
    assert server._ledger.reserved_tokens == 0 and server._ledger.reserved_cost == 0
    total = server.totals()["total"]
    assert total["calls"] == 4 and total["total_tokens"] == 0 and total["cost_source"] == "estimate"


def test_an_unexpected_transport_error_is_a_failed_attempt() -> None:
    def transport(*_: Any) -> tuple[int, str, bytes]:
        raise OverflowError("timeout too large")

    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as server:
        code, body = _post(server.url, json.dumps(REQUEST).encode(), server.token)
    assert code == 502 and KEY.encode() not in body and server._ledger.reserved_tokens == 0
    assert server.totals()["total"]["attempts"] == 3 and server.totals()["total"]["failures"] == 1


def test_a_lone_surrogate_is_forwarded_as_a_json_escape() -> None:
    bodies: list[bytes] = []
    answer = b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":3}}'

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        bodies.append(body)
        return 200, "application/json", answer

    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    # Half of an emoji, as a truncation in the agent can leave it: valid JSON, no UTF-8 form.
    body = json.dumps(REQUEST).replace("vulnerabilities.", "vulnerabilities \\ud83d").encode()
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as server:
        code, _ = _post(server.url, body, server.token)
    assert code == 200 and len(bodies) == 1 and b"\\ud83d" in bodies[0]
    assert json.loads(bodies[0])["messages"][0]["content"].endswith("\ud83d")


def test_the_gateway_answers_before_it_reads_the_body_of_a_request_without_the_credential() -> None:
    fake = FakeModel()
    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    with ModelGateway(config, transport=fake.transport, sleep=lambda _: None) as server:
        port = int(server.url.rsplit(":", 1)[1])
        # A body of 1 GB is announced and never sent: the answer comes at once.
        refused = _raw(port, b"POST /chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000000\r\n\r\n")
        auth = f"Authorization: Bearer {server.token}\r\n".encode()
        bad_size = _raw(port, b"POST /chat/completions HTTP/1.1\r\nHost: x\r\n" + auth + b"Transfer-Encoding: chunked\r\n\r\nzz\r\n")
        negative = _raw(port, b"POST /chat/completions HTTP/1.1\r\nHost: x\r\n" + auth + b"Transfer-Encoding: chunked\r\n\r\n-5\r\n")
        length = _raw(port, b"POST /chat/completions HTTP/1.1\r\nHost: x\r\n" + auth + "Content-Length: ²\r\n\r\n".encode())
        chunked = json.dumps(REQUEST).encode()
        good = _raw(
            port,
            b"POST /chat/completions HTTP/1.1\r\nHost: x\r\n"
            + auth
            + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            + f"{len(chunked):x}\r\n".encode()
            + chunked
            + b"\r\n0\r\n\r\n",
        )
    assert refused.startswith(b"HTTP/1.1 401")
    assert bad_size.startswith(b"HTTP/1.1 400") and negative.startswith(b"HTTP/1.1 400") and length.startswith(b"HTTP/1.1 400")
    assert good.startswith(b"HTTP/1.1 200") and len(fake.bodies) == 1


def test_a_proxy_with_a_user_gets_proxy_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, str]] = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length") or 0))
            seen.append({"path": self.path, **{key.lower(): value for key, value in self.headers.items()}})
            data = b'{"ok": true}'
            self.send_response(200)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for name in ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("HTTP_PROXY", f"http://user:p%40ss@127.0.0.1:{server.server_address[1]}")
        monkeypatch.setenv("http_proxy", f"http://user:p%40ss@127.0.0.1:{server.server_address[1]}")
        status, _, body = http_transport("http://model.example/v1/chat/completions", b"{}", {"content-type": "application/json"}, 10)
    finally:
        server.shutdown()
    assert status == 200 and body == b'{"ok": true}'
    assert seen[0]["path"] == "http://model.example/v1/chat/completions"
    assert seen[0]["proxy-authorization"] == "Basic dXNlcjpwQHNz"  # user:p@ss
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:3128")
    monkeypatch.setenv("https_proxy", "https://proxy.example:3128")
    assert "not supported" in (proxy_problem("https://openrouter.ai/api/v1") or "")


@pytest.mark.parametrize(
    "text",
    [
        '[provider]\nbase_url = "http://"\n',
        '[provider]\nbase_url = "https://user:secret@example.com/v1"\n',
        '[provider]\nbase_url = "https://example.com:port/v1"\n',
        "[provider]\napi_key_env = []\n",
        '[provider]\napi_key_env = ["NOT A NAME"]\n',
        '[provider.headers]\nX-Api-Key = "x"\n',
        '[provider.headers]\napi-key = "x"\n',
        '[provider.headers]\nx-goog-api-key = "x"\n',
        "[tools]\npi = 5\n",
        '[policies."z-ai/glm-5.3-flash"]\nattempt_timeout_seconds = inf\n',
        '[policies."z-ai/glm-5.3-flash"]\ninput_cost_per_million = nan\n',
        '[policies."vendor/model"]\noutput_cost_per_million = -1.0\n',
    ],
)
def test_an_unsafe_or_invalid_value_is_a_configuration_error(tmp_path: Path, text: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(text)
    with pytest.raises(ConfigError) as error:
        load_config(path, environment={})
    assert "secret" not in str(error.value)


def test_a_file_that_is_not_utf8_and_a_number_that_is_not_ascii_are_configuration_errors(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b'[models]\ndefault = "\xff"\n')
    with pytest.raises(ConfigError):
        load_config(path, environment={})
    with pytest.raises(ConfigError):
        load_config(None, environment={"SENTRYTOWER_MAX_TOKENS": "²"})


def test_line_numbers_and_cwe_numbers_from_a_model_cannot_break_the_reading() -> None:
    huge = "9" * 5000
    document = {
        "findings": [
            {"title": "a", "locations": [{"path": "a.py", "line_start": "²", "line_end": huge}], "cwe": ["CWE-" + huge, "²"]},
            {"title": "b", "locations": [{"path": "b.py:" + huge}, {"path": "c.py", "line": huge + "-" + huge}], "cwe": huge},
            {"title": "c", "locations": [{"path": "d.py", "line_start": 1e300, "line_end": float("inf")}], "cwe": ["CWE-79"]},
            {"title": "d", "locations": [{"path": "e.py", "line_start": 12, "line_end": 14}], "cwe": "CWE-22"},
        ]
    }
    findings, dropped = read_findings(document, cwd=None)
    assert not dropped and len(findings) == 4
    assert [len(finding.locations) for finding in findings[:2]] == [0, 0]
    assert findings[3].locations[0].line_start == 12 and findings[3].cwe == ["CWE-22"]
    from sentrytower.findings import from_agent

    output = [from_agent(finding, rank=rank, route="agent", engine="single-agent") for rank, finding in enumerate(findings, 1)]
    # A line number above the limit of the output is no location.
    assert output[2].location is None and output[3].location is not None


def test_the_engine_environment_holds_no_key_variable_no_key_value_and_no_url_with_a_password() -> None:
    base = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/dev",
        "LANG": "C.UTF-8",
        "MY_PROVIDER_KEY": KEY,
        "LLM_KEY": "x" * 40,
        "COPY_OF_IT": f"prefix-{KEY}",
        "SAME": KEY,
        "DATABASE_URL": "postgres://app:password@db:5432/app",
        "CI_REPOSITORY_URL": "https://gitlab-ci-token:abc@gitlab.example/x.git",
        "SLACK_WEBHOOK_URL": "https://hooks.example/services/T0/B0/X",
        "SENTRY_DSN": "https://key@sentry.example/1",
        "GITHUB_TOKEN": "t",
        "HTTPS_PROXY": "http://proxy:3128",
    }
    environment = engine_environment(base, secret_names=("MY_PROVIDER_KEY", "LLM_KEY"), secret_values=(KEY,))
    assert set(environment) == {"PATH", "HOME", "LANG", "NO_PROXY", "no_proxy", "PYTHONSAFEPATH"}
    # A short key is compared with whole values only: it cannot empty PATH.
    assert "PATH" in engine_environment({"PATH": "/usr/bin:/bin"}, secret_values=("bin",))


def test_a_tool_in_the_audited_repository_is_refused(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    shutil.copy(rig.tools["rg"], repo / "rg")
    with pytest.raises(AuditError) as error:
        rig.audit(repo, extra_env={"SENTRYTOWER_RG": str(repo / "rg")})
    assert error.value.exit_code == 2 and "audited repository" in str(error.value)


def test_an_output_folder_that_cannot_be_written_stops_the_run_before_a_model_call(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    blocker = rig.base / "not-a-folder"
    blocker.write_text("x")
    fake = FakeModel()
    with pytest.raises(AuditError) as error:
        rig.audit(repo, fake=fake, out=blocker / "out")
    assert error.value.exit_code == 3 and fake.bodies == [] and not rig.pi_log()


def test_a_state_folder_with_a_link_is_refused(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    state = rig.base / "state"
    (rig.base / "elsewhere").mkdir()
    state.mkdir()
    (state / ".local").symlink_to(rig.base / "elsewhere")
    with pytest.raises(AuditError) as error:
        rig.audit(repo, state=state)
    assert "not a folder" in str(error.value)


@pytest.mark.slow
def test_an_interrupted_run_writes_its_outputs_and_exits_130(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    # The first progress report of the engine loop raises the interrupt: deterministic, and inside the loop.
    calls: list[int] = []
    totals = ModelGateway.totals

    def interrupting(self: ModelGateway) -> dict[str, Any]:
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt
        return totals(self)

    monkeypatch.setattr(audit, "PROGRESS_SECONDS", 0.5)
    monkeypatch.setattr(ModelGateway, "totals", interrupting)
    repo = write_repo(counted_files(1001))
    outcome, _ = rig.audit(repo, extra_env={"FAKE_PI_SLEEP": "60"})
    assert outcome.exit_code == 130 and outcome.run["status"] == "interrupted" and outcome.run["stop"] == "interrupted"
    assert json.loads((rig.base / "out" / "run.json").read_text())["status"] == "interrupted"


@pytest.mark.slow
def test_sigterm_takes_the_path_of_an_interrupt(rig, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(("SENTRYTOWER_", "OPENROUTER_")):
            monkeypatch.delenv(name)
    for name, value in rig.env(FAKE_PI_SLEEP="60").items():
        monkeypatch.setenv(name, value)
    repo = write_repo(counted_files(1001))
    # A late signal must not end the test process: the handler of the test ignores it.
    previous = signal.signal(signal.SIGTERM, lambda *_: None)
    timer = threading.Timer(3.0, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        code = main(["audit", str(repo), "--out", str(rig.base / "out"), "--base-url", "http://127.0.0.1:9/v1", "-q"])
    finally:
        timer.cancel()
        signal.signal(signal.SIGTERM, previous)
    assert code == 130 and json.loads((rig.base / "out" / "run.json").read_text())["status"] == "interrupted"


def test_an_unexpected_error_exits_4_with_its_type_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*_: Any, **__: Any) -> None:
        raise RuntimeError("text of the model that must not be printed")

    monkeypatch.setattr("sentrytower.cli.run_audit", broken)
    monkeypatch.setenv("SENTRYTOWER_API_KEY", KEY)
    assert main(["audit", str(tmp_path), "--out", str(tmp_path / "out")]) == 4
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "must not be printed" not in err


@pytest.mark.parametrize("option", [["--sarif-path-prefix", "../x"], ["--max-cost-usd", "nan"], ["--sarif-category", "a b"]])
def test_an_invalid_option_exits_2(option: list[str], tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        main(["audit", str(tmp_path), *option])
    assert error.value.code == 2


def test_doctor_reports_an_endpoint_that_does_not_speak_http(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def answer() -> None:
        connection, _ = listener.accept()
        connection.recv(65536)
        connection.sendall(b"garbage\r\n\r\n")
        connection.close()

    threading.Thread(target=answer, daemon=True).start()
    monkeypatch.setenv("SENTRYTOWER_API_KEY", KEY)
    monkeypatch.setenv("SENTRYTOWER_BASE_URL", f"http://127.0.0.1:{listener.getsockname()[1]}/v1")
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    try:
        code = main(["doctor"])
    finally:
        listener.close()
    out = capsys.readouterr().out
    assert code == 3 and "BadStatusLine" in out and KEY not in out


def test_sarif_paths_are_relative_uris_with_the_prefix_and_the_category() -> None:
    def finding(rank: int, path: str) -> OutputFinding:
        return OutputFinding(
            rank=rank,
            title=f"F{rank}",
            severity="high",
            cwe=["CWE-22"],
            locations=[OutputLocation(path, 3, 4)],
            evidence="e",
            exploit_conditions="",
            engine="single-agent",
            route="agent",
        )

    findings = [finding(1, "src/a b.py"), finding(2, "pages/[id]/page#1.tsx"), finding(3, "/etc/passwd"), finding(4, "../up.py")]
    log = sarif_document(findings, {"route": "agent"}, category="api", path_prefix="services/api")
    jsonschema.Draft4Validator(json.loads(SARIF_SCHEMA.read_text())).validate(log)
    run = log["runs"][0]
    uris = [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in run["results"]]
    assert uris == ["services/api/src/a%20b.py", "services/api/pages/%5Bid%5D/page%231.tsx"]
    assert run["automationDetails"]["id"] == "api/" and run["properties"]["findingsWithoutLocation"] == 2


GUARD_SCRIPT = r"""
import guard, { checkToolCall, allowedRoots, readCandidates } from "./guard.mts";
const [repo, pkg] = process.argv.slice(2);
const roots = allowedRoots(repo, pkg);
const calls = JSON.parse(process.argv[4]);
const results = calls.map(([tool, input]) => checkToolCall({ toolName: tool, input }, repo, roots) ?? null);
let handler;
guard({ on: (name, fn) => { if (name === "tool_call") handler = fn; } });
const hook = [await handler({ toolName: "read", input: { path: "/" } }, { cwd: repo }),
              await handler({ toolName: "read", input: { path: "src/app.py" } }, { cwd: repo })];
console.log(JSON.stringify({ results, hook, variants: readCandidates("/r/it's 1 PM.txt").length }));
"""


def _node_with_type_stripping() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    probe = subprocess.run([node, "--experimental-strip-types", "-e", "1"], check=False, capture_output=True, text=True)
    return node if probe.returncode == 0 else None


def test_the_repository_guard_keeps_the_tools_in_the_repository(tmp_path: Path) -> None:
    node = _node_with_type_stripping()
    if node is None:
        pytest.skip("needs Node.js 22.6 or later (type stripping)")
    repo, outside, package = tmp_path / "repo", tmp_path / "outside", tmp_path / "pi-package"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print(1)\n")
    outside.mkdir()
    (outside / "key.txt").write_text("secret\n")
    (package / "docs").mkdir(parents=True)
    (package / "README.md").write_text("Pi\n")
    (repo / "link.txt").symlink_to(outside / "key.txt")
    (repo / "out-folder").symlink_to(outside)
    (repo / "it’s.txt").symlink_to(outside / "key.txt")
    (repo / "in-repo-link.py").symlink_to(repo / "src" / "app.py")
    work = tmp_path / "node"
    work.mkdir()
    (work / "guard.mts").write_bytes(GUARD.read_bytes())
    (work / "run.mjs").write_text(GUARD_SCRIPT)
    calls = [
        ["read", {"path": "src/app.py"}],
        ["read", {"path": "in-repo-link.py"}],
        ["read", {"path": "missing.py"}],
        ["grep", {"pattern": "x"}],
        ["ls", {}],
        ["find", {"pattern": "*.py", "path": "src"}],
        ["read", {"path": str(package / "README.md")}],
        ["read", {"path": "link.txt"}],
        ["read", {"path": "@link.txt"}],
        ["read", {"path": "it's.txt"}],
        ["read", {"path": str(outside / "key.txt")}],
        ["read", {"path": "/proc/self/environ"}],
        ["read", {"path": "~"}],
        ["grep", {"pattern": "x", "path": "out-folder"}],
        ["find", {"pattern": "*", "path": ".."}],
        ["ls", {"path": "out-folder/"}],
        ["read", {"path": "file://" + str(outside / "key.txt")}],
    ]
    result = subprocess.run(
        [node, "--experimental-strip-types", "--no-warnings", str(work / "run.mjs"), str(repo), str(package), json.dumps(calls)],
        check=False,
        capture_output=True,
        text=True,
        cwd=work,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    allowed = [reason is None for reason in report["results"]]
    # /proc/self/environ does not exist on every system: a path that does not exist passes (the tool reports it).
    proc = Path("/proc/self/environ").exists()
    assert allowed == [True] * 7 + [False] * 4 + [not proc] + [False] * 5
    assert report["hook"][0]["block"] is True and "outside the repository" in report["hook"][0]["reason"]
    assert report["hook"][1] is None and report["variants"] == 5


def test_each_agent_session_loads_the_repository_guard(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    rig.audit(repo, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps({"findings": []}), "FAKE_PI_SLEEP": "0.1"})
    sessions = rig.pi_log()
    assert sessions
    for entry in sessions:
        extensions = [entry["argv"][index + 1] for index, part in enumerate(entry["argv"][:-1]) if part == "--extension"]
        assert [Path(item).name for item in extensions] == ["numbered-read.ts", "repository-guard.ts"]
        assert all(entry["extension_exists"])


def test_the_guard_follows_the_path_rules_of_the_pinned_pi() -> None:
    text = GUARD.read_text()
    assert pi.PI_VERSION in text and "dist/core/tools/path-utils.js" in text


def test_the_engines_import_no_module_of_the_audited_repository(rig, write_repo, tmp_path: Path) -> None:
    marker = tmp_path / "imported-from-the-repository"
    planted = f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n"
    # A package with the name of SentryTower and a module of the standard library, in the audited repository.
    repo = write_repo({"app.py": "import os\nos.system('ping ' + host)\n", "sentrytower/__init__.py": planted, "json.py": planted})
    outcome, fake = rig.audit(repo, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps({"findings": []}), "FAKE_PI_SLEEP": "0.1"})
    assert outcome.exit_code == 0 and fake.bodies and rig.pi_log()
    assert not marker.exists()


def test_a_lone_surrogate_in_model_text_or_in_a_path_cannot_stop_the_outputs(tmp_path: Path) -> None:
    from sentrytower.agent.answer import read_findings
    from sentrytower.audit import write_outputs
    from sentrytower.findings import from_agent

    document = {
        "findings": [
            {
                "title": "XSS \ud83d in view",
                "locations": [{"path": "v\udcffiew.py", "line_start": 3, "line_end": 4, "note": "half \ude00"}],
                "cwe": ["CWE-79"],
                "severity": "high",
                "evidence": "e \ud800",
                "exploit_conditions": "😀",
            }
        ]
    }
    agent_findings, _ = read_findings(document, cwd=None)
    findings = [from_agent(item, rank=1, route="agent", engine="single-agent") for item in agent_findings]
    assert findings[0].title == "XSS � in view" and findings[0].exploit_conditions == "\U0001f600"
    run = {"route": "agent", "repository": {"name": "r\udcffepo", "files_counted": 3}, "models": {}}
    out = tmp_path / "out"
    files = write_outputs(findings, run, out, ("json", "sarif", "markdown"))
    assert sorted(files) == ["json", "markdown", "run", "sarif"] and "warnings" not in run
    for path in files.values():
        path.read_bytes().decode("utf-8")
    assert json.loads((out / "findings.json").read_text())["findings"][0]["title"] == "XSS � in view"
    assert not list(out.glob(".*.tmp"))


RUN = {"route": "agent", "repository": {"name": "repo", "files_counted": 3}, "models": {}}


def _finding(rank: int = 1) -> OutputFinding:
    return OutputFinding(
        rank=rank,
        title="Command injection",
        severity="high",
        cwe=["CWE-78"],
        locations=[OutputLocation("app.py", 2, 2)],
        evidence="e",
        exploit_conditions="",
        engine="single-agent",
        route="agent",
    )


def _shell_file(home: Path) -> Path:
    target = home / ".bashrc"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# my shell\n")
    return target


def test_an_output_folder_that_is_a_link_is_refused_before_a_model_call(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    elsewhere = rig.base / "elsewhere"
    elsewhere.mkdir()
    (rig.base / "results").symlink_to(elsewhere, target_is_directory=True)
    fake = FakeModel()
    with pytest.raises(AuditError) as error:
        rig.audit(repo, fake=fake, out=rig.base / "results")
    assert error.value.exit_code == 2 and "is a symbolic link" in str(error.value)
    assert fake.bodies == [] and not rig.pi_log() and list(elsewhere.iterdir()) == []


def test_the_default_output_folder_as_a_link_of_the_repository_is_refused(
    rig, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # sentrytower audit . in a repository with a committed link sentrytower-results -> the home folder.
    repo = write_repo({"app.py": "print(1)\n"})
    home = rig.base / "home"
    target = _shell_file(home)
    (repo / "sentrytower-results").symlink_to(home, target_is_directory=True)
    for name in list(os.environ):
        if name.startswith(("SENTRYTOWER_", "OPENROUTER_")):
            monkeypatch.delenv(name)
    for name, value in rig.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(repo)
    assert main(["audit", ".", "--base-url", "http://127.0.0.1:9/v1", "-q"]) == 2
    assert "symbolic link" in capsys.readouterr().err
    assert sorted(path.name for path in home.iterdir()) == [".bashrc"] and target.read_text() == "# my shell\n"


def test_a_link_in_a_folder_of_the_repository_on_the_output_path_is_refused(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    elsewhere = rig.base / "elsewhere"
    elsewhere.mkdir()
    (repo / "reports").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(AuditError) as error:
        rig.audit(repo, out=repo / "reports" / "run-1")
    assert error.value.exit_code == 2 and "in the audited repository" in str(error.value)
    assert list(elsewhere.iterdir()) == []


def test_a_state_folder_through_a_link_in_the_repository_is_refused(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    elsewhere = rig.base / "elsewhere"
    elsewhere.mkdir()
    (repo / "cache").symlink_to(elsewhere, target_is_directory=True)
    fake = FakeModel()
    with pytest.raises(AuditError) as error:
        rig.audit(repo, fake=fake, state=repo / "cache" / "state")
    assert error.value.exit_code == 2 and "state folder" in str(error.value) and "in the audited repository" in str(error.value)
    assert fake.bodies == [] and list(elsewhere.iterdir()) == []


def test_a_link_of_the_user_outside_the_repository_on_the_output_path_is_followed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "real").mkdir()
    (tmp_path / "mine").symlink_to(tmp_path / "real", target_is_directory=True)
    out = tmp_path / "mine" / "results"
    audit._probe_out_dir(out, repo)
    files = write_outputs([_finding()], dict(RUN), out, ("json",), repository=repo)
    assert sorted(files) == ["json", "run"] and (tmp_path / "real" / "results" / "run.json").is_file()


def test_a_link_at_the_name_of_an_output_file_is_refused_before_a_model_call(rig, write_repo) -> None:
    repo = write_repo({"app.py": "print(1)\n"})
    target = _shell_file(rig.base / "home")
    out = rig.base / "out"
    out.mkdir()
    (out / "report.md").symlink_to(target)
    fake = FakeModel()
    with pytest.raises(AuditError) as error:
        rig.audit(repo, fake=fake, out=out)
    assert error.value.exit_code == 2 and "report.md" in str(error.value) and "symbolic link" in str(error.value)
    assert fake.bodies == [] and target.read_text() == "# my shell\n"


def test_the_write_replaces_a_link_at_the_name_of_an_output_file_and_never_writes_through_it(tmp_path: Path) -> None:
    target = _shell_file(tmp_path / "home")
    out = tmp_path / "out"
    out.mkdir()
    (out / "run.json").symlink_to(target)
    (out / "report.md").symlink_to(tmp_path / "missing")
    write_outputs([_finding()], dict(RUN), out, ("markdown",))
    assert target.read_text() == "# my shell\n" and not (tmp_path / "missing").exists()
    assert not (out / "run.json").is_symlink() and json.loads((out / "run.json").read_text())["route"] == "agent"
    assert not (out / "report.md").is_symlink() and "Command injection" in (out / "report.md").read_text()


def test_a_planted_link_at_a_staging_name_is_never_written_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shell_file(tmp_path / "home")
    out = tmp_path / "out"
    out.mkdir()
    # A fixed staging name that is easy to guess, and the first random name that the write draws.
    (out / ".report.md.tmp").symlink_to(target)
    (out / ".report.md.aaaaaaaaaaaa.tmp").symlink_to(target)
    tokens = iter(["aaaaaaaaaaaa", *(f"{index:012x}" for index in range(10))])
    monkeypatch.setattr(audit, "token_hex", lambda _: next(tokens))
    files = write_outputs([_finding()], dict(RUN), out, ("markdown",))
    assert sorted(files) == ["markdown", "run"] and target.read_text() == "# my shell\n"
    assert "Command injection" in (out / "report.md").read_text()
    # Only the planted links stay: no staging file of the write is left.
    assert sorted(path.name for path in out.glob(".*.tmp")) == [".report.md.aaaaaaaaaaaa.tmp", ".report.md.tmp"]


def test_a_folder_at_the_name_of_an_output_file_stops_the_write_with_a_plain_error(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "report.md").mkdir(parents=True)
    with pytest.raises(AuditError) as error:
        audit._probe_out_dir(out)
    assert error.value.exit_code == 2 and "report.md" in str(error.value) and "not a file" in str(error.value)
    with pytest.raises(AuditError) as error:
        write_outputs([_finding()], dict(RUN), out, ("markdown",))
    assert error.value.exit_code == 3 and "report.md" in str(error.value)
    assert not list(out.glob(".*.tmp"))


def test_an_output_folder_of_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(os, "getuid", lambda: out.stat().st_uid + 1)
    with pytest.raises(AuditError) as error:
        audit._probe_out_dir(out)
    assert error.value.exit_code == 2 and "another user" in str(error.value)


def test_a_staging_file_is_private_and_an_output_file_gets_the_mode_of_a_new_file(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    folder = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
    try:
        staging, descriptor = audit._staging_file(folder, "report.md")
        os.close(descriptor)
        assert stat.S_IMODE(os.stat(staging, dir_fd=folder).st_mode) == 0o600
        os.unlink(staging, dir_fd=folder)
    finally:
        os.close(folder)
    previous = os.umask(0o027)
    try:
        write_outputs([_finding()], dict(RUN), out, ("markdown",))
    finally:
        os.umask(previous)
    assert {stat.S_IMODE(path.stat().st_mode) for path in out.iterdir()} == {0o640}


def test_last_reads_only_regular_files_of_an_output_folder_without_links(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from sentrytower.ui.results import remember

    folder = tmp_path / "results"
    write_outputs([_finding()], dict(RUN), folder, ("json", "markdown"))
    remember(folder, RUN)
    assert main(["last"]) == 0 and "1 findings" in capsys.readouterr().out
    # A link that replaces findings.json is not read.
    crafted = tmp_path / "crafted.json"
    crafted.write_text(json.dumps({"findings": [{"title": "planted"}, {"title": "planted"}]}))
    (folder / "findings.json").unlink()
    (folder / "findings.json").symlink_to(crafted)
    assert main(["last"]) == 0 and "0 findings" in capsys.readouterr().out
    # A folder that a link replaced is refused.
    folder.rename(tmp_path / "moved")
    folder.symlink_to(tmp_path / "moved", target_is_directory=True)
    assert main(["last"]) == 2 and "symbolic link" in capsys.readouterr().err


def _program(folder: Path, name: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("#!/bin/sh\necho planted\n")
    path.chmod(0o755)
    return path


def test_the_search_path_keeps_the_absolute_entries_outside_the_repository_only(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    linked = tmp_path / "link-to-repo"
    linked.symlink_to(repo, target_is_directory=True)
    value = os.pathsep.join(["node_modules/.bin", "", ".", "bin", "~/bin", "/usr/bin", str(repo / "bin"), str(linked / "bin"), "/opt/x"])
    assert search_path(value) == os.pathsep.join(["/usr/bin", str(repo / "bin"), str(linked / "bin"), "/opt/x"])
    assert search_path(value, outside=[repo]) == os.pathsep.join(["/usr/bin", "/opt/x"])
    # No absolute entry: the default search path, never an empty PATH (an empty PATH searches the working folder).
    assert search_path("node_modules/.bin::.") == os.defpath and search_path(None) == os.defpath
    assert program_environment({"PATH": "a:/usr/bin", "HOME": "/h"}) == {"PATH": "/usr/bin", "HOME": "/h"}
    assert program_environment({"HOME": "/h"}) == {"HOME": "/h"}
    environment = engine_environment({"PATH": value, "HOME": "/h"}, repository=repo)
    assert environment["PATH"] == os.pathsep.join(["/usr/bin", "/opt/x"])


def test_a_program_of_the_working_folder_is_never_found_on_a_relative_path_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    for name in ("pi", "rg", "fd", "fdfind", "node", "open", "xdg-open", "security", "secret-tool"):
        _program(repo / "node_modules" / ".bin", name)
        _program(repo, name)
    tools = tmp_path / "tools"
    rg = _program(tools, "rg")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", os.pathsep.join(["node_modules/.bin", "", ".", str(tools)]))
    monkeypatch.delenv("SENTRYTOWER_PI", raising=False)
    monkeypatch.setattr(pi, "PI_CANDIDATES", ())
    assert which("node") is None and which("rg") == str(rg) and which("./rg") is None
    assert pi.find_pi() is None and pi.find_tool("fd") is None and pi.find_tool("rg") == rg
    # A configured relative path is made absolute in the folder of the parent: the engines run elsewhere.
    configured = pi.find_pi("node_modules/.bin/pi")
    assert configured == repo / "node_modules" / ".bin" / "pi" and configured.is_absolute()


def test_the_report_opener_and_the_keychain_tools_run_from_absolute_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sentrytower.ui import keychain, results

    tools = tmp_path / "tools"
    for name in ("open", "xdg-open", "security", "secret-tool"):
        _program(tools, name)
        _program(tmp_path / "rel", name)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(["rel", str(tools)]))
    started: list[list[str]] = []
    monkeypatch.setattr(results.subprocess, "Popen", lambda argv, **_: started.append(argv))
    monkeypatch.setattr(results.time, "sleep", lambda _: None)
    assert results.open_file(tmp_path / "report.html")
    assert started == [[str(tools / ("open" if sys.platform == "darwin" else "xdg-open")), str(tmp_path / "report.html")]]

    class Completed:
        returncode = 0
        stdout = "key-from-keychain\n"

    ran: list[list[str]] = []
    monkeypatch.setattr(keychain.subprocess, "run", lambda argv, **_: ran.append(argv) or Completed())
    for kind, tool in (("macos", "security"), ("secret-service", "secret-tool")):
        monkeypatch.setattr(keychain, "backend", lambda kind=kind: kind)
        assert keychain.read() == "key-from-keychain"
        assert ran[-1][0] == str(tools / tool)


def test_each_agent_session_gets_absolute_path_entries_outside_the_repository(rig, write_repo) -> None:
    repo = write_repo({"app.py": "import os\nos.system('ping ' + host)\n"})
    _program(repo / "node_modules" / ".bin", "node")
    _program(repo / "bin", "node")
    path = os.pathsep.join(["node_modules/.bin", "", ".", "bin", str(repo / "bin"), rig.environment["PATH"]])
    outcome, _ = rig.audit(repo, extra_env={"PATH": path, "FAKE_PI_FREE_ANSWER": json.dumps({"findings": []}), "FAKE_PI_SLEEP": "0.1"})
    sessions = rig.pi_log()
    assert outcome.exit_code == 0 and sessions
    # The funnel engine, each agent session of it and the runner of each session: the absolute entries outside the repository.
    assert {entry["path"] for entry in sessions} == {rig.environment["PATH"]}


@pytest.mark.slow
def test_the_agent_route_gets_absolute_path_entries_outside_the_repository(rig, write_repo) -> None:
    repo = write_repo(counted_files(1001))
    path = os.pathsep.join(["node_modules/.bin", "", ".", str(repo / "src"), rig.environment["PATH"]])
    outcome, _ = rig.audit(repo, extra_env={"PATH": path, "FAKE_PI_SLEEP": "0.1"})
    assert outcome.run["route"] == "agent" and {entry["path"] for entry in rig.pi_log()} == {rig.environment["PATH"]}


def _session_lines(text: str) -> list[dict[str, Any]]:
    return [
        {"type": "session", "version": 3, "id": "s", "cwd": "/repo"},
        {"type": "message", "message": {"role": "user", "content": [{"type": "text", "text": "task\u2028with a separator"}]}},
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
                "stopReason": "stop",
                "usage": {"totalTokens": 10},
            },
        },
    ]


def test_line_separators_in_a_json_string_of_an_answer_keep_the_whole_answer(tmp_path: Path) -> None:
    from sentrytower.agent.session import read_answer, read_session

    evidence = "Line one\u2028line two\u2029line three\u0085line four\x1cend"
    answer = {
        "findings": [
            {
                "title": "Command injection",
                "locations": [{"path": "app.py", "line_start": 2, "line_end": 2}],
                "cwe": ["CWE-78"],
                "severity": "high",
                "evidence": evidence,
                "exploit_conditions": "The host.",
            }
        ]
    }
    # The agent writes U+2028, U+2029 and U+0085 raw inside the JSON strings of its session lines.
    data = "".join(json.dumps(line, ensure_ascii=False) + "\r\n" for line in _session_lines(json.dumps(answer, ensure_ascii=False)))
    assert all(character in data for character in "\u2028\u2029\u0085") and len(data.splitlines()) > 3
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    (sessions / "s1.jsonl").write_bytes(data.encode())
    document, error = read_answer(sessions)
    assert error is None and document is not None and document["findings"][0]["evidence"] == evidence
    header, messages, truncated = read_session(sessions / "s1.jsonl")
    assert header["cwd"] == "/repo" and len(messages) == 2 and not truncated
    # A stop that cuts the last line in the middle of a character: the lines before it still count.
    cut = json.dumps({"type": "message", "message": {"role": "assistant", "content": [{"type": "text", "text": "é"}]}}, ensure_ascii=False)
    (sessions / "s1.jsonl").write_bytes(data.encode() + cut.encode()[:-6])
    _, messages, truncated = read_session(sessions / "s1.jsonl")
    assert truncated and len(messages) == 2
    document, error = read_answer(sessions)
    assert error is None and document is not None and len(document["findings"]) == 1


def test_the_live_view_splits_session_lines_on_newlines_only(tmp_path: Path) -> None:
    from sentrytower.ui.live import SessionTail

    call = {"type": "toolCall", "id": "c1", "name": "read", "arguments": {"path": "a\u2028b.py"}}
    line = json.dumps({"type": "message", "message": {"role": "assistant", "content": [call]}}, ensure_ascii=False)
    # A carriage return is JSON white space: bytes.splitlines would cut the line there.
    line = line.replace('"type": "message", ', '"type": "message",\r ', 1)
    (tmp_path / "s1.jsonl").write_bytes((line + "\n").encode())
    tail = SessionTail([tmp_path], tmp_path)
    tail.poll()
    assert tail.reads == 1 and tail.files_read == {"a\u2028b.py"}


def test_the_web_report_keeps_a_line_separator_of_model_text_in_its_line() -> None:
    from sentrytower.html_report import rich_text

    assert rich_text("one\u2028two\nthree") == "<p>one\u2028two<br>three</p>"


def test_model_text_and_file_names_reach_the_terminal_without_control_codes() -> None:
    import io

    from sentrytower.ui.term import PLAIN, TRUECOLOR, Style, to_ansi, to_plain

    # A finding title or a file name of the audited repository: a clipboard write (OSC 52), a screen clear, a
    # right-to-left override, an 8-bit CSI and a newline.
    hostile = "title\x1b]52;c;ZXZpbA==\x07 \x1b[2J\u202egnp.exe\x9b31m\nnext"
    styled = to_ansi([(hostile, Style(bold=True)), (hostile, PLAIN)], TRUECOLOR)
    # Only the style of the interface gives escape codes: bold, then its reset.
    assert styled.count("\x1b") == 2 and not {"\x07", "\u202e", "\x9b", "\n"} & set(styled)
    assert to_plain([(hostile, PLAIN)]) == "title?]52;c;ZXZpbA==? ?[2J?gnp.exe?31m?next"
    stream = io.StringIO()
    audit.Log(stream=stream).warn(hostile)
    assert "\x1b" not in stream.getvalue() and stream.getvalue().count("\n") == 1


def test_the_engines_get_no_loader_variable_that_names_the_repository(tmp_path: Path) -> None:
    from sentrytower.programs import program_environment

    repository = tmp_path / "repo"
    (repository / "lib").mkdir(parents=True)
    tools = tmp_path / "tools"
    tools.mkdir()
    environment = {
        "PATH": f"{tools}:node_modules/.bin",
        # An empty entry and "." name the working folder; an absolute entry can also be in the repository.
        "PYTHONPATH": f":{tools}:.:{repository / 'lib'}",
        "NODE_PATH": "node_modules",
        "LD_LIBRARY_PATH": str(tools),
        "NODE_OPTIONS": "--require=./evil.cjs",
        "RIPGREP_CONFIG_PATH": ".ripgreprc",
        "LD_PRELOAD": "./evil.so",
        "HOME": "/home/dev",
    }
    result = program_environment(environment, outside=[repository])
    assert result["PATH"] == result["PYTHONPATH"] == result["LD_LIBRARY_PATH"] == str(tools) and result["HOME"] == "/home/dev"
    assert not {"NODE_PATH", "NODE_OPTIONS", "RIPGREP_CONFIG_PATH", "LD_PRELOAD"} & set(result)
    engine = engine_environment(environment, repository=repository)
    assert engine["PYTHONPATH"] == str(tools) and not {"NODE_PATH", "NODE_OPTIONS", "RIPGREP_CONFIG_PATH", "LD_PRELOAD"} & set(engine)


def test_the_markdown_report_holds_no_control_character_of_the_model() -> None:
    from sentrytower.report import markdown_report

    hostile = OutputFinding(
        rank=1,
        title="SQL injection\x1b]52;c;ZXZpbA==\x07\x1b[2J \u202eexe.txt",
        severity="high",
        cwe=["CWE-89"],
        locations=[OutputLocation("app\x1b[31m.py", 2, 2)],
        evidence="line one\r\nline two\tindented\x9b31m",
        exploit_conditions="",
        engine="single-agent",
        route="agent",
    )
    report = markdown_report([hostile], {"route": "agent"})
    assert not {"\x1b", "\x07", "\x9b", "\u202e", "\r"} & set(report)
    # A text of several lines keeps its lines and tabs.
    assert "line one\nline two\tindented?31m" in report and "SQL injection?]52;c;ZXZpbA==??[2J ?exe.txt" in report
