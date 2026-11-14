"""The command line: exit codes, the outputs of an audit through a local OpenAI-compatible endpoint, doctor, version."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path

import jsonschema
import pytest

from fakes import FakeModel, FakeServer
from sentrytower import __version__
from sentrytower.cli import main
from sentrytower.policies import DEFAULT_MODEL
from synthetic import WEBAPP, counted_files, line_of

SARIF_SCHEMA = Path(__file__).resolve().parent / "data" / "sarif-schema-2.1.0.json"
_READ = line_of(WEBAPP, "files.py", "def read")
FREE_ANSWER = {
    "findings": [
        {
            "title": "Path traversal",
            "locations": [{"path": "files.py", "line_start": _READ, "line_end": _READ + 2}],
            "cwe": ["CWE-22"],
            "severity": "high",
            "evidence": "e",
            "exploit_conditions": "c",
        }
    ]
}


@pytest.fixture
def cli_env(rig, monkeypatch: pytest.MonkeyPatch):
    for name in list(os.environ):
        if name.startswith(("SENTRYTOWER_", "OPENROUTER_")):
            monkeypatch.delenv(name)
    for name, value in rig.environment.items():
        monkeypatch.setenv(name, value)
    return rig


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out.startswith(f"sentrytower {__version__} (funnel v1.4, agent protocol v2.4, Pi 1.5.0")
    assert main(["version", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["pi_coding_agent"] == "1.5.0"
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0


def test_no_command_prints_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "audit" in capsys.readouterr().out


def test_audit_without_a_key_exits_3(cli_env, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("SENTRYTOWER_API_KEY")
    assert main(["audit", str(write_repo(WEBAPP)), "--out", str(cli_env.base / "out"), "-q"]) == 3
    assert "no provider key" in capsys.readouterr().err
    assert not (cli_env.base / "out").exists()


def test_audit_with_an_invalid_configuration_exits_2(cli_env, write_repo, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "bad.toml"
    config.write_text('[provider]\napi_key = "do-not-print-this"\n')
    assert main(["audit", str(write_repo(WEBAPP)), "--config", str(config)]) == 2
    error = capsys.readouterr().err
    assert "configuration error" in error and "do-not-print-this" not in error


def test_audit_of_a_missing_folder_exits_2(cli_env, tmp_path: Path) -> None:
    assert main(["audit", str(tmp_path / "missing"), "-q"]) == 2


def test_audit_with_a_bad_format_exits_2(cli_env, write_repo) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["audit", str(write_repo(WEBAPP)), "--format", "xml"])
    assert stop.value.code == 2


@pytest.mark.slow
def test_audit_through_a_local_endpoint_writes_each_output(
    cli_env, write_repo, monkeypatch: pytest.MonkeyPatch, findings_validator
) -> None:
    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps(FREE_ANSWER))
    fake = FakeModel(cost=0.0001)
    out = cli_env.base / "out"
    with FakeServer(fake) as server:
        code = main(["audit", str(write_repo(WEBAPP)), "--out", str(out), "--base-url", server.url, "-q"])
    assert code == 0
    assert sorted(path.name for path in out.iterdir()) == ["findings.json", "findings.sarif", "report.html", "report.md", "run.json"]
    findings = json.loads((out / "findings.json").read_text())
    findings_validator.validate(findings)
    sarif = json.loads((out / "findings.sarif").read_text())
    jsonschema.Draft4Validator(json.loads(SARIF_SCHEMA.read_text())).validate(sarif)
    run = json.loads((out / "run.json").read_text())
    assert run["route"] == "funnel" and run["status"] == "complete" and run["findings"]["count"] == len(findings["findings"])
    assert run["usage"]["total"]["cost_source"] == "provider" and run["usage"]["total"]["calls"] == len(fake.bodies)
    assert run["configuration"]["provider"]["base_url"] == server.url and "benchmark_deviations" not in run
    # No cap of a setting: the default cap of $2, the standard run of 20M tokens.
    assert (
        run["schema_version"] == "1.0.0"
        and run["budget"]["token_ceiling_source"] == "standard run"
        and run["budget"]["max_tokens"] == 20_000_000
        and run["budget"]["max_cost_usd"] == 2.0
        and run["budget"]["depth_factor"] == 1.0
    )
    assert run["result"]["status"] == "complete" and run["result"]["calls"]["total"] == len(fake.bodies)
    assert findings["schema_version"] == "2.0.0" and findings["run"]["result"] == run["result"]
    finding = next(item for item in findings["findings"] if item["engine"]["mode"] == "free-roaming")
    assert finding["title"] == "Path traversal" and finding["evidence"] == {"class": "suspected", "verification": {"status": "none"}}
    assert (
        finding["location"] == {"path": "files.py", "startLine": _READ, "endLine": _READ + 2}
        and finding["description"] == "e\n\nAttack conditions, as the model states them: c"
    )
    fingerprints = [result["partialFingerprints"]["sentrytowerFindingHash/v1"] for result in sarif["runs"][0]["results"]]
    assert fingerprints == [item["fingerprint"]["value"] for item in findings["findings"] if "location" in item]
    page = (out / "report.html").read_text()
    assert page.startswith("<!doctype html>") and "<script" not in page
    assert all(html.escape(item["title"]) in page for item in findings["findings"]) and page.count("<article ") == len(findings["findings"])
    # The provider got the key in the authorization header; no output file holds the key.
    key = cli_env.environment["SENTRYTOWER_API_KEY"]
    assert all(headers.get("authorization") == f"Bearer {key}" for headers in fake.headers)
    for path in out.iterdir():
        assert key not in path.read_text()
    assert run["key_variable"] == "SENTRYTOWER_API_KEY"


@pytest.mark.slow
def test_fail_on_exits_1_when_a_finding_reaches_the_severity(cli_env, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps(FREE_ANSWER))
    repo = write_repo(WEBAPP)
    with FakeServer(FakeModel()) as server:
        assert main(["audit", str(repo), "--out", str(cli_env.base / "a"), "--base-url", server.url, "--fail-on", "high", "-q"]) == 1
        # Only findings at or above the threshold count: a threshold that no finding reaches gives 0.
        monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps({"findings": []}))
        monkeypatch.setenv("FAKE_PI_SLEEP", "0.1")
        code = main(["audit", str(repo), "--out", str(cli_env.base / "b"), "--base-url", server.url, "--fail-on", "critical", "-q"])
    findings = json.loads((cli_env.base / "b" / "findings.json").read_text())["findings"]
    assert code == (1 if any(item["severity"] == "critical" for item in findings) else 0)


@pytest.mark.slow
def test_a_run_without_an_answer_exits_4_and_keeps_its_state(
    cli_env, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FAKE_PI_MODE", "no-answer")
    monkeypatch.setenv("FAKE_PI_SLEEP", "0.1")
    # The agent route: more than 1,000 files. The final turn of the fake agent answers, so make both turns fail.
    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", "not json")
    repo = write_repo(counted_files(1001))
    with FakeServer(FakeModel()) as server:
        code = main(
            ["audit", str(repo), "--out", str(cli_env.base / "out"), "--base-url", server.url, "--state-dir", str(cli_env.base / "state")]
        )
    assert code == 4
    run = json.loads((cli_env.base / "out" / "run.json").read_text())
    assert run["status"] == "incomplete" and "no findings answer" in run["failure"]
    assert (cli_env.base / "state" / ".local" / "share" / "pi-sessions" / "runner.json").is_file()
    assert "run state kept" in capsys.readouterr().err


def _fake_node(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    node = folder / "node"
    node.write_text("#!/bin/sh\necho v24.19.0\n")
    node.chmod(0o755)


def test_doctor_offline_checks_the_tools_and_never_prints_the_key(
    cli_env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_node(cli_env.base / "bin")
    monkeypatch.setenv("PATH", f"{cli_env.base / 'bin'}:{os.environ['PATH']}")
    code = main(["doctor", "--offline", "--json"])
    output = capsys.readouterr().out
    checks = {check["name"]: check for check in json.loads(output)["checks"]}
    assert cli_env.environment["SENTRYTOWER_API_KEY"] not in output
    assert checks["python"]["status"] == "ok" and checks["node"]["status"] == "ok" and checks["pi"]["status"] == "ok"
    # The stand-ins of rg and fd print another version than the pinned one: a warning, not a failure.
    assert checks["rg"]["status"] == "warn" and checks["fd"]["status"] == "warn"
    assert checks["rg"]["hint"] == "the pinned version is 15.2.0" and checks["fd"]["hint"] == "the pinned version is 10.5.0"
    assert checks["api key"]["status"] == "ok" and "SENTRYTOWER_API_KEY" in checks["api key"]["detail"]
    assert checks["endpoint"]["status"] == "skip" and code == 0


def test_doctor_fails_without_a_key_and_without_pi(cli_env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("SENTRYTOWER_API_KEY")
    monkeypatch.setenv("SENTRYTOWER_PI", str(cli_env.base / "missing" / "cli.js"))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert main(["doctor", "--offline"]) == 3
    output = capsys.readouterr().out
    assert "[FAIL] api key" in output and "[FAIL] pi" in output and "npm install -g @earendil-works/pi-coding-agent@1.5.0" in output


def test_doctor_sends_one_tiny_request_to_the_endpoint(
    cli_env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_node(cli_env.base / "bin")
    monkeypatch.setenv("PATH", f"{cli_env.base / 'bin'}:{os.environ['PATH']}")
    fake = FakeModel()
    with FakeServer(fake) as server:
        monkeypatch.setenv("SENTRYTOWER_BASE_URL", server.url)
        assert main(["doctor"]) == 0
    assert f"[ok  ] endpoint  {DEFAULT_MODEL} answered" in capsys.readouterr().out
    [body] = fake.bodies
    request = json.loads(body)
    assert request["max_completion_tokens"] == 256 and request["reasoning"] == {"effort": "low"}
    assert request["messages"] == [{"role": "user", "content": "Reply with the word OK."}]


def test_setup_needs_a_terminal(cli_env, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["setup"]) == 2
    assert "run it in a terminal" in capsys.readouterr().err


def test_settings_without_a_terminal_prints_the_settings_and_no_key(cli_env, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["settings"]) == 0
    output = capsys.readouterr().out
    assert "Juno (sand)" in output and "found in SENTRYTOWER_API_KEY" in output and DEFAULT_MODEL in output
    assert "20,000,000 tokens" in output and "benchmark" not in output
    assert cli_env.environment["SENTRYTOWER_API_KEY"] not in output


def test_last_without_an_audit_exits_2(cli_env, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["last"]) == 2
    assert "no audit yet" in capsys.readouterr().err


def test_the_results_folder_of_the_settings_gets_a_folder_for_each_repository(cli_env, write_repo, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps(FREE_ANSWER))
    results = cli_env.base / "results"
    settings = Path(os.environ["XDG_CONFIG_HOME"]) / "sentrytower" / "config.toml"
    settings.parent.mkdir(parents=True)
    settings.write_text(f'[run]\nout_dir = "{results}"\n')
    with FakeServer(FakeModel(cost=0.0001)) as server:
        code = main(["audit", str(write_repo(WEBAPP, name="shop")), "--base-url", server.url, "-q"])
    assert code == 0 and (results / "shop" / "findings.json").is_file()


def test_an_audit_in_a_terminal_shows_the_live_view_and_the_summary(
    cli_env, write_repo, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sentrytower.ui import keys, term
    from sentrytower.ui.results import last_run

    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps(FREE_ANSWER))
    recording = cli_env.base / "screen.jsonl"
    monkeypatch.setenv("SENTRYTOWER_RECORD", str(recording))
    monkeypatch.setattr(term, "detect", lambda **_: term.Caps(color=term.TRUECOLOR, unicode=True, interactive=True, width=110, height=40))
    # The end of the scripted keys is Esc: "What next?" ends the command.
    monkeypatch.setattr(keys, "KeyReader", lambda: keys.ScriptedKeys([]))
    out = cli_env.base / "out"
    with FakeServer(FakeModel(cost=0.0001)) as server:
        code = main(["audit", str(write_repo(WEBAPP, name="shop")), "--out", str(out), "--base-url", server.url])
    assert code == 0 and (out / "report.md").is_file()
    screens = [json.loads(line) for line in recording.read_text().splitlines()]
    shown = "\n".join("".join(text for text, _ in line) for event in screens for line in event.get("lines") or [])
    assert "Juno is auditing shop" in shown and "funnel engine" in shown and "Map the code" in shown
    count = len(json.loads((out / "findings.json").read_text())["findings"])
    assert count > 1 and f"Juno found {count} issues in shop" in shown and "CWE-22" in shown and "What next?" in shown
    key = cli_env.environment["SENTRYTOWER_API_KEY"]
    assert key not in recording.read_text() and key not in capsys.readouterr().out
    record = last_run()
    assert record is not None and record["out_dir"] == str(out.resolve()) and record["repository"] == "shop"
    # `last` without a terminal names the folder of that run.
    monkeypatch.setattr(term, "detect", lambda **_: term.Caps())
    assert main(["last"]) == 0
    assert f"{out.resolve()}: {count} findings, status complete" in capsys.readouterr().out


def test_open_opens_the_html_report_or_says_where_it_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from sentrytower import cli
    from sentrytower.audit import AuditOutcome, Log
    from sentrytower.ui import results

    assert cli.build_parser().parse_args(["audit", ".", "--no-open"]).open is False
    assert cli.build_parser().parse_args(["audit", "."]).open is None
    opened: list[Path] = []
    monkeypatch.setattr(results, "can_open", lambda environ=None: True)
    monkeypatch.setattr(results, "open_file", lambda path: opened.append(path) or True)
    outcome = AuditOutcome(findings=[], run={}, files={"markdown": tmp_path / "report.md", "html": tmp_path / "report.html"})
    cli._open_report(outcome, Log())
    assert opened == [tmp_path / "report.html"]
    monkeypatch.setattr(results, "can_open", lambda environ=None: False)
    cli._open_report(outcome, Log())
    assert (
        opened == [tmp_path / "report.html"] and f"the report cannot be opened here: {tmp_path / 'report.html'}" in capsys.readouterr().err
    )


def test_depth_sets_the_cost_cap_unless_max_cost_usd_is_given() -> None:
    from sentrytower import cli

    parser = cli.build_parser()
    assert cli._cost_cap(parser.parse_args(["audit", ".", "--depth", "deep"])) == 10.0
    assert cli._cost_cap(parser.parse_args(["audit", ".", "--depth", "deep", "--max-cost-usd", "3"])) == 3.0
    assert cli._cost_cap(parser.parse_args(["audit", "."])) is None
    with pytest.raises(SystemExit):
        parser.parse_args(["audit", ".", "--depth", "extreme"])
