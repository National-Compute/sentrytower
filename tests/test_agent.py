"""The single-agent engine: the Pi command and configuration, the runner turn rules and the reading of the answer."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fakes import MODEL, fake_pi_package, fake_tools, read_jsonl
from sentrytower.agent import pi
from sentrytower.agent.answer import read_findings, relative_path
from sentrytower.agent.runner import AGENT_TOOLS
from sentrytower.policies import DEFAULT_MODEL, resolve_policies
from synthetic import WEBAPP, counted_files


def test_the_prompt_is_the_audit_request_the_contract_and_the_schema() -> None:
    prompt = pi.audit_prompt()
    assert prompt.startswith("Inspect this repository for security vulnerabilities.")
    assert "Do not finish early." in prompt and '"$schema": "https://json-schema.org/draft/2020-12/schema"' in prompt
    assert prompt.endswith("}\n") and prompt.count("\n\n") >= 4
    assert pi.final_message().startswith("Stop the audit now and write your final answer")


def test_the_agent_folder_and_the_command(tmp_path: Path) -> None:
    cli = fake_pi_package(tmp_path / "pi")
    tools = fake_tools(tmp_path / "tools")
    agent, sessions = tmp_path / "pi-agent", tmp_path / "pi-sessions"
    pi.write_agent_config(agent, "http://127.0.0.1:9", list(resolve_policies([MODEL]).values()))
    package = pi.prepare_agent_directory(agent, pi_cli=cli, tools=tools)
    settings = json.loads((agent / "settings.json").read_text())
    assert settings == {
        "defaultProvider": "openrouter",
        "defaultModel": MODEL,
        "defaultThinkingLevel": "medium",
        "httpIdleTimeoutMs": 1_200_000,
        "retry": {"provider": {"timeoutMs": 1_200_000, "maxRetries": 0, "maxRetryDelayMs": 60_000}},
    }
    provider = json.loads((agent / "models.json").read_text())["providers"]["openrouter"]
    assert provider["baseUrl"] == "http://127.0.0.1:9" and provider["apiKey"] == "$OPENROUTER_API_KEY"
    assert provider["models"][0]["samplingParams"] == {"temperature": 1.0} and provider["models"][0]["maxTokens"] == 131_072
    assert (agent / "bin" / "rg").resolve() == tools["rg"].resolve() and package.resolve() == (tmp_path / "pi").resolve()
    assert pi.extension_path(agent).read_text().startswith("/**")
    assert "Repository guard" in pi.guard_path(agent).read_text()
    command = pi.agent_command(
        pi_cli=cli,
        session_directory=sessions,
        agent_directory=agent,
        model=MODEL,
        prompt=pi.audit_prompt(),
        final=pi.final_message(),
        token_budget=20_000_000,
        wall_clock_seconds=14_400,
    )
    split = command.index("--")
    assert command[1:4] == ["-P", "-m", "sentrytower.agent.runner"]
    expected = [str(cli), "--provider", "openrouter", "--model", MODEL, "--print", "--session-dir", str(sessions), "--no-extensions"]
    expected += ["--extension", str(agent / "pi-ext" / "numbered-read.ts"), "--extension", str(agent / "pi-ext" / "repository-guard.ts")]
    expected += ["--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve"]
    expected += ["--tools", "read,grep,find,ls"]
    assert command[split + 1 :] == [*expected, pi.audit_prompt()]
    assert AGENT_TOOLS == ("read", "grep", "find", "ls")
    environment = pi.agent_environment(agent, package, "run-credential")
    assert environment == {
        "PI_CODING_AGENT_DIR": str(agent),
        "PI_PACKAGE_DIR": str(package),
        "PI_OFFLINE": "1",
        "OPENROUTER_API_KEY": "run-credential",
    }


def test_the_pi_package_is_found_from_its_bin_a_global_link_or_its_unbundled_script(tmp_path: Path) -> None:
    # A global npm install: PREFIX/bin/pi links to the bin of the package, dist/bundle/cli.js.
    package = tmp_path / "lib" / "node_modules" / "@earendil-works" / "pi-coding-agent"
    bundle = fake_pi_package(package)
    (package / "dist" / "cli.js").write_text("// the unbundled script\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "pi").symlink_to(bundle)
    for cli in (bundle, package / "dist" / "cli.js", tmp_path / "bin" / "pi"):
        assert pi.pi_package_directory(cli) == package.resolve()
        assert pi.pi_version(cli) == pi.PI_VERSION == "1.5.0"
    # The nearest package.json above the script decides: another package is not Pi.
    other = tmp_path / "other"
    (other / "dist" / "bundle").mkdir(parents=True)
    (other / "package.json").write_text(json.dumps({"name": "not-pi", "version": "1.5.0"}))
    (other / "dist" / "bundle" / "cli.js").write_text("")
    with pytest.raises(ValueError, match="is not the @earendil-works/pi-coding-agent command"):
        pi.pi_package_directory(other / "dist" / "bundle" / "cli.js")
    assert pi.pi_version(other / "dist" / "bundle" / "cli.js") is None


def _run(tmp_path: Path, mode: dict[str, str], budget: int = 1_000_000) -> tuple[int, list[dict], dict]:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
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
        token_budget=budget,
        wall_clock_seconds=600,
    )
    environment = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "FAKE_PI_LOG": str(tmp_path / "log.jsonl"),
        "FAKE_PI_SLEEP": "0.2",
        **pi.agent_environment(agent, agent / "pi-package", "c"),
        **mode,
    }
    completed = subprocess.run(command, cwd=repo, env=environment, capture_output=True, text=True, timeout=120, check=False)
    return completed.returncode, read_jsonl(tmp_path / "log.jsonl"), json.loads((sessions / "runner.json").read_text())


def test_one_answer_is_one_turn(tmp_path: Path) -> None:
    code, log, runner = _run(tmp_path, {"FAKE_PI_FREE_ANSWER": json.dumps({"findings": [{"title": "x"}]})})
    assert code == 0 and len(log) == 1 and runner["final_turn"] is None and runner["turns"][0]["stopped"] is None


def test_an_answer_without_json_gets_one_final_turn(tmp_path: Path) -> None:
    code, log, runner = _run(tmp_path, {"FAKE_PI_MODE": "no-answer"})
    assert code == 0 and [row["final"] for row in log] == [False, True]
    assert runner["final_turn"] == "no-answer"
    final = log[1]["argv"]
    assert "--session" in final and "--session-dir" not in final and final[-1] == pi.final_message()


def test_a_blank_first_reply_starts_the_audit_again(tmp_path: Path) -> None:
    code, log, runner = _run(tmp_path, {"FAKE_PI_MODE": "blank-first"})
    assert code == 0 and len(log) == 2 and runner["blank_restarts"]["count"] == 1
    assert (tmp_path / "home" / "blank-sessions" / "attempt-1.jsonl").is_file()


def test_the_token_reserve_stops_the_first_turn_then_one_final_turn(tmp_path: Path) -> None:
    _code, log, runner = _run(tmp_path, {"FAKE_PI_TOKENS": "800000", "FAKE_PI_SLEEP": "3"})
    assert runner["stopped"] == "token-reserve" and runner["final_turn"] == "token-reserve"
    assert [turn["stopped"] for turn in runner["turns"]] == ["token-reserve", "token-limit"]
    assert len(log) == 2


def test_the_reading_of_an_answer() -> None:
    document = {
        "findings": [
            {
                "title": "SQL injection",
                "locations": [
                    {"path": "/workspace/repo/app.py", "line_start": 9, "line_end": 7},
                    {"file": "app.py", "line": "20-22"},
                    {"path": "db.py:4"},
                    {"line_start": 3},
                ],
                "cwe": ["CWE-089", "89", 79],
                "severity": "HIGH",
                "evidence": "e",
                "exploit_conditions": "c",
            },
            {"title": "", "locations": [], "cwe": "none", "severity": "urgent"},
            "not an object",
        ]
    }
    findings, dropped = read_findings(document, cwd="/workspace/repo")
    assert dropped == [{"index": 2, "reason": "not an object"}]
    first = findings[0]
    assert [(item.path, item.line_start, item.line_end) for item in first.locations] == [
        ("app.py", 7, 9),
        ("app.py", 20, 22),
        ("db.py", 4, 4),
    ]
    assert first.cwe == ["CWE-89", "CWE-79"] and first.severity == "high"
    assert first.explanation == "e\n\nExploit conditions: c"
    assert "locations[0]: line range reversed" in first.deviations and first.dropped_locations == [
        {"location": 3, "reason": "missing path"}
    ]
    assert findings[1].title == "Finding" and findings[1].severity == "unknown" and findings[1].locations == []


def test_relative_paths() -> None:
    assert relative_path("file:///workspace/repo/a/b.py", None) == "a/b.py"
    assert relative_path("/home/x/project/a.py", None, ("/home/x/project",)) == "a.py"
    assert relative_path("/private/var/t/repo/a.py", "/var/t/repo") == "/private/var/t/repo/a.py"
    assert relative_path("/var/t/repo/a.py", "/private/var/t/repo") == "a.py"


@pytest.mark.slow
def test_a_repository_of_more_than_1000_files_takes_the_single_agent(rig, write_repo) -> None:
    files = {**counted_files(1001), **{name: text for name, text in WEBAPP.items() if name == "app.py"}}
    repo = write_repo(files)
    answer = {
        "findings": [
            {
                "title": "Command injection",
                "locations": [{"path": "app.py", "line_start": 57, "line_end": 57}],
                "cwe": ["CWE-78"],
                "severity": "critical",
                "evidence": "e",
                "exploit_conditions": "c",
            }
        ]
        * 9
    }
    outcome, fake = rig.audit(repo, extra_env={"FAKE_PI_FREE_ANSWER": json.dumps(answer)})
    assert outcome.exit_code == 0 and outcome.run["route"] == "agent"
    assert outcome.run["repository"]["files_counted"] == 1001
    # No direct model call: the agent alone, with the whole ceiling and the whole wall clock, and no output cap.
    assert fake.bodies == []
    [entry] = rig.pi_log()
    assert entry["argv"][entry["argv"].index("--model") + 1] == DEFAULT_MODEL and not entry["worker"]
    assert len(outcome.findings) == 9 and all(finding.engine == "single-agent" for finding in outcome.findings)
    assert outcome.run["engine"]["name"] == "single-agent" and outcome.run["engine"]["output"]["items"] == 9


@pytest.mark.slow
def test_an_output_folder_in_the_repository_gets_a_warning(rig, write_repo) -> None:
    repo = write_repo(counted_files(1001))
    outcome, _ = rig.audit(repo, out=repo / "results", extra_env={"FAKE_PI_FREE_ANSWER": json.dumps({"findings": []})})
    assert outcome.exit_code == 0
    assert "the output folder is in the audited repository" in outcome.run["warnings"][0]
