"""The helper of the GitHub Action (scripts/github_action.py): what the Action shows, and its report.

The tests run the helper as the composite steps of ``action.yml`` run it: a
separate Python process with the environment of a step, an event payload
file, and the files $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeModel, FakeServer
from sentrytower.cli import main
from synthetic import WEBAPP, line_of

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "github_action.py"
TITLE = "SQL injection in the login form"
PATH = "app/db.py"


def run_helper(tmp_path: Path, command: str, environment: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], dict[str, str], str]:
    output, summary = tmp_path / "github-output", tmp_path / "step-summary"
    output.write_text("")
    summary.write_text("")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)}
    process = subprocess.run(
        [sys.executable, str(HELPER), command], check=False, env=env | environment, capture_output=True, text=True, timeout=60
    )
    values = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
    return process, values, summary.read_text()


def event(tmp_path: Path, repository: dict[str, Any] | None) -> str:
    path = tmp_path / "event.json"
    path.write_text(json.dumps({} if repository is None else {"repository": repository}))
    return str(path)


@pytest.mark.parametrize(
    ("repository", "event_name", "ref", "inputs", "expected"),
    [
        # A private repository gets the findings everywhere.
        ({"private": True, "default_branch": "main"}, "pull_request", "refs/pull/7/merge", {}, ("private", "false", "true", "true", "all")),
        (
            {"visibility": "internal", "private": True},
            "pull_request",
            "refs/pull/7/merge",
            {},
            ("internal", "false", "true", "true", "all"),
        ),
        # A public repository gets counts only; a pull request run uploads no SARIF.
        (
            {"private": False, "default_branch": "main"},
            "pull_request",
            "refs/pull/7/merge",
            {},
            ("public", "true", "false", "false", "record"),
        ),
        (
            {"visibility": "public", "default_branch": "main"},
            "pull_request_target",
            "refs/heads/main",
            {},
            ("public", "true", "false", "false", "record"),
        ),
        # The alert list of the default branch needs write access: auto uploads it.
        ({"private": False, "default_branch": "main"}, "push", "refs/heads/main", {}, ("public", "true", "false", "true", "record")),
        (
            {"private": False, "default_branch": "main"},
            "workflow_dispatch",
            "refs/heads/feature",
            {},
            ("public", "true", "false", "false", "record"),
        ),
        # The opt-in and the explicit inputs.
        (
            {"private": False, "default_branch": "main"},
            "pull_request",
            "refs/pull/7/merge",
            {"INPUT_PUBLIC_FINDINGS": "true"},
            ("public", "true", "true", "true", "all"),
        ),
        (
            {"private": False},
            "pull_request",
            "refs/pull/7/merge",
            {"INPUT_UPLOAD_SARIF": "true"},
            ("public", "true", "false", "true", "record"),
        ),
        (
            {"private": True},
            "push",
            "refs/heads/main",
            {"INPUT_UPLOAD_SARIF": "false", "INPUT_UPLOAD_ARTIFACT": "false"},
            ("private", "false", "true", "false", "none"),
        ),
    ],
)
def test_the_context_decides_what_the_action_shows(
    tmp_path: Path, repository: dict[str, Any], event_name: str, ref: str, inputs: dict[str, str], expected: tuple[str, ...]
) -> None:
    environment = {"GITHUB_EVENT_PATH": event(tmp_path, repository), "GITHUB_EVENT_NAME": event_name, "GITHUB_REF": ref} | inputs
    process, values, _ = run_helper(tmp_path, "context", environment)
    assert process.returncode == 0, process.stderr
    assert tuple(values[name] for name in ("visibility", "public", "details", "upload-sarif", "artifact")) == expected
    if expected[1] == "true" and expected[2] == "false":
        assert "::notice title=SentryTower::This repository is public" in process.stdout
    if expected[1] == "true" and expected[2] == "true":
        assert "::warning title=SentryTower::public-findings is true" in process.stdout


def test_a_wrong_input_is_a_usage_error(tmp_path: Path) -> None:
    environment = {"GITHUB_EVENT_PATH": event(tmp_path, {"private": True}), "INPUT_UPLOAD_SARIF": "yes"}
    process, values, _ = run_helper(tmp_path, "context", environment)
    assert process.returncode == 2 and "::error" in process.stdout and "upload-sarif" in process.stdout and not values


@pytest.fixture
def api() -> Iterator[tuple[str, list[dict[str, str]], dict[str, Any]]]:
    """A fake GitHub REST API: GET /repos/OWNER/REPO answers with ``answer``; each request's headers are kept."""
    headers: list[dict[str, str]] = []
    answer: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_GET(self) -> None:
            headers.append({key.lower(): value for key, value in self.headers.items()} | {"path": self.path})
            data = json.dumps(answer).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", headers, answer
    finally:
        server.shutdown()


def test_a_scheduled_run_asks_the_api_with_the_token_of_the_job(
    tmp_path: Path, api: tuple[str, list[dict[str, str]], dict[str, Any]]
) -> None:
    url, headers, answer = api
    answer.update(visibility="private", private=True, default_branch="main")
    environment = {
        "GITHUB_EVENT_PATH": event(tmp_path, None),
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_API_URL": url,
        "GITHUB_REPOSITORY": "example/app",
        "INPUT_TOKEN": "job-token",
    }
    process, values, _ = run_helper(tmp_path, "context", environment)
    assert process.returncode == 0, process.stderr
    assert values["visibility"] == "private" and values["details"] == "true" and values["upload-sarif"] == "true"
    assert headers[0]["path"] == "/repos/example/app" and headers[0]["authorization"] == "Bearer job-token"
    assert "job-token" not in process.stdout + process.stderr


def test_a_scheduled_run_of_a_public_repository_uploads_the_sarif_of_the_default_branch(
    tmp_path: Path, api: tuple[str, list[dict[str, str]], dict[str, Any]]
) -> None:
    url, _, answer = api
    answer.update(visibility="public", private=False, default_branch="main")
    environment = {"GITHUB_EVENT_PATH": event(tmp_path, None), "GITHUB_EVENT_NAME": "schedule", "GITHUB_API_URL": url}
    _, values, _ = run_helper(tmp_path, "context", environment | {"GITHUB_REPOSITORY": "example/app"})
    assert (values["public"], values["details"], values["upload-sarif"], values["artifact"]) == ("true", "false", "true", "record")


def test_an_unknown_visibility_shows_counts_only(tmp_path: Path) -> None:
    environment = {
        "GITHUB_EVENT_PATH": event(tmp_path, None),
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_API_URL": "http://127.0.0.1:9",
        "GITHUB_REPOSITORY": "example/app",
    }
    process, values, _ = run_helper(tmp_path, "context", environment)
    assert process.returncode == 0 and values["visibility"] == "unknown" and values["details"] == "false"
    assert "::warning title=SentryTower::the visibility of the repository is unknown" in process.stdout


def result(**changes: Any) -> dict[str, Any]:
    value = {
        "status": "complete",
        "stop_reason": "done",
        "stop_text": "The run checked every code unit.",
        "failure": None,
        "spent_usd": 1.234,
        "cap_usd": 2.0,
        "units": {"kind": "code units", "checked": 120, "failed": 3, "total": 400},
        "calls": {"total": 950, "failed": 12, "failed_share": 0.0126},
        "depth_factor": 1.0,
        "preview": False,
    }
    return value | changes


def write_outputs(folder: Path, run_result: dict[str, Any] | None, findings: list[dict[str, Any]], **run: Any) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    record = {"schema_version": "1.0.0", "status": "complete", "failure": None, "route": "funnel", "repository": {"files_counted": 412}}
    if run_result is not None:
        record["result"] = run_result
    (folder / "run.json").write_text(json.dumps(record | run))
    counts = {name: sum(1 for item in findings if item["severity"] == name) for name in ("critical", "high", "medium", "low", "unknown")}
    document = {"run": {"route": "funnel"}, "summary": {"findings": len(findings), "by_severity": counts}, "findings": findings}
    (folder / "findings.json").write_text(json.dumps(document))
    for name in ("findings.sarif", "report.md", "report.html"):
        (folder / name).write_text("{}")
    return folder


def finding(title: str = TITLE, severity: str = "high", path: str = PATH, **changes: Any) -> dict[str, Any]:
    value = {
        "title": title,
        "severity": severity,
        "location": {"path": path, "start_line": 42, "end_line": 44},
        "evidence": "The query joins the user name into the SQL text.",
        "tier": 1,
        "verification": "verified",
    }
    return value | changes


def report(
    tmp_path: Path, out: Path, code: int, *, details: bool, fail_on: str = "", sarif: bool = True
) -> tuple[subprocess.CompletedProcess[str], dict[str, str], str]:
    environment = {
        "AUDIT_OUT": str(out),
        "AUDIT_EXIT_CODE": str(code),
        "AUDIT_DETAILS": str(details).lower(),
        "AUDIT_FAIL_ON": fail_on,
        "AUDIT_UPLOAD_SARIF": str(sarif).lower(),
    }
    process = run_helper(tmp_path, "report", environment)
    assert process[0].returncode == 0, process[0].stderr
    return process


def test_the_report_of_a_private_repository_lists_the_findings(tmp_path: Path) -> None:
    findings = [finding(), finding("Path traversal in the download route", "medium", "app/files.py", tier=2, verification="unverified")]
    out = write_outputs(tmp_path / "out", result(), findings)
    process, values, summary = report(tmp_path, out, 0, details=True)
    assert values["count"] == "2" and values["status"] == "complete" and values["route"] == "funnel"
    assert values["findings"] == str(out / "findings.json") and values["sarif"] == str(out / "findings.sarif")
    assert summary.startswith("## SentryTower: complete")
    assert "| Spend | $1.23 of the $2.00 cap |" in summary and "| Checked | 120 of 400 code units, 3 failed |" in summary
    assert (
        "| Model calls | 950 (12 failed, 1.3%) |" in summary
        and "| Findings | 2: 0 critical, 1 high, 1 medium, 0 low, 0 unknown |" in summary
    )
    assert "The run checked every code unit\\." in summary
    assert "SQL injection in the login form" in summary and "app/db\\.py:42\\-44" in summary
    assert "unverified; second tier" in summary and "| Depth |" not in summary
    assert "::notice title=SentryTower::complete: 2 finding(s)" in process.stdout


def test_the_report_of_a_public_repository_shows_counts_only(tmp_path: Path) -> None:
    out = write_outputs(tmp_path / "out", result(), [finding(), finding("Command injection in ping", "critical", "app/ping.py")])
    process, values, summary = report(tmp_path, out, 1, details=False, fail_on="high")
    shown = summary + process.stdout + process.stderr
    for secret in (TITLE, "Command injection", "app/db", "app/ping", "db.py", ":42", "joins the user name"):
        assert secret not in shown
    assert "| Findings | 2: 1 critical, 1 high, 0 medium, 0 low, 0 unknown |" in summary
    assert "This repository is public, so this summary shows counts only" in summary and "go to code scanning" in summary
    _, _, summary = report(tmp_path, out, 0, details=False, sarif=False)
    assert "This run uploads no SARIF file: a run of the default branch" in summary
    assert "::error title=SentryTower::findings at or above high (1 critical, 1 high): exit code 1" in process.stdout
    assert values["count"] == "2"


def test_a_failed_run_gives_the_reason_of_the_run_record_whatever_fail_on_says(tmp_path: Path) -> None:
    failed = result(
        status="failed",
        stop_reason="provider-error",
        stop_text="The provider refused the key (HTTP 401).",
        failure="The run stopped before it checked a unit.",
        spent_usd=0.0,
        units={"kind": "code units", "checked": 0, "failed": 0, "total": 400},
    )
    out = write_outputs(tmp_path / "out", failed, [], status="failed")
    for fail_on in ("", "critical"):
        process, values, summary = report(tmp_path, out, 4, details=False, fail_on=fail_on)
        assert (
            "::error title=SentryTower::exit code 4 (the run failed or is incomplete): "
            "The provider refused the key (HTTP 401). The run stopped before it checked a unit." in process.stdout
        )
        assert (
            summary.startswith("## SentryTower: failed")
            and "| Why it is not complete | The run stopped before it checked a unit\\. |" in summary
        )
        assert "| Exit code | 4: the run failed or is incomplete |" in summary and values["status"] == "failed"


def test_a_run_that_is_not_complete_uploads_no_sarif_file(tmp_path: Path) -> None:
    refused = result(status="failed", stop_reason="provider-error", failure="The provider refused the key (HTTP 401).")
    _, _, summary = report(tmp_path, write_outputs(tmp_path / "out", refused, [], status="failed"), 4, details=True, sarif=True)
    assert "uploads no SARIF file: code scanning keeps the alerts of the last complete run" in summary
    # The upload step runs for a complete run only.
    step = (ROOT / "action.yml").read_text(encoding="utf-8").split("- name: Upload SARIF to code scanning", 1)[1].split("uses:", 1)[0]
    assert "steps.report.outputs.status == 'complete'" in step


def test_a_config_input_that_links_out_of_the_workspace_is_refused(tmp_path: Path) -> None:
    lines = (ROOT / "action.yml").read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.strip().startswith('config="$(python3'))
    end = next(index for index in range(start, len(lines)) if lines[index].strip() == "esac")
    block = tmp_path / "block.sh"
    block.write_text("\n".join(lines[start : end + 1]) + "\n", encoding="utf-8")
    workspace = tmp_path / "ws"
    (workspace / ".github").mkdir(parents=True)
    (workspace / ".github" / "real.toml").write_text("x = 1\n", encoding="utf-8")
    (workspace / ".github" / "inside.toml").symlink_to("real.toml")
    outside = tmp_path / "outside.toml"
    outside.write_text("x = 2\n", encoding="utf-8")
    (workspace / ".github" / "linked.toml").symlink_to(outside)
    script = 'refuse() { echo "REFUSED: $1"; exit 0; }; workspace="$(cd "${GITHUB_WORKSPACE}" && pwd -P)"; source "$1"; echo "ACCEPTED: ${config}"'
    answers = {}
    for name in ("real.toml", "inside.toml", "linked.toml", "missing.toml"):
        environment = {**os.environ, "GITHUB_WORKSPACE": str(workspace), "CONFIG": f".github/{name}"}
        answers[name] = subprocess.run(
            ["bash", "-c", script, "bash", str(block)], env=environment, capture_output=True, text=True, check=True
        ).stdout
    assert answers["real.toml"].startswith("ACCEPTED") and answers["inside.toml"].startswith("ACCEPTED")
    assert answers["linked.toml"] == "REFUSED: the config input must be a file of the workspace\n"
    assert answers["missing.toml"].startswith("REFUSED: the config input is not a file")


def test_an_audit_without_outputs_reports_its_exit_code(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    process, values, summary = report(tmp_path, out, 3, details=True)
    assert summary.startswith("## SentryTower: no result") and "exit code 3" in summary
    assert "::error title=SentryTower::exit code 3 (an environment problem" in process.stdout
    assert "count" not in values and values["status"] == ""


def test_the_report_reads_a_run_record_without_the_result_object(tmp_path: Path) -> None:
    out = write_outputs(tmp_path / "out", None, [finding()], usage={"total": {"calls": 10, "failures": 0, "cost_usd": 0.31}})
    _, values, summary = report(tmp_path, out, 0, details=True)
    assert values["status"] == "complete" and "| Spend | $0.31 (no cap) |" in summary and "| Model calls | 10 |" in summary


def test_a_deeper_run_carries_the_preview_label(tmp_path: Path) -> None:
    out = write_outputs(tmp_path / "out", result(cap_usd=10.0, depth_factor=4.2, preview=True), [])
    _, _, summary = report(tmp_path, out, 0, details=True)
    assert "| Depth | preview: more checks; effect on findings not yet measured |" in summary


def test_the_report_escapes_the_text_of_the_model(tmp_path: Path) -> None:
    hostile = "A <img src=x onerror=alert(1)> [link](https://example.com) | cell\n::error::forged `code` **bold**"
    out = write_outputs(
        tmp_path / "out", result(stop_text="Stopped.\n::warning::forged annotation"), [finding(hostile, path="a|b.py\n::x::")]
    )
    process, _, summary = report(tmp_path, out, 4, details=True)
    rows = [line for line in summary.splitlines() if line.startswith("| high |")]
    assert len(rows) == 1 and rows[0].count(" | ") == 3
    # Each markup character has a backslash in front, and no line starts a workflow command.
    assert not re.search(r"(?<!\\)[<>\[\]()`*|]", rows[0].replace(" | ", "")[1:-1])
    assert "\\<img" in summary and "\\[link\\]" in summary and "\\|" in summary and "\n::" not in summary
    assert "\n::warning::forged" not in process.stdout and "%0A::warning::forged annotation" in process.stdout


@pytest.mark.slow
def test_the_plain_log_of_an_audit_holds_no_text_of_a_finding(rig, write_repo, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """On a public repository the Action shows the log of the audit to every reader: it must hold counts, not findings."""
    for name in list(os.environ):
        if name.startswith(("SENTRYTOWER_", "OPENROUTER_")):
            monkeypatch.delenv(name)
    for name, value in rig.environment.items():
        monkeypatch.setenv(name, value)
    line = line_of(WEBAPP, "files.py", "def read")
    answer = {
        "findings": [
            {
                "title": "Marker title of the download route",
                "locations": [{"path": "files.py", "line_start": line, "line_end": line + 2}],
                "cwe": ["CWE-22"],
                "severity": "high",
                "evidence": "Marker evidence of the finding.",
                "exploit_conditions": "Marker conditions of the finding.",
            }
        ]
    }
    monkeypatch.setenv("FAKE_PI_FREE_ANSWER", json.dumps(answer))
    out = rig.base / "out"
    with FakeServer(FakeModel()) as server:
        code = main(["audit", str(write_repo(WEBAPP)), "--out", str(out), "--base-url", server.url, "--plain"])
    log = capsys.readouterr()
    findings = json.loads((out / "findings.json").read_text())["findings"]
    assert code == 0 and any(item["title"] == "Marker title of the download route" for item in findings)
    for text in ("Marker title", "Marker evidence", "Marker conditions", f"files.py:{line}"):
        assert text not in log.out + log.err
