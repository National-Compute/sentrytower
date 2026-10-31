"""The scenarios of the golden request fixtures (``tests/golden/*.json``).

A golden fixture holds the model requests that the gateway sends upstream
in one scenario (a synthetic repository, the fake model and the fake Pi CLI),
byte for byte as a sorted list, and the commands of the agent sessions with
neutral paths. The release produced them. The scenarios run GLM 5.3 Flash
(``fakes.MODEL``), the model of the harness that the requests were compared
with: the requests are equal to what that harness sent in the same
scenario; the agent commands differ in one point, the repository guard
extension of the release.

Regenerate the fixtures only for a deliberate change of the model requests:

    python tests/golden.py --write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fakes import MODEL, FakeModel, fake_pi_package, fake_tools, read_jsonl  # noqa: E402
from synthetic import MIXED, WEBAPP, counted_files, line_of, many_modules, write_repository  # noqa: E402

GOLDEN = HERE / "golden"
_READ = line_of(WEBAPP, "files.py", "def read")
_PING = line_of(WEBAPP, "app.py", "os.system(")
_EXEC = line_of(WEBAPP, "static/app.js", "runner.exec(")
FREE_ANSWER = {
    "findings": [
        {
            "title": "Path traversal in read",
            "locations": [{"path": "files.py", "line_start": _READ, "line_end": _READ + 2, "note": "open"}],
            "cwe": ["CWE-22"],
            "severity": "high",
            "evidence": "`open(os.path.join(BASE, name))` takes the name of the request.",
            "exploit_conditions": "The attacker sends ../ in the name.",
        },
        {
            "title": "Command injection in ping",
            "locations": [{"path": "app.py", "line_start": _PING, "line_end": _PING}],
            "cwe": ["CWE-78"],
            "severity": "critical",
            "evidence": '`os.system("ping -c 1 " + host)`',
            "exploit_conditions": "The host.",
        },
    ]
}
SEARCHES = [
    {
        "tool": "grep",
        "arguments": {"pattern": "system", "path": "."},
        "output": f'app.py:{_PING}: os.system("ping -c 1 " + host)\nstatic/app.js:{_EXEC}:   runner.exec("ls " + req.query.dir);',
    },
    {"tool": "find", "arguments": {"pattern": "*.py"}, "output": "app.py\nfiles.py\nconfig_loader.py\ntests/test_app.py"},
]
SCENARIOS: dict[str, dict[str, Any]] = {
    # The funnel route with a free-roaming answer and search hits.
    "funnel-webapp": {"files": WEBAPP, "free": FREE_ANSWER, "searches": SEARCHES, "delays": {"unit-check": 1.5}},
    # The funnel route on code in Go, Java, PHP, Ruby and C.
    "funnel-mixed": {"files": MIXED, "free": {"findings": []}, "searches": [], "delays": {}},
    # The output caps of the funnel: more deep-check findings than 6.
    "funnel-caps": {"files": many_modules(6), "free": FREE_ANSWER, "searches": [], "delays": {}},
    # The agent route: more than 1,000 files.
    "agent-route": {"files": {**counted_files(1001), "app.py": WEBAPP["app.py"]}, "free": FREE_ANSWER, "searches": [], "delays": {}},
}
_TASK = re.compile(r"/tasks/t\d{5}")


def run_scenario(name: str, base: Path) -> dict[str, Any]:
    """Run one scenario with the release; return its requests and its agent sessions with neutral paths."""
    from sentrytower.audit import AuditRequest, Log, run_audit
    from sentrytower.config import load_config

    scenario = SCENARIOS[name]
    base = base.resolve()
    repo = write_repository(base / "repo", scenario["files"])
    pi_cli = fake_pi_package(base / "pi")
    tools = fake_tools(base / "tools")
    log = base / "pi.jsonl"
    environment = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(base / "home"),
        "SENTRYTOWER_API_KEY": "golden-key",
        "SENTRYTOWER_PI": str(pi_cli),
        "SENTRYTOWER_RG": str(tools["rg"]),
        "SENTRYTOWER_FD": str(tools["fd"]),
        "FUNNEL_INVENTORY_SCANNER": "python",
        "FAKE_PI_LOG": str(log),
        "FAKE_PI_SLEEP": "0.4",
        "FAKE_PI_FREE_ANSWER": json.dumps(scenario["free"]),
        "FAKE_PI_FREE_SEARCH": json.dumps(scenario["searches"]),
    }
    fake = FakeModel(delays=scenario["delays"])
    config = load_config(None, environment=environment, model=MODEL, max_tokens=2_000_000, wall_clock_seconds=3600)
    request = AuditRequest(repository=repo, out_dir=base / "out", state_dir=base / "state")
    outcome = run_audit(config, request, log=Log(quiet=True), environment=environment, transport=fake.transport)
    if outcome.exit_code != 0:
        raise RuntimeError(f"the scenario {name} failed: {outcome.run.get('failure')}")

    def neutral(text: str) -> str:
        text = text.replace(str(base / "state"), "<STATE>").replace(str(repo), "<REPO>").replace(str(pi_cli), "<PI>")
        text = text.replace(str(base), "<BASE>").replace(str(Path(sys.executable)), "<PYTHON>")
        text = re.sub(r"http://127\.0\.0\.1:\d+", "http://127.0.0.1:<PORT>", text)
        return _TASK.sub("/tasks/<TASK>", text)

    sessions = []
    for row in read_jsonl(log):
        argv = [neutral(part) for part in row["argv"]]
        prompt = argv[-1]
        session = {
            "argv": [*argv[:-1], f"<prompt sha256:{hashlib.sha256(prompt.encode()).hexdigest()}>"],
            "prompt": prompt if row["worker"] else None,
            "cwd": neutral(row["cwd"]),
            "env": {key: neutral(value) for key, value in row["env"].items()},
            "settings.json": row["config"]["settings.json"],
            "models.json": json.loads(neutral(json.dumps(row["config"]["models.json"]))),
        }
        sessions.append(session)
    sessions.sort(key=lambda item: json.dumps(item, sort_keys=True))
    return {
        "scenario": name,
        "route": outcome.run["route"],
        "requests": fake.requests(),
        "agent_sessions": sessions,
        "findings": [
            {
                "title": finding.title,
                "severity": finding.severity,
                "cwe": finding.cwe,
                "engine": finding.engine,
                "locations": [[location.path, location.start_line, location.end_line] for location in finding.locations],
            }
            for finding in outcome.findings
        ],
    }


def golden_path(name: str) -> Path:
    return GOLDEN / f"{name}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the golden request fixtures.")
    parser.add_argument("--write", action="store_true", help="write tests/golden/*.json")
    parser.add_argument("names", nargs="*", default=sorted(SCENARIOS))
    args = parser.parse_args()
    GOLDEN.mkdir(exist_ok=True)
    for name in args.names:
        with tempfile.TemporaryDirectory(prefix="st-golden-") as folder:
            result = run_scenario(name, Path(folder))
        text = json.dumps(result, indent=1, ensure_ascii=False) + "\n"
        if args.write:
            golden_path(name).write_text(text, encoding="utf-8")
        print(f"{name}: {len(result['requests'])} requests, {len(result['agent_sessions'])} agent sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
