#!/usr/bin/env python3
"""The real-model smoke of a release: seven audits through the container image, then a check of each result.

    python3 scripts/release/smoke.py --image sentrytower:smoke --work ~/sentrytower-smoke --yes

The maintainer runs it before a release tag. It spends real money, at most the
sum of the caps ($25), and it reads two OpenRouter keys from the environment:

- ``SENTRYTOWER_API_KEY``: a key with credit, for five runs;
- ``SMOKE_NOCREDIT_KEY``: a key with a credit limit of $0.01, for the run that
  must stop when the provider refuses the account.

The seventh run uses a key that is not valid and must stop on HTTP 401. The
keys reach each container only in its environment; this script never prints
them. The repositories are public and pinned to a commit.

The smoke passes when:

- no run is falsely clean: a complete run made model calls, checked units, had
  at most 20% failed calls and no provider refusal, and exited with 0;
- every run stays within its cost cap;
- $2 gives depth factor 1 (the standard run, with the measured pacing), and
  $10 gives a depth above 1 with the preview label;
- the runs with a refused key or account fail with exit code 4.

The report (``smoke-report.md`` and ``smoke-report.json`` in the folder of the
runs) gives one line for each run. ``--fake`` runs the same plan against local
fake endpoints (no key, no cost) to test this script; ``--check FOLDER`` checks
the runs of an earlier smoke again.

Standard library only; Python 3.9 or later.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPOSITORIES = {
    "DVWA": ("https://github.com/digininja/DVWA", "a1978a2fed195acd093010af6395f86a281537ca"),
    "nginx": ("https://github.com/nginx/nginx", "67290bfea61c81347464539f5e6d0a7cebec1fc8"),
    "juice-shop": ("https://github.com/juice-shop/juice-shop", "717f5efa886b0417eeecb52378b03cf10567b7e2"),
}
EXPENSIVE_MODEL = "moonshotai/kimi-k2.5"
# The OpenRouter list prices of the expensive model on 2026-10-31, in US dollars for one million tokens.
EXPENSIVE_POLICY = f"""[policies."{EXPENSIVE_MODEL}"]
input_cost_per_million = 0.5
output_cost_per_million = 2.5
cache_read_cost_per_million = 0.15
context_window = 262144
max_output_tokens = 235929
"""
INVALID_KEY = "invalid-smoke-key"
OUTPUTS = ("run.json", "findings.json", "findings.sarif", "report.md", "report.html")
FAILED_SHARE_LIMIT = 0.2


@dataclass(frozen=True)
class Run:
    """One audit of the smoke and what its result must show."""

    name: str
    repository: str
    route: str
    wall_clock: int
    cap: float | None = None  # None: the default cap of the command line
    expected_cap: float = 2.0
    key: str = "main"  # main, nocredit or invalid
    model: str | None = None
    depth: str = "one"  # one: depth factor 1; more: above 1, with the preview label
    refused: int | None = None  # the HTTP status of a provider refusal that must stop the run
    standard: bool = False  # the standard run: the measured token pacing, no soft stop
    money_ends: bool = False  # dollars end the run: a soft stop at 85% of the cap


RUNS = (
    Run("invalid-key", "DVWA", "funnel", 900, key="invalid", refused=401),
    Run("no-credit", "DVWA", "funnel", 900, key="nocredit", refused=402),
    Run("standard-funnel", "DVWA", "funnel", 3600, standard=True),
    Run("standard-agent", "juice-shop", "agent", 3600, standard=True),
    Run("expensive-model", "DVWA", "funnel", 3600, cap=1.0, expected_cap=1.0, model=EXPENSIVE_MODEL, money_ends=True),
    Run("deep-funnel", "nginx", "funnel", 7200, cap=10.0, expected_cap=10.0, depth="more", money_ends=True),
    Run("deep-agent", "juice-shop", "agent", 7200, cap=10.0, expected_cap=10.0, depth="more", money_ends=True),
)
# Two lanes: the deep runs one after the other, the rest in the other lane, so that at most one deep run
# (up to one agent session for each CPU) runs at a time.
LANES = (("deep-funnel", "deep-agent"), ("invalid-key", "no-credit", "standard-funnel", "standard-agent", "expensive-model"))


def lane_plan(names: list[str], lanes: str) -> list[list[str]]:
    """The runs of each lane: the lanes run at the same time, the runs of one lane one after the other."""
    if lanes == "1":
        # One lane: the short runs first, then the deep runs.
        return [[name for lane in reversed(LANES) for name in lane if name in names]]
    if lanes == "all":
        return [[name] for name in names]
    return [[name for name in lane if name in names] for lane in LANES]


def check(run: Run, code: int | None, out: Path) -> tuple[list[str], list[str], dict[str, Any]]:
    """The problems (the smoke fails), the notes (honest but unexpected) and the summary of one run."""
    problems: list[str] = []
    notes: list[str] = []
    missing = [name for name in OUTPUTS if not (out / name).is_file()]
    if missing:
        problems.append("missing outputs: " + ", ".join(missing))
    try:
        record = json.loads((out / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        problems.append(f"no readable run.json (exit code {code})")
        return problems, notes, {"exit": code}
    result = record.get("result") or {}
    usage = (record.get("usage") or {}).get("total") or {}
    budget = record.get("budget") or {}
    status, calls, units = result.get("status"), result.get("calls") or {}, result.get("units") or {}
    spent, cap, factor = result.get("spent_usd"), result.get("cap_usd"), result.get("depth_factor")
    refusal = usage.get("provider_error") or {}
    summary = {
        "exit": code,
        "route": record.get("route"),
        "status": status,
        "stop_reason": result.get("stop_reason"),
        "stop_text": result.get("stop_text"),
        "failure": result.get("failure"),
        "spent_usd": spent,
        "cap_usd": cap,
        "depth_factor": factor,
        "preview": result.get("preview"),
        "units": units,
        "calls": calls,
        "findings": (record.get("findings") or {}).get("count"),
        "seconds": record.get("seconds"),
        "provider_status": refusal.get("status"),
    }

    # 1. No run is falsely clean.
    if status == "complete":
        if not calls.get("total"):
            problems.append("complete with no model call")
        if not units.get("checked"):
            problems.append("complete with no checked unit")
        if float(calls.get("failed_share") or 0) > FAILED_SHARE_LIMIT:
            problems.append(f"complete with {calls.get('failed_share'):.0%} failed calls")
        if refusal:
            problems.append(f"complete after a provider refusal (HTTP {refusal.get('status')})")
        if code != 0:
            problems.append(f"complete, but exit code {code}")
    elif code == 0:
        problems.append(f"exit code 0, but the status is {status}")

    # 2. Every run stays within its cap.
    if cap != run.expected_cap:
        problems.append(f"the cap is {cap}, expected {run.expected_cap}")
    if cap is not None and spent is None:
        problems.append("a run with a cap reports no spend")
    elif cap is not None and spent > cap:
        problems.append(f"spent ${spent:.4f}, above the cap of ${cap:.2f}")

    # 3. The depth: $2 is the standard run; $10 buys more, with the preview label.
    if run.depth == "one" and factor != 1:
        problems.append(f"depth factor {factor}, expected 1")
    if run.depth == "more" and not (isinstance(factor, (int, float)) and factor > 1 and result.get("preview") is True):
        problems.append(f"depth factor {factor} and preview {result.get('preview')}, expected above 1 with the preview label")
    # The standard run of the funnel has no soft stop; on the agent route the soft stop is at 85% of each cap.
    soft_stop = None if run.route == "funnel" else round(0.85 * run.expected_cap, 6)
    if run.standard and (budget.get("token_ceiling_source") != "standard run" or budget.get("soft_stop_usd") != soft_stop):
        problems.append("not the standard run: " + json.dumps({key: budget.get(key) for key in ("token_ceiling_source", "soft_stop_usd")}))
    if run.money_ends and budget.get("soft_stop_usd") is None:
        problems.append("dollars do not end this run: no soft stop")

    # 4. The status of each run.
    if record.get("route") != run.route:
        notes.append(f"route {record.get('route')}, expected {run.route}")
    if run.refused is not None:
        if status != "failed" or result.get("stop_reason") != "provider-error" or code != 4:
            problems.append(
                f"a refused key or account must fail with exit 4: status {status}, stop {result.get('stop_reason')}, exit {code}"
            )
        if refusal and refusal.get("status") != run.refused:
            notes.append(f"the provider answered HTTP {refusal.get('status')}, expected {run.refused}")
        if run.key == "invalid" and spent not in (0, 0.0):
            problems.append(f"a key that is not valid spent ${spent}")
    elif status != "complete":
        notes.append(f"status {status}: {result.get('failure')}")
    return problems, notes, summary


class _Refuse(BaseHTTPRequestHandler):
    status = 401

    def log_message(self, *_: object) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("content-length") or 0))
        body = json.dumps({"error": {"code": self.status, "message": "refused by the fake endpoint of the smoke"}}).encode()
        self.send_response(self.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST  # noqa: N815 - the name of the method of http.server


def _refusing_server(status: int) -> ThreadingHTTPServer:
    handler = type(f"Refuse{status}", (_Refuse,), {"status": status})
    # All interfaces: a container reaches the host through host.docker.internal (on Linux the bridge gateway).
    server = ThreadingHTTPServer(("0.0.0.0", 0), handler)  # noqa: S104
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _fake_endpoint(root: Path, work: Path) -> tuple[subprocess.Popen[bytes], int]:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    log = (work / "fake-endpoint.log").open("wb")
    process = subprocess.Popen(
        [sys.executable, str(root / "tests" / "smoke" / "fake_endpoint.py"), "--host", "0.0.0.0", "--port", str(port)],  # noqa: S104 - see _refusing_server
        stdout=log,
        stderr=log,
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return process, port
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise SystemExit("smoke: the fake endpoint does not answer")


def fetch(name: str, folder: Path) -> Path:
    """The repository ``name`` at its pinned commit in ``folder`` (fetched once)."""
    url, commit = REPOSITORIES[name]
    target = folder / name
    head = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
    if head.returncode == 0 and head.stdout.strip() == commit:
        return target
    target.mkdir(parents=True, exist_ok=True)
    for argv in (
        ["git", "init", "-q"],
        ["git", "fetch", "-q", "--depth", "1", url, commit],
        ["git", "checkout", "-q", "--force", "FETCH_HEAD"],
    ):
        subprocess.run(argv, cwd=target, check=True)
    return target


def docker_argv(run: Run, image: str, repository: Path, out: Path, config: Path | None, base_url: str | None) -> list[str]:
    """The docker run command of one audit, with the flags of the GitHub Action; the key comes from the environment."""
    uid, gid = os.getuid(), os.getgid()
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"sentrytower-smoke-{run.name}-{os.getpid()}",
        "--user",
        f"{uid}:{gid}",
        "--read-only",
        "--tmpfs",
        f"/home/dev:rw,nosuid,nodev,size=4g,uid={uid},gid={gid}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=1g",  # noqa: S108 - a tmpfs inside the container
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        "SENTRYTOWER_API_KEY",
        "-v",
        f"{repository}:/workspace/repo:ro",
        "-v",
        f"{out}:/workspace/out",
    ]
    if config is not None:
        argv += ["-v", f"{config}:/workspace/sentrytower.toml:ro"]
    if base_url is not None:
        argv += ["--add-host=host.docker.internal:host-gateway"]
    argv += [image, "audit", "/workspace/repo", "--out", "/workspace/out", "--wall-clock", str(run.wall_clock)]
    if run.cap is not None:
        argv += ["--max-cost-usd", f"{run.cap:g}"]
    if run.model is not None:
        argv += ["--model", run.model]
    if config is not None:
        argv += ["--config", "/workspace/sentrytower.toml"]
    if base_url is not None:
        argv += ["--base-url", base_url]
    return argv


def run_one(
    run: Run, *, image: str, repository: Path, folder: Path, config: Path | None, key: str, base_url: str | None, lock: threading.Lock
) -> dict[str, Any]:
    out = folder / run.name / "out"
    out.mkdir(parents=True, exist_ok=True)
    environment = {name: value for name, value in os.environ.items() if name not in ("SMOKE_NOCREDIT_KEY", "SENTRYTOWER_API_KEY")}
    environment["SENTRYTOWER_API_KEY"] = key
    argv = docker_argv(run, image, repository, out, config if run.model else None, base_url)
    with lock:
        print(f"smoke: {run.name} started ({run.repository}, cap {'default' if run.cap is None else f'${run.cap:g}'})", flush=True)
    started = time.monotonic()
    with (folder / run.name / "log.txt").open("wb") as log:
        try:
            code: int | None = subprocess.run(
                argv, check=False, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=run.wall_clock + 1800
            ).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "stop", argv[argv.index("--name") + 1]], check=False, capture_output=True)
            code = None
    problems, notes, summary = check(run, code, out)
    summary.update(name=run.name, problems=problems, notes=notes, minutes=round((time.monotonic() - started) / 60, 1))
    with lock:
        print(
            f"smoke: {run.name} {'PASS' if not problems else 'FAIL'}: {summary.get('status')}, exit {code}, "
            f"spent {summary.get('spent_usd')} of {summary.get('cap_usd')}, {summary['minutes']} min",
            flush=True,
        )
    return summary


def report(folder: Path, summaries: list[dict[str, Any]], image: str) -> bool:
    passed = all(not item["problems"] for item in summaries)
    lines = [
        f"# SentryTower real-model smoke: {'PASS' if passed else 'FAIL'}",
        "",
        f"Image `{image}`, {datetime.now().astimezone().isoformat(timespec='seconds')}.",
        "",
        "| Run | Route | Status | Exit | Stop | Spent / cap | Depth | Units checked | Calls (failed) | Findings | Minutes | Verdict |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in summaries:
        units, calls = item.get("units") or {}, item.get("calls") or {}
        spent = "?" if item.get("spent_usd") is None else f"${item['spent_usd']:.4f}"
        cap = "none" if item.get("cap_usd") is None else f"${item['cap_usd']:g}"
        lines.append(
            f"| {item['name']} | {item.get('route')} | {item.get('status')} | {item.get('exit')} | {item.get('stop_reason')} | "
            f"{spent} / {cap} | {item.get('depth_factor')} | {units.get('checked')} of {units.get('total')} {units.get('kind', '')} | "
            f"{calls.get('total')} ({calls.get('failed')}) | {item.get('findings')} | {item.get('minutes')} | "
            f"{'PASS' if not item['problems'] else 'FAIL'} |"
        )
    for item in summaries:
        if item["problems"] or item["notes"] or item.get("failure"):
            lines += ["", f"## {item['name']}", "", f"- Stop: {item.get('stop_text')}"]
            lines += [f"- Failure: {item['failure']}"] if item.get("failure") else []
            lines += [f"- Problem: {text}" for text in item["problems"]] + [f"- Note: {text}" for text in item["notes"]]
    total = sum(float(item.get("spent_usd") or 0) for item in summaries)
    lines += ["", f"Total spend: ${total:.2f}.", ""]
    (folder / "smoke-report.md").write_text("\n".join(lines), encoding="utf-8")
    (folder / "smoke-report.json").write_text(
        json.dumps({"passed": passed, "image": image, "runs": summaries}, indent=2) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))
    return passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="sentrytower:smoke", help="the image to test (default: sentrytower:smoke)")
    parser.add_argument("--build", action="store_true", help="build the image from this checkout first")
    parser.add_argument("--work", type=Path, default=Path.home() / "sentrytower-smoke", help="the folder of the repositories and the runs")
    parser.add_argument("--only", help="comma-separated run names (default: all seven)")
    parser.add_argument(
        "--lanes",
        choices=("1", "2", "all"),
        default="2",
        help="1: one run at a time; 2: the deep runs beside the rest (default); all: every run at the same time, the fastest",
    )
    parser.add_argument("--fake", action="store_true", help="local fake endpoints, no key and no cost: a test of this script")
    parser.add_argument("--check", type=Path, metavar="FOLDER", help="check the runs of an earlier smoke again")
    parser.add_argument("--yes", action="store_true", help="start the runs that spend money (without --fake)")
    args = parser.parse_args(argv)
    runs = [run for run in RUNS if not args.only or run.name in args.only.split(",")]
    if not runs:
        parser.error("--only names no run: " + ", ".join(run.name for run in RUNS))

    if args.check is not None:
        checked = []
        for run in runs:
            problems, notes, summary = check(run, None, args.check / run.name / "out")
            summary.update(name=run.name, problems=problems, notes=notes, minutes=None)
            checked.append(summary)
        return 0 if report(args.check, checked, args.image) else 1

    keys = {"invalid": INVALID_KEY}
    if args.fake:
        keys.update(main="smoke", nocredit="smoke")
    else:
        keys.update(main=os.environ.get("SENTRYTOWER_API_KEY", ""), nocredit=os.environ.get("SMOKE_NOCREDIT_KEY", ""))
        needed = {run.key for run in runs} - {"invalid"}
        unset = [
            name
            for name, variable in (("main", "SENTRYTOWER_API_KEY"), ("nocredit", "SMOKE_NOCREDIT_KEY"))
            if name in needed and not keys[name]
        ]
        if unset:
            parser.error("set " + " and ".join("SENTRYTOWER_API_KEY" if name == "main" else "SMOKE_NOCREDIT_KEY" for name in unset))
        if "nocredit" in needed and keys["nocredit"] == keys["main"]:
            parser.error("SMOKE_NOCREDIT_KEY must be another key than SENTRYTOWER_API_KEY: a key with a credit limit of $0.01")
        caps = sum(2.0 if run.cap is None and run.key == "main" else (run.cap or 0.0) for run in runs if run.key == "main")
        print(f"smoke: {len(runs)} runs on OpenRouter with {args.image}; at most ${caps:.2f} with the main key and $0.01 with the other.")
        if not args.yes:
            print("smoke: add --yes to start them.")
            return 2

    if args.build:
        subprocess.run(["docker", "build", "-f", str(ROOT / "docker" / "Dockerfile"), "-t", args.image, str(ROOT)], check=True)
    version = subprocess.run(["docker", "run", "--rm", args.image, "--version"], check=False, capture_output=True, text=True)
    if version.returncode != 0:
        print(f"smoke: the image {args.image} does not run: {version.stderr.strip()[-300:]}", file=sys.stderr)
        return 2
    print(f"smoke: {version.stdout.strip()}", flush=True)

    work = args.work.expanduser().absolute()
    folder = work / f"runs-{datetime.now().strftime('%Y%m%d-%H%M%S')}{'-fake' if args.fake else ''}"
    folder.mkdir(parents=True)
    repositories = {name: fetch(name, work / "repos") for name in sorted({run.repository for run in runs})}
    config = work / "expensive-model.toml"
    config.write_text(EXPENSIVE_POLICY, encoding="utf-8")

    base_urls: dict[str, str | None] = {"main": None, "nocredit": None, "invalid": None}
    servers: list[Any] = []
    endpoint = None
    if args.fake:
        endpoint, port = _fake_endpoint(ROOT, folder)
        servers = [_refusing_server(401), _refusing_server(402)]
        base_urls = {
            "main": f"http://host.docker.internal:{port}/v1",
            "invalid": f"http://host.docker.internal:{servers[0].server_address[1]}/v1",
            "nocredit": f"http://host.docker.internal:{servers[1].server_address[1]}/v1",
        }

    lock = threading.Lock()
    by_name = {run.name: run for run in runs}
    lanes = lane_plan(list(by_name), args.lanes)
    summaries: dict[str, dict[str, Any]] = {}

    def lane_worker(names: list[str]) -> None:
        for name in names:
            run = by_name[name]
            summaries[name] = run_one(
                run,
                image=args.image,
                repository=repositories[run.repository],
                folder=folder,
                config=config,
                key=keys[run.key],
                base_url=base_urls[run.key],
                lock=lock,
            )

    threads = [threading.Thread(target=lane_worker, args=(lane,)) for lane in lanes if lane]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if endpoint is not None:
        endpoint.terminate()
    for server in servers:
        server.shutdown()
    return 0 if report(folder, [summaries[run.name] for run in runs if run.name in summaries], args.image) else 1


if __name__ == "__main__":
    raise SystemExit(main())
