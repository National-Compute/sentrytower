"""The orchestrator of the funnel engine: SentryTower's engine for repositories of up to 1,000 files.

A free agent chooses badly what to read in a repository, and it stops early.
In the funnel the orchestrator selects the code to read, divides the budget
and decides when to stop. The agent does not. One run, behind one model
gateway and one token ceiling:

- t = 0: the free-roaming session (the single agent on the whole
  repository, with a share of the token ceiling) and phase 0 (the
  deterministic inventory of ``funnel.inventory``, in its own process, with
  a deadline) start at the same time.
- Phase 1: the model rates unit cards in batches, when phase 2 cannot check
  each unit. The deterministic rank and the rating give the queue order.
  Each grep match and find file of an agent session adds to the score of the
  unit around it, or adds a window unit (``hits.py``).
- Phase 2: one model call for each unit of the queue, with a plain question
  and a structured answer. Each finding of the answer becomes a lead. A lead
  is never an output finding.
- Triage: one blind verification call for each new lead (the prompt and the
  message of phase 4 on the line of the lead). Its keep score orders the
  units for the deep checks; a "safe" verdict goes after all others.
- Phase 3: one deep-check agent session for each unit with a triaged lead
  (the best triage score first), with the settings of the single agent and a
  narrow task: report only a vulnerability with a concrete path of attacker
  data to the operation. The findings of the deep checks and of the
  free-roaming session are the output candidates.
- Phase 4: line resolution, a blind verification call for each candidate
  (the score ranks), duplicates and the output caps. The orchestrator writes
  the findings file again after each change, so a stop at any time leaves a
  valid run.
- The reserve: more unit checks, then more deep checks.

The phases overlap: a lead goes to a deep check while the unit checks go on.
The orchestrator owns the stop: the queue is empty, or the used tokens or
the time reached the stop level. A deep check that ends ends itself only.

With a cost cap (``money`` of the spec) the orchestrator reads the money of
the run from the gateway (``GET /budget``): at 85% of the cap no new work
starts (the running sessions get their final turns), and when dollars end
the run (``money.extend``) the token plan grows while the cap still has
money, so that the estimate of the token price does not end the run.

Standard library only. ``python -m sentrytower.funnel --spec SPEC.json``
starts one run (``run_main``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..limits import read_budget
from .hits import SearchHit, search_hits
from .model_client import BUDGET_REFUSED, DEADLINE, STOPPED, TIMEOUT, CallResult, ModelClient, estimate_tokens
from .pacing import FREE_POOL, Budget, Clock, Parameters
from .paths import PathClasses
from .protocols import CONFIDENCES, FUNNEL_VERSION, ParseError, Setup, combine_votes, load_setup, read_prompt, render
from .records import (
    FINDINGS_FILE,
    FINDINGS_SCHEMA,
    HITS_FILE,
    INVENTORY_FILE,
    LEADS_FILE,
    LEDGER_FILE,
    RECORD_FILE,
    SUMMARY_FILE,
    SUMMARY_SCHEMA,
    WORKERS_FILE,
    Ledger,
    append_jsonl,
    atomic_write_json,
    cap_inventory,
    read_json,
)
from .resolve import (
    FOCUS_SOURCE,
    FREE_SOURCE,
    SWEEP_SOURCE,
    UNVERIFIED_SCORE,
    Finding,
    configure_root,
    final_locations,
    finding_from_item,
    finding_item,
    rank_key,
    resolve_first,
    resolve_path,
    select_output,
)
from .slices import (
    SourceFiles,
    claim_message,
    containing_unit,
    target_cwe,
    unit_card,
    unit_classes,
    unit_code,
    unit_range,
    unit_routes,
)
from .workers import TEMPLATE_AGENT, PiSession, PlainCommand, TaskSessions, stop_sessions

RECORD_SCHEMA_VERSION = 1
SPEC_SCHEMA = "sentrytower-funnel-spec-v1"
EXIT_REFUSED = 70
EXIT_ERROR = 1
EXIT_TERMINATED = 143
POLL_SECONDS = 0.5
STATUS_SECONDS = 30.0
FREE_SESSION = "free"
PHASE0_LOG = "phase0.log"
INVENTORY_FULL = "inventory-full.json"
TASKS = "tasks"
# The passes after the queues (depth_passes): the focus paragraph, the lenses, and the files of a repository
# with native code (its focus sessions start with memory safety).
FOCUS_PROMPT = "funnel-focus.txt"
FOCUS_LENSES = "funnel-focus-lenses.txt"
NATIVE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".m", ".mm", ".rs", ".zig")
# The roles of a run: the direct calls, the deep checks and the free-roaming session.
ROLES = ("rating", "unit_check", "triage", "verify", "deep_check", "free_roaming")
CALL_ROLES = {"rating": "rating", "unit-check": "unit_check", "triage": "triage", "verify": "verify"}
# The stop reasons of the run (funnel-run.json, "stop").
STOP_QUEUE = "queue-empty"
STOP_TOKENS = "token-stop"
STOP_TIME = "time-stop"
STOP_REFUSED = "budget-refused"
STOP_TERMINATED = "terminated"
STOP_END = "end-of-time"
# Work is left, but no pool has the tokens (or the time) for its next task.
STOP_BLOCKED = "budget-blocked"
# Phase 2 reached max_unit_checks, and no other work is left.
STOP_CAP = "unit-check-cap"
# 85% of the cost cap is spent: no new work (the gateway says so, GET /budget).
STOP_MONEY = "budget-stop"
# Dollars end the run, and the money left before 85% of the cap buys no more tokens for the next task.
STOP_MONEY_LEFT = "budget-left"
# The orchestrator reads the money of the run at most this often, and grows its plan by at least this share.
MONEY_POLL_SECONDS = 1.0
MONEY_GROW_MIN_FRACTION = 0.02
MONEY_GREW = "grew"
MONEY_SPENT = "spent"
# The stop of the sessions that still run at the end: all at the same time,
# SIGKILL after this grace. After SIGTERM (or at the stop level of the wall
# clock) the grace is short, so that the stop and the files fit in the stop
# grace of the caller.
TERMINATED_STOP_GRACE = 5.0
END_STOP_GRACE = 30.0
CONFIDENCE_RANK = {name: rank for rank, name in enumerate(CONFIDENCES)}
# The search hits that wait for the queue (phase 0 runs), and the rows of
# the hit file of a run.
PENDING_HITS_LIMIT = 50_000
HIT_ROWS_LIMIT = 50_000


def now_text() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class RunSpec:
    """The inputs of one funnel run (the spec file that the caller writes).

    ``models`` gives the model of each role; ``completion_ceilings`` gives
    the completion ceiling of the model policy of each model (the gateway
    reserves it for each call). ``agent_command`` is the command of the
    single agent (runner, ``--``, Pi command, prompt) and ``agent_env`` its
    variables.
    """

    repository: Path
    work_dir: Path
    token_ceiling: int
    wall_clock_seconds: int
    model_base_url: str
    models: dict[str, str]
    completion_ceilings: dict[str, int]
    agent_command: list[str]
    agent_env: list[tuple[str, str]]
    parameters: dict[str, Any] = field(default_factory=dict)
    # The cost cap of the run (None without a cap): cap_usd, soft_stop_usd, price_per_million (the estimate),
    # extend (dollars end the run: the plan grows while money is left) and token_limit (None: no token ceiling).
    money: dict[str, Any] | None = None

    @property
    def default_model(self) -> str:
        return self.models["unit_check"]

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> RunSpec:
        if not isinstance(document, dict) or document.get("schema") != SPEC_SCHEMA:
            raise ValueError(f"the spec is not a {SPEC_SCHEMA} document")
        models = document.get("models")
        if (
            not isinstance(models, dict)
            or set(models) != set(ROLES)
            or not all(isinstance(value, str) and value for value in models.values())
        ):
            raise ValueError(f"the spec must name one model for each role: {', '.join(ROLES)}")
        ceilings = document.get("completion_ceilings") or {}
        if not isinstance(ceilings, dict) or any(model not in ceilings for model in models.values()):
            raise ValueError("the spec must give the completion ceiling of each model")
        command = document.get("agent_command")
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command) or "--" not in command:
            raise ValueError("the spec has no agent command")
        environment = document.get("agent_env") or {}
        if not isinstance(environment, dict):
            raise ValueError("agent_env must be an object")
        pairs = parse_pairs([f"{name}={value}" for name, value in environment.items()])
        token_ceiling, wall_clock = document.get("token_ceiling"), document.get("wall_clock_seconds")
        if not isinstance(token_ceiling, int) or not isinstance(wall_clock, int) or token_ceiling < 1 or wall_clock < 1:
            raise ValueError("the token ceiling and the wall clock must be positive integers")
        if not isinstance(document.get("model_base_url"), str) or not document["model_base_url"]:
            raise ValueError("the spec has no model base URL")
        return cls(
            repository=Path(str(document.get("repository") or Path.cwd())).absolute(),
            work_dir=Path(str(document["work_dir"])).absolute(),
            token_ceiling=token_ceiling,
            wall_clock_seconds=wall_clock,
            model_base_url=document["model_base_url"],
            models=dict(models),
            completion_ceilings={str(name): int(value) for name, value in ceilings.items()},
            agent_command=list(command),
            agent_env=pairs,
            parameters=dict(document.get("parameters") or {}),
            money=dict(document["money"]) if isinstance(document.get("money"), dict) else None,
        )


@dataclass
class CallTask:
    id: str
    kind: str
    pool: str
    estimate: int
    messages: list[dict[str, Any]]
    started: float
    unit_ids: list[str] = field(default_factory=list)
    finding_id: str | None = None
    # The line ranges of the code that the call showed.
    shown: list[tuple[int, int]] = field(default_factory=list)
    lead_id: str | None = None


@dataclass
class Lead:
    """A finding of a unit check: a place for a deep check, never an output finding."""

    id: str
    unit_id: str
    path: str
    line: int
    end_line: int
    quote: str
    cwe: str | None
    confidence: str
    source: str
    queue_score: float
    resolution: str | None
    status: str = "queued"
    worker: str | None = None
    # The triage: pending, running, done, failed, skipped (no tokens) or
    # not-needed (the unit had its deep check first).
    triage_status: str = "pending"
    triage_verdict: str | None = None
    triage_score: float | None = None

    @property
    def triaged(self) -> bool:
        """The lead can go to a deep check: its triage ended (or cannot run)."""
        return self.triage_status in ("done", "failed", "skipped")

    def rank(self) -> tuple[int, float, int, float]:
        """The order of the leads for the deep checks: a "safe" verdict after all others, then the
        triage score (0.5 without one), the confidence of the unit check and the queue score."""
        score = UNVERIFIED_SCORE if self.triage_score is None else float(self.triage_score)
        return (1 if self.triage_verdict == "safe" else 0, -score, CONFIDENCE_RANK.get(self.confidence, 9), -self.queue_score)

    def record(self) -> dict[str, Any]:
        """The row of the lead file: places and codes, no code text and no reason."""
        return {
            "id": self.id,
            "unit_id": self.unit_id,
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "source": self.source,
            "queue_score": round(self.queue_score, 6),
            "resolution": self.resolution,
            "status": self.status,
            "worker": self.worker,
            "triage_status": self.triage_status,
            "triage_verdict": self.triage_verdict,
            "triage_score": self.triage_score,
        }


class Orchestrator:
    """One funnel run. ``run`` returns the exit code of the orchestrator."""

    def __init__(
        self,
        *,
        spec: RunSpec,
        setup: Setup,
        record: dict[str, Any],
        client: ModelClient | None = None,
    ) -> None:
        self.spec = spec
        self.setup = setup
        self.parameters: Parameters = setup.parameters
        self.record = record
        self.repository = spec.repository
        self.work = spec.work_dir
        self.models = dict(spec.models)
        self.plain = PlainCommand(spec.agent_command)
        self.tasks = TaskSessions(self.plain, list(spec.agent_env), cwd=self.repository, base_env=dict(os.environ))
        self.clock = Clock(spec.wall_clock_seconds, self.parameters)
        self.budget = Budget(spec.token_ceiling, self.parameters)
        self.ledger = Ledger(self.work / LEDGER_FILE, started=self.clock.started)
        self.files = SourceFiles(self.repository)
        # A cited path that starts with the repository folder of the run is a repository path.
        configure_root(str(self.repository))
        # The path classes of the inventory: no hit, lead or deep-check output in tests, docs and non-code files.
        self.paths = PathClasses(self.repository)
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.client = client or ModelClient(
            spec.model_base_url,
            spec.default_model,
            temperature=self.parameters.call_temperature,
            timeout_seconds=self.parameters.call_timeout_seconds,
            max_attempts=self.parameters.call_attempts,
            stop_event=self.stop_event,
            max_completion_tokens=spec.completion_ceilings.get(spec.default_model, 0),
            models={role: spec.models[role] for role in CALL_ROLES.values()},
            completion_ceilings=spec.completion_ceilings,
        )
        self.executor = ThreadPoolExecutor(max_workers=self.parameters.max_concurrency, thread_name_prefix="call")
        self.calls: dict[Future[CallResult], CallTask] = {}
        self.free: PiSession | None = None
        self.free_name = FREE_SESSION
        self.sessions: dict[str, PiSession] = {}
        self.ended_sessions: set[str] = set()
        self.units: list[dict[str, Any]] = []
        self.unit_index: dict[str, dict[str, Any]] = {}
        self.units_by_path: dict[str, list[dict[str, Any]]] = {}
        self.position: dict[str, int] = {}
        # Search hits: the bonus of each unit, the hits that wait for the
        # queue, and the window units that hits added.
        self.hit_bonus: dict[str, float] = {}
        self.pending_hits: list[tuple[str, SearchHit]] = []
        self.hit_windows: dict[str, list[str]] = {}
        self.hit_rows = 0
        self.queue_ready = False
        self.det_score: dict[str, float] = {}
        self.unit_score: dict[str, float] = {}
        self.ratings: dict[str, tuple[int, str | None]] = {}
        self.routes_by_path: dict[str, list[dict[str, Any]]] = {}
        self.signals_by_path: dict[str, list[dict[str, Any]]] = {}
        self.known_paths: list[str] = []
        self.queue: list[str] = []
        # The units with a unit check that gave an answer, and the units that could not be checked: a
        # file that cannot be read, or a unit check that failed again after its one requeue.
        self.checked: set[str] = set()
        self.unit_failed: set[str] = set()
        self.requeued: set[str] = set()
        self.leads: dict[str, Lead] = {}
        # One deep check for each unit: the queue of the units with leads,
        # the leads of each unit, and the deep check of each unit that had one.
        self.task_queue: list[str] = []
        self.unit_leads: dict[str, list[str]] = {}
        self.unit_workers: dict[str, str] = {}
        # The leads that wait for their triage call, best confidence first.
        self.triage_queue: list[str] = []
        self.findings: dict[str, Finding] = {}
        self.order = 0
        self.verify_running: set[str] = set()
        self.verify_failed: set[str] = set()
        # The verdicts of each finding when a finding gets more than one verification (verify_votes).
        self.votes: dict[str, list[dict[str, Any]]] = {}
        # The passes after the queues (depth_passes): the focus lenses that wait, and the sweep queue.
        self.focus_waiting: list[tuple[str, str]] | None = None
        self.lens_texts: dict[str, str] = {}
        self.sweep_queue: list[str] | None = None
        self.checked_order: list[str] = []
        self.counts: Counter[str] = Counter()
        self.phase_times: dict[str, list[float]] = {}
        self.stop_new_work: str | None = None
        self.stop_reason: str | None = None
        self.terminated = False
        self.budget_refused = False
        self.refusal_counts: dict[str, int] = {}
        self.dirty = False
        self.leads_dirty = False
        self.window = {"checks": 0, "leads": 0}
        self.rolled: set[str] = set()
        # The unit checks started (each unit once), the large-queue decision
        # and the end of the deep-check pace.
        self.unit_checks_started = 0
        # A large repository (more files than large_repo_files, or a queue that does not fit).
        self.large_repo = False
        self.large_queue = False
        self.planned_checks = 0
        self.pace_open = False
        self.last_status = 0.0
        self.rating_ran = False
        self.task_number = 0
        # The money of the run (GET /budget of the gateway), when the run has a cost cap.
        self.money_state: dict[str, Any] | None = None
        self.money_read_at = float("-inf")

    def elapsed(self) -> float:
        return round(self.clock.elapsed(), 1)

    def mark(self, phase: str, *, end: bool = False) -> None:
        moment = self.clock.elapsed()
        times = self.phase_times.setdefault(phase, [moment, moment])
        if end:
            times[1] = max(times[1], moment)

    def next_id(self, prefix: str) -> str:
        self.task_number += 1
        return f"{prefix}{self.task_number:05d}"

    def running_workers(self) -> int:
        return sum(1 for name, session in self.sessions.items() if name not in self.ended_sessions)

    def free_running(self) -> bool:
        return self.free is not None and self.free_name not in self.ended_sessions

    def free_slots(self) -> int:
        return self.parameters.max_concurrency - int(self.free_running()) - self.running_workers() - len(self.calls)

    def anything_running(self) -> bool:
        return bool(self.calls) or self.running_workers() > 0 or self.free_running()

    def calls_of(self, kinds: tuple[str, ...]) -> int:
        return sum(1 for task in self.calls.values() if task.kind in kinds)

    def run(self) -> int:
        self.prepare()
        self.classify_repository()
        self.start_free_session()
        self.phase0()
        self.load_queue()
        if not self.terminated:
            self.phase1()
        self.order_queue()
        self.roll("rating-end", "rating", "unit_check")
        # A large queue: phase 2 cannot check each unit, so the deep checks follow its progress.
        self.large_queue = bool(self.queue) and not self.queue_fits()
        if self.large_queue and not self.large_repo:
            # A budget-bound run: the triage rules of a large repository from here on (the
            # free-roaming session keeps the cap it started with).
            self.large_repo = True
            self.record["repository"].update(large=True, reason="queue")
            self.size_triage_for_large_repository()
        self.planned_checks = min(self.parameters.max_unit_checks, len(self.queue))
        self.record["pacing"] = {"large_queue": self.large_queue, "planned_checks": self.planned_checks}
        self.main_loop()
        return self.finish()

    def prepare(self) -> None:
        (self.work / TASKS).mkdir(parents=True, exist_ok=True)
        # A valid findings file from the start: a stop at any time leaves one.
        self.write_findings(final=False)
        if self.tasks.agent_from and Path(self.tasks.agent_from).is_dir():
            # A clean copy before any session starts: each deep check copies it.
            self.tasks.use_template(self.work / TEMPLATE_AGENT)
        self.record.update(
            limits={
                "token_ceiling": self.budget.ceiling,
                "stop_level_tokens": self.budget.stop_level,
                "max_completion_tokens": self.client.max_completion_tokens,
                **self.clock.record(),
            },
            parameters=self.parameters.record(),
            setup=self.setup.record(),
            models=dict(self.models),
        )
        self.write_record()

    def classify_repository(self) -> None:
        """A repository with more than large_repo_files files is large: its free-roaming session gets
        free_token_fraction_large of the ceiling, and its triage pool share_triage_large of S."""
        limit = self.parameters.large_repo_files
        files = repository_files(self.repository, limit + 1)
        self.large_repo = files > limit
        self.record["repository"] = {"files_counted": files, "large": self.large_repo, "reason": "files" if self.large_repo else None}
        if self.large_repo:
            self.budget.set_free_limit(int(self.budget.ceiling * self.parameters.free_token_fraction_large))
            self.size_triage_for_large_repository()

    def size_triage_for_large_repository(self) -> None:
        """The triage pool of a large repository: share_triage_large of S, the difference from the reserve."""
        target = int(self.budget.stop_level * self.parameters.share_triage_large)
        extra = target - self.budget.allowance["triage"]
        if extra > 0:
            self.roll("large-triage", "reserve", "triage", extra)

    def start_free_session(self) -> None:
        tokens = self.budget.free_limit
        seconds = self.clock.free_seconds
        entry: dict[str, Any] = {"token_budget": tokens, "wall_clock_seconds": seconds, "started": False}
        self.record["free_session"] = entry
        if tokens < 1 or seconds < 1:
            entry["skipped"] = "no-budget"
            return
        argv = self.plain.with_inputs(token_budget=tokens, seconds=seconds, model=self.models["free_roaming"])
        environment = self.tasks.environment()
        try:
            self.free = PiSession(
                FREE_SESSION, argv, environment, self.repository, Path(self.plain.session_dir), self.work / "free"
            ).start()
        except OSError as error:
            entry["error"] = f"start: {type(error).__name__}"
            return
        # Its own pool: its use does not come out of the deep checks.
        self.free.extra.update(pool=FREE_POOL, cap=tokens, charged=0, model=self.models["free_roaming"])
        self.budget.start(self.free_name, FREE_POOL, self.budget.free_pending(0), in_pool=False, reserve=self.session_reserve(self.free))
        entry.update(started=True, started_at=now_text(), started_seconds=self.elapsed())
        self.mark("free_session")

    def phase0(self) -> None:
        self.mark("inventory")
        record: dict[str, Any] = {"status": "failed", "source": "inventory"}
        started = time.monotonic()
        inventory, problem = self.run_inventory()
        if problem:
            record["error"] = problem
        if isinstance(inventory, dict):
            record.update(
                status="partial" if inventory.get("partial") else "complete",
                version=inventory.get("version"),
                elapsed_seconds=inventory.get("elapsed_seconds"),
                stats=inventory.get("stats") if isinstance(inventory.get("stats"), dict) else None,
            )
            self.inventory_units(inventory)
            capped, cap = cap_inventory(inventory, self.parameters.inventory_limit_bytes)
            record["inventory_cap"] = cap
            atomic_write_json(self.work / INVENTORY_FILE, capped)
            (self.work / INVENTORY_FULL).unlink(missing_ok=True)
        record.update(
            seconds=round(time.monotonic() - started, 1),
            path_classes=self.paths.available,
            units=len(self.units),
            files=len(self.known_paths),
            routes=sum(len(items) for items in self.routes_by_path.values()),
        )
        self.record["phase0"] = record
        self.counts["units"] = len(self.units)
        self.ledger.append({"phase": "inventory", "task": "phase0", "status": record["status"], "seconds": record["seconds"]})
        self.mark("inventory", end=True)
        self.write_record()

    def run_inventory(self) -> tuple[dict[str, Any] | None, str | None]:
        """Phase 0 in its own process group, with the deadline of the parameters and a grace."""
        output = self.work / INVENTORY_FULL
        deadline = self.clock.phase0_deadline
        # -P: the working folder is the audited repository; Python must not import a module from it.
        argv = [sys.executable, "-P", "-m", "sentrytower.funnel", "--phase0", "--repository", str(self.repository), "--output", str(output)]
        argv += ["--deadline-seconds", str(deadline), "--max-units", str(self.parameters.max_units)]
        with (self.work / PHASE0_LOG).open("ab") as log:
            try:
                process = subprocess.Popen(
                    argv, cwd=self.repository, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True
                )
            except OSError as error:
                return None, f"start: {type(error).__name__}"
        hard = deadline + self.parameters.phase0_grace_seconds
        problem = None
        while process.poll() is None:
            self.tick()
            if self.terminated or self.clock.past(hard):
                problem = "terminated" if self.terminated else "deadline"
                for number in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(process.pid, number)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        process.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                break
            time.sleep(POLL_SECONDS)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if problem is None and process.returncode != 0:
            problem = f"exit {process.returncode}"
        if problem is not None or not output.is_file():
            return None, problem or "no output"
        try:
            value = read_json(output)
        except (OSError, ValueError) as error:
            return None, f"output: {type(error).__name__}"
        return (value, None) if isinstance(value, dict) else (None, "output: not an object")

    def inventory_units(self, inventory: dict[str, Any]) -> None:
        seen: set[str] = set()
        for unit in inventory.get("units") or []:
            if not isinstance(unit, dict):
                continue
            identifier, path = unit.get("id"), unit.get("path")
            if not isinstance(identifier, str) or not isinstance(path, str) or identifier in seen:
                continue
            if not isinstance(unit.get("start_line"), int) or isinstance(unit.get("start_line"), bool):
                continue
            seen.add(identifier)
            self.add_unit(unit)
            for signal_entry in unit.get("signals") or []:
                if isinstance(signal_entry, dict) and isinstance(signal_entry.get("line"), int):
                    self.signals_by_path.setdefault(path, []).append(signal_entry)
        for route in inventory.get("routes") or []:
            if isinstance(route, dict) and isinstance(route.get("path"), str):
                self.routes_by_path.setdefault(route["path"], []).append(route)
        self.paths = PathClasses(self.repository, inventory.get("files") or [])
        paths = [item.get("path") for item in inventory.get("files") or [] if isinstance(item, dict)]
        self.known_paths = list(dict.fromkeys(path for path in [*paths, *(unit["path"] for unit in self.units)] if isinstance(path, str)))

    def add_unit(self, unit: dict[str, Any]) -> None:
        self.position[unit["id"]] = len(self.units)
        self.units.append(unit)
        self.unit_index[unit["id"]] = unit
        self.units_by_path.setdefault(unit["path"], []).append(unit)

    def load_queue(self) -> None:
        count = len(self.units)
        for rank, unit in enumerate(self.units):
            self.det_score[unit["id"]] = 1.0 - rank / max(1, count)
        # A unit of a test, docs, example, fixture, generated or non-code file gives no lead: no check.
        self.queue = []
        for unit in self.units:
            if self.paths.excluded(unit["path"]):
                self.counts["units_excluded"] += 1
            else:
                self.queue.append(unit["id"])
        self.unit_score = {identifier: score + self.hit_bonus.get(identifier, 0.0) for identifier, score in self.det_score.items()}

    def unit_check_prompt_chars(self) -> int:
        protocol = self.setup.protocol("unit_check")
        return sum(len(self.setup.prompts[name]) for name in protocol.prompts)

    def check_estimate(self, unit: dict[str, Any]) -> int:
        start, end = unit_range(unit)
        chars = min(self.parameters.slice_max_chars, (end - start + 1 + self.parameters.header_lines) * 48)
        return (chars + self.unit_check_prompt_chars() + 600) // 3 + self.parameters.estimate_answer_tokens

    def queue_fits(self) -> bool:
        """Phase 2 can check each unit of the queue: at most max_unit_checks units, within the
        unit-check pool and the rating pool."""
        if len(self.queue) > self.parameters.max_unit_checks:
            return False
        total = sum(self.check_estimate(self.unit_index[identifier]) for identifier in self.queue)
        return total <= self.budget.allowance["unit_check"] + self.budget.allowance["rating"]

    def rating_needed(self) -> bool:
        """False when phase 2 can check each unit (``queue_fits``)."""
        return bool(self.queue) and not self.queue_fits()

    def phase1(self) -> None:
        record: dict[str, Any] = {"ran": False}
        self.record["rating"] = record
        if not self.parameters.use_rating:
            record["skipped"] = "off"
            return
        if not self.rating_needed():
            record["skipped"] = "phase 2 can check each unit"
            return
        self.rating_ran = True
        record["ran"] = True
        self.mark("rating")
        size = self.parameters.rating_batch
        batches = [self.units[index : index + size] for index in range(0, len(self.units), size)]
        system = self.setup.prompt("rating")
        sent = 0
        while not self.terminated:
            self.tick()
            if self.stop_new_work:
                break
            blocked = False
            while sent < len(batches) and self.free_slots() > 0:
                batch = batches[sent]
                cards = [unit_card(unit, unit_routes(unit, self.routes_by_path.get(unit["path"], []))) for unit in batch]
                user = "Cards:\n\n" + "\n\n".join(cards) + "\n"
                messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
                admitted = self.admit_call("rating", messages, role="rating")
                if admitted is None:
                    blocked = True
                    break
                self.submit(
                    "rating",
                    "rating",
                    admitted,
                    messages,
                    unit_ids=[unit["id"] for unit in batch],
                    deadline=self.clock.work_end,
                )
                sent += 1
            # The phase ends when each batch was sent, or when the next batch
            # does not fit in the pool and no rating call runs.
            if self.calls_of(("rating",)) == 0 and (sent >= len(batches) or blocked):
                break
            self.wait()
        record.update(batches=len(batches), sent=sent, rated=len(self.ratings))
        self.mark("rating", end=True)

    def order_queue(self) -> None:
        weight = self.parameters.rating_weight if self.rating_ran else 0.0
        unrated = (self.parameters.rating_unrated_score - 1) / 4
        for unit in self.units:
            identifier = unit["id"]
            rating = self.ratings.get(identifier)
            norm = (rating[0] - 1) / 4 if rating is not None else unrated
            base = weight * norm + (1 - weight) * self.det_score[identifier]
            self.unit_score[identifier] = round(base + self.hit_bonus.get(identifier, 0.0), 6)
        self.sort_queue()
        self.queue_ready = True
        pending, self.pending_hits = self.pending_hits, []
        for source, hit in pending:
            self.absorb_hit(source, hit)
        if pending:
            self.sort_queue()

    def sort_queue(self) -> None:
        self.queue = sorted(
            (identifier for identifier in dict.fromkeys(self.queue) if not self.taken(identifier)),
            key=lambda identifier: (-self.unit_score[identifier], self.position[identifier]),
        )

    def taken(self, identifier: str) -> bool:
        """The unit left the queue for good: it was checked, or it could not be checked."""
        return identifier in self.checked or identifier in self.unit_failed

    def absorb_searches(self, source: str, searches: list[tuple[str, Any, str]]) -> None:
        """Turn the grep and find outputs of a session into queue scores."""
        if not searches:
            return
        changed = False
        for tool, arguments, text in searches:
            self.counts["searches"] += 1
            hits = search_hits(
                tool,
                arguments,
                text,
                root=str(self.repository),
                is_file=self.files.is_file,
                limit=self.parameters.hit_rank_limit,
            )
            for hit in hits:
                self.counts["search_hits"] += 1
                if not self.queue_ready:
                    if len(self.pending_hits) < PENDING_HITS_LIMIT:
                        self.pending_hits.append((source, hit))
                    continue
                changed = self.absorb_hit(source, hit) or changed
        if changed:
            self.sort_queue()

    def absorb_hit(self, source: str, hit: SearchHit) -> bool:
        """Add the bonus of one hit to the unit around it; return True when the queue changed."""
        parameters = self.parameters
        if self.paths.excluded(hit.path):
            self.counts["search_hits_excluded"] += 1
            return False
        units = self.units_by_path.get(hit.path, [])
        unit: dict[str, Any] | None
        if hit.line is None:
            open_units = [item for item in units if not self.taken(item["id"])]
            unit = max(open_units, key=lambda item: self.unit_score.get(item["id"], 0.0), default=None)
            bonus = parameters.hit_bonus_find
        else:
            unit = containing_unit(units, hit.path, hit.line)  # type: ignore[assignment]
            if unit is None:
                unit = self.hit_window(hit)
            bonus = parameters.hit_bonus_top if hit.rank <= parameters.hit_top_rank else parameters.hit_bonus
        if unit is None:
            self.counts["search_hits_unplaced"] += 1
            return False
        identifier = unit["id"]
        before = self.hit_bonus.get(identifier, 0.0)
        after = min(parameters.hit_bonus_cap, before + bonus)
        if after <= before:
            return False
        self.hit_bonus[identifier] = after
        self.unit_score[identifier] = round(self.unit_score.get(identifier, 0.0) + after - before, 6)
        if before == 0.0:
            self.counts["hit_units"] += 1
        if self.hit_rows < HIT_ROWS_LIMIT:
            self.hit_rows += 1
            row = {
                "t": self.elapsed(),
                "session": source,
                "tool": hit.tool,
                "path": hit.path,
                "line": hit.line,
                "rank": hit.rank,
                "unit_id": identifier,
                "bonus": round(after - before, 3),
                "checked": identifier in self.checked,
            }
            append_jsonl(self.work / HITS_FILE, row)
        return not self.taken(identifier)

    def hit_window(self, hit: SearchHit) -> dict[str, Any] | None:
        """The window unit of a grep match that no unit holds: an earlier window of the file, or a new one."""
        assert hit.line is not None
        if self.paths.vendor(hit.path):
            # A vendor file: the bonus of a hit, never a window.
            self.counts["search_hits_vendor_no_window"] += 1
            return None
        for identifier in self.hit_windows.get(hit.path, []):
            start, end = unit_range(self.unit_index[identifier])
            if start <= hit.line <= end:
                return self.unit_index[identifier]
        if sum(len(items) for items in self.hit_windows.values()) >= self.parameters.hit_max_windows:
            return None
        lines = self.files.lines(hit.path)
        if not lines or hit.line > len(lines):
            return None
        radius = self.parameters.hit_window_lines
        identifier = f"H{sum(len(items) for items in self.hit_windows.values()) + 1:05d}"
        unit = {
            "id": identifier,
            "path": hit.path,
            "start_line": max(1, hit.line - radius),
            "end_line": min(len(lines), hit.line + radius),
            "symbol": None,
            "language": None,
            "kind": "window",
            "signals": [{"kind": "search-hit", "class": "search-hit", "cwe": None, "line": hit.line, "rule": hit.tool, "text": ""}],
            "tags": ["search-hit"],
            "score": 0.0,
            "features": {},
        }
        self.add_unit(unit)
        self.hit_windows.setdefault(hit.path, []).append(identifier)
        self.det_score[identifier] = 0.0
        self.unit_score[identifier] = self.parameters.hit_window_base
        self.queue.append(identifier)
        self.counts["hit_windows"] += 1
        self.counts["units"] = len(self.units)
        return unit

    def main_loop(self) -> None:
        self.mark("unit_check")
        while True:
            self.tick()
            if self.terminated:
                self.stop_reason = STOP_TERMINATED
                return
            # The stop level of the wall clock.
            if self.clock.past(self.clock.end):
                self.stop_reason = self.stop_new_work or STOP_END
                return
            started = self.schedule()
            if started == 0 and not self.anything_running() and self.stop_new_work is None and self.paced_only():
                # Only the pace holds the deep checks back, and no other work runs: it ends.
                self.pace_open = True
                self.record.setdefault("pacing", {})["opened_seconds"] = self.elapsed()
                continue
            if started == 0 and not self.anything_running() and self.stop_new_work is None and self.waiting_for_tokens():
                # Work waits for tokens: when dollars end the run, the money may still buy them.
                grown = self.extend_by_money()
                if grown == MONEY_GREW:
                    continue
                if grown == MONEY_SPENT:
                    self.stop_new_work = self.stop_reason = self.money_stop_reason()
                    self.record["stop_new_work"] = {"reason": self.stop_reason, "seconds": self.elapsed()}
                    return
            if started == 0 and not self.anything_running():
                if self.stop_new_work is not None:
                    self.stop_reason = self.stop_new_work
                elif self.queue and not self.unit_checks_capped():
                    self.stop_reason = STOP_BLOCKED
                elif self.task_queue:
                    # Leads wait: no deep check fits before the work cut-off, or no pool holds one.
                    self.stop_reason = STOP_TIME if self.workers_out_of_time() else STOP_BLOCKED
                elif self.queue:
                    self.stop_reason = STOP_CAP
                else:
                    self.stop_reason = STOP_QUEUE
                return
            self.wait()

    def wait(self) -> None:
        self.wake.wait(POLL_SECONDS)
        self.wake.clear()

    def waiting_for_tokens(self) -> bool:
        """Work waits that only tokens hold back: units of the queue below the unit-check cap, leads, triage, or passes
        while a deep check still fits in the time."""
        if (self.queue and not self.unit_checks_capped()) or self.triage_queue:
            return True
        if self.workers_out_of_time():
            return False
        passes = self.parameters.depth_passes and not self.task_queue and self.next_pass() is not None
        return bool(self.task_queue) or passes

    def tick(self) -> None:
        self.harvest_calls()
        self.poll_sessions()
        self.check_stop()
        self.roll_forward()
        if self.dirty:
            self.write_findings(final=False)
            self.dirty = False
        if self.leads_dirty:
            self.write_leads()
        if time.monotonic() - self.last_status >= STATUS_SECONDS:
            self.last_status = time.monotonic()
            self.write_summary()
            self.write_record()

    def check_stop(self) -> None:
        if self.stop_new_work is not None:
            return
        if self.terminated:
            self.stop_new_work = STOP_TERMINATED
        elif self.budget_refused:
            self.stop_new_work = STOP_REFUSED
        elif self.money_stopped():
            self.stop_new_work = STOP_MONEY
        elif self.budget.at_stop():
            grown = self.extend_by_money()
            if grown != MONEY_GREW:
                # Dollars end the run: the money left buys no more work; else the token ceiling ends it.
                self.stop_new_work = self.money_stop_reason() if grown == MONEY_SPENT else STOP_TOKENS
        elif self.clock.past(self.clock.work_end):
            self.stop_new_work = STOP_TIME
        if self.stop_new_work is not None:
            self.record["stop_new_work"] = {"reason": self.stop_new_work, "seconds": self.elapsed()}

    def read_money(self, *, force: bool = False) -> dict[str, Any] | None:
        """The money of the run from the gateway (read at most every MONEY_POLL_SECONDS), or None without a cap."""
        if self.spec.money is None:
            return None
        now = time.monotonic()
        if force or now - self.money_read_at >= MONEY_POLL_SECONDS:
            self.money_read_at = now
            state = read_budget(self.spec.model_base_url, self.client.credential)
            if state is not None:
                self.money_state = state
        return self.money_state

    def money_stopped(self) -> bool:
        """85% of the cost cap is spent (or the provider refused the run): no new work starts."""
        state = self.read_money()
        return bool(state and state.get("stop"))

    def money_stop_reason(self) -> str:
        """The stop when the money ends the run: 85% of the cap is spent, or the money left buys too little."""
        return STOP_MONEY if self.money_stopped() else STOP_MONEY_LEFT

    def extend_by_money(self) -> str | None:
        """Dollars end the run: grow the token plan to what the money left before the soft stop buys.

        Returns ``MONEY_GREW``; ``MONEY_SPENT`` when the money left buys too
        little (the money ends the run); None when dollars do not end this
        run (no cap, a standard run, a token ceiling) or the money cannot be
        read. The price of a token is the observed one (the spent money for
        the committed tokens of the gateway), else the estimate of the spec.
        """
        money = self.spec.money
        if not money or not money.get("extend"):
            return None
        state = self.read_money(force=True)
        if not state or state.get("soft_stop_usd") is None:
            return None
        if state.get("stop"):
            return MONEY_SPENT
        spent, tokens = float(state.get("spent_usd") or 0.0), int(state.get("tokens") or 0)
        estimate = float(money.get("price_per_million") or 0.0) / 1_000_000
        price = spent / tokens if spent > 0 and tokens > 0 else estimate
        if price <= 0:
            return None
        affordable = (float(state["soft_stop_usd"]) - spent) / price
        grow = int(affordable - (self.budget.stop_level - self.budget.committed()))
        limit = money.get("token_limit")
        if isinstance(limit, int):
            grow = min(grow, int(limit * self.parameters.stop_fraction) - self.budget.stop_level)
        if grow < max(1, int(self.budget.initial_stop_level * MONEY_GROW_MIN_FRACTION)):
            return MONEY_SPENT
        self.budget.grow(grow, "money-left")
        self.counts["money_extensions"] += 1
        self.record["money"] = {
            "extensions": self.counts["money_extensions"],
            "stop_level_tokens": self.budget.stop_level,
            "spent_usd": round(spent, 6),
            "price_per_million": round(price * 1_000_000, 6),
        }
        return MONEY_GREW

    def roll(self, name: str, source: str, target: str, amount: int | None = None) -> None:
        moved = self.budget.move(source, target, self.budget.pool_remaining(source) if amount is None else amount, name)
        if moved:
            self.counts[f"roll_{name}"] += 1

    def unit_checks_running(self) -> int:
        return self.calls_of(("unit-check",))

    def roll_forward(self) -> None:
        """The roll-forward rules of the pools."""
        if not self.units and not self.leads:
            return
        parameters = self.parameters
        # Few leads: the unit checks get half of the deep-check tokens that
        # the queued and running leads do not need.
        if self.window["checks"] >= parameters.low_rate_window:
            rate = self.window["leads"] / self.window["checks"]
            # Not while triaged leads wait for a deep check, and not after the cap of phase 2.
            if rate < parameters.low_lead_rate and self.next_unit() is None and not self.unit_checks_capped():
                need = (len(self.task_queue) + self.running_workers() + 2) * parameters.worker_tokens
                spare = self.budget.pool_remaining("deep_check") - need
                if spare > 0:
                    self.roll("low-lead-rate", "deep_check", "unit_check", spare // 2)
            self.window = {"checks": 0, "leads": 0}
        queue_done = (not self.queue or self.unit_checks_capped()) and self.unit_checks_running() == 0
        if queue_done and "unit-queue-done" not in self.rolled:
            self.rolled.add("unit-queue-done")
            self.roll("unit-queue-done", "unit_check", "deep_check")
        triage_idle = not self.triage_queue and self.calls_of(("triage",)) == 0
        if queue_done and triage_idle and "triage-done" not in self.rolled:
            # Phase 2 ended and each lead has its triage: the rest of the triage pool goes to the deep checks.
            self.rolled.add("triage-done")
            self.roll("triage-done", "triage", "deep_check")
        deep_idle = not self.task_queue and self.running_workers() == 0 and triage_idle
        if queue_done and deep_idle:
            self.roll("deep-idle", "deep_check", "reserve")
        if self.queue and not self.unit_checks_capped() and deep_idle and self.unit_checks_running() == 0:
            # Phase 2 stalls for lack of tokens while no lead waits.
            unit = self.unit_index[self.queue[0]]
            estimate = self.check_estimate(unit)
            if not self.budget.admits("unit_check", estimate):
                self.roll("phase2-continues", "deep_check", "unit_check")
                need = parameters.verify_max_findings * self.verify_estimate()
                spare = self.budget.pool_remaining("verify") - need
                if spare > 0 and not self.budget.admits("unit_check", estimate):
                    self.roll("verify-spare", "verify", "unit_check", spare)
        if self.task_queue and self.running_workers() == 0 and self.worker_pool() is None:
            # Leads wait and no pool holds a deep check: the verify pool keeps
            # the tokens of verify_max_findings verifications and gives the rest.
            need = parameters.verify_max_findings * self.verify_estimate()
            spare = self.budget.pool_remaining("verify") - need
            if spare > 0:
                self.roll("verify-spare-deep", "verify", "deep_check", spare)

    def unit_checks_capped(self) -> bool:
        """Phase 2 started max_unit_checks unit checks: no new unit check (the reserve included)."""
        return self.unit_checks_started >= self.parameters.max_unit_checks

    def phase2_progress(self) -> float:
        """The progress of phase 2: its checks of the planned checks, or the share of the time to the
        work cut-off, the larger; 1 when phase 2 has no more to do."""
        if not self.queue or self.unit_checks_capped() or self.planned_checks <= 0:
            return 1.0
        checks = min(1.0, self.counts["checked"] / self.planned_checks)
        return max(checks, min(1.0, self.clock.elapsed() / max(1.0, self.clock.work_end)))

    def deep_release(self) -> int | None:
        """The deep-check tokens that the pace gives now; None without a pace (the queue fits)."""
        if not self.large_queue or self.pace_open or self.parameters.deep_pace_start >= 1.0:
            return None
        start = self.parameters.deep_pace_start
        return int(self.budget.allowance["deep_check"] * min(1.0, start + (1.0 - start) * self.phase2_progress()))

    def deep_paced(self) -> bool:
        """The pace holds the next deep check of the deep-check pool back."""
        release = self.deep_release()
        if release is None:
            return False
        return self.budget.pool_committed("deep_check") + self.parameters.worker_tokens // 2 > release

    def paced_only(self) -> bool:
        """Triaged leads wait, a pool holds a deep check, and only the pace holds it back."""
        return self.next_unit() is not None and not self.workers_out_of_time() and self.worker_pool() == "deep_check" and self.deep_paced()

    def workers_out_of_time(self) -> bool:
        """A deep check starts only when its whole wall clock fits before the work cut-off."""
        return self.clock.remaining(self.clock.work_end) < self.parameters.worker_seconds

    def session_reserve(self, session: PiSession | None) -> int:
        """The reservation of the gateway for the next call of an agent session: its context
        (the tokens of its last call, 4 bytes each, / 3) and the completion ceiling of its model."""
        last = session.tokens.last_call if session is not None and session.tokens is not None else 0
        model = session.extra.get("model") if session is not None else None
        return -(-4 * last // 3) + self.client.completion_ceiling(model)

    def worker_pool(self, tokens: int | None = None) -> str | None:
        """The pool of the next deep check (or pass): deep_check, else the reserve when the queue is empty; None without tokens."""
        tokens = self.parameters.worker_tokens if tokens is None else tokens
        for candidate in ("deep_check", "reserve"):
            if candidate == "reserve" and self.queue:
                continue
            if self.budget.admits(candidate, tokens, pool_minimum=tokens // 2):
                return candidate
        return None

    def verify_estimate(self) -> int:
        return (self.parameters.slice_max_chars // 2 + len(self.setup.prompt("verify"))) // 3 + self.parameters.estimate_answer_tokens

    def schedule(self) -> int:
        """Start each task that a slot, a pool and the time allow; return the count."""
        started = 0
        slots = self.free_slots()
        if slots <= 0 or self.terminated:
            return 0
        if (
            not self.budget_refused
            and self.stop_new_work not in (STOP_MONEY, STOP_MONEY_LEFT)
            and not self.clock.past(self.clock.verify_end)
        ):
            for finding in self.verify_candidates():
                if slots <= 0:
                    break
                if not self.budget.admits("verify", self.verify_estimate()):
                    break
                if self.submit_verify(finding):
                    started += 1
                    slots -= 1
        if self.stop_new_work is not None:
            return started
        parameters = self.parameters
        # Phase 3: a deep check for the unit with the best triaged lead.
        leads_blocked = not self.task_queue
        while slots > 0 and self.task_queue and self.running_workers() < parameters.max_workers:
            unit_id = self.next_unit()
            if unit_id is None:
                # The leads wait for their triage.
                break
            if self.workers_out_of_time():
                leads_blocked = True
                break
            pool = self.worker_pool()
            if pool is None or (pool == "deep_check" and self.deep_paced()):
                leads_blocked = True
                break
            self.task_queue.remove(unit_id)
            if self.start_worker(unit_id, pool):
                started += 1
                slots -= 1
        # Triage: one blind verification call for each new lead.
        while slots > 0 and self.triage_queue:
            outcome = self.try_triage(self.triage_queue[0])
            if outcome == "blocked":
                break
            self.triage_queue.pop(0)
            if outcome == "started":
                started += 1
                slots -= 1
        # Phase 2: the next units of the queue, up to max_unit_checks.
        queue_blocked = not self.queue or self.unit_checks_capped()
        while slots > 0 and self.queue and not self.unit_checks_capped():
            outcome = self.try_unit_check(self.queue[0], "unit_check")
            if outcome == "blocked":
                queue_blocked = True
                break
            self.queue.pop(0)
            if outcome == "started":
                started += 1
                slots -= 1
        # The reserve: when phases 2 and 3 have no tokens for their next
        # task, more unit checks from the reserve pool.
        while slots > 0 and queue_blocked and leads_blocked:
            if self.queue and not self.unit_checks_capped():
                outcome = self.try_unit_check(self.queue[0], "reserve")
                if outcome == "blocked":
                    break
                self.queue.pop(0)
            else:
                break
            if outcome == "started":
                started += 1
                slots -= 1
        # The passes after the queues (depth_passes): focus sessions, then the sweep.
        if parameters.depth_passes and not self.task_queue and not self.triage_queue and (not self.queue or self.unit_checks_capped()):
            while slots > 0 and self.running_workers() < parameters.max_workers and not self.workers_out_of_time():
                upcoming = self.next_pass()
                if upcoming is None:
                    break
                kind, target = upcoming
                pool = self.worker_pool(parameters.focus_tokens if kind == "focus" else None)
                if pool is None:
                    break
                self.take_pass(kind)
                if self.start_pass(kind, target, pool):
                    started += 1
                    slots -= 1
        return started

    def admit_call(self, pool: str, messages: list[dict[str, Any]], *, role: str) -> tuple[int, int] | None:
        """The estimate and the gateway reservation of a direct call that ``pool`` admits now, else None."""
        text = "".join(str(message.get("content") or "") for message in messages)
        estimate = estimate_tokens(text) + self.parameters.estimate_answer_tokens
        reserve = self.client.reservation(messages, role=role)
        return (estimate, reserve) if self.budget.admits(pool, estimate, reserve=reserve) else None

    def submit(
        self,
        kind: str,
        pool: str,
        admitted: tuple[int, int],
        messages: list[dict[str, Any]],
        *,
        unit_ids: list[str] | None = None,
        finding_id: str | None = None,
        shown: list[tuple[int, int]] | None = None,
        deadline: float,
        lead_id: str | None = None,
    ) -> CallTask:
        estimate, reserve = admitted
        task = CallTask(
            id=self.next_id("c"),
            kind=kind,
            pool=pool,
            estimate=estimate,
            messages=messages,
            started=self.clock.elapsed(),
            unit_ids=list(unit_ids or []),
            finding_id=finding_id,
            shown=list(shown or []),
            lead_id=lead_id,
        )
        self.budget.start(task.id, pool, estimate, reserve=reserve)
        future = self.executor.submit(self.client.complete, messages, deadline=self.clock.at(deadline), role=CALL_ROLES[kind])
        self.calls[future] = task
        future.add_done_callback(lambda _future: self.wake.set())
        self.mark(pool)
        return task

    def try_unit_check(self, identifier: str, pool: str) -> str:
        """Start a unit check: "started", "skip" (the file cannot be read) or "blocked" (no tokens)."""
        unit = self.unit_index[identifier]
        values, meta = unit_code(unit, self.files, max_chars=self.parameters.slice_max_chars, header_lines=self.parameters.header_lines)
        if values is None:
            self.counts["units_unreadable"] += 1
            self.unit_failed.add(identifier)
            return "skip"
        # The template has a place for a focus sentence after the question; this release sends none.
        values["lens"] = ""
        system = self.setup.prompt("unit_check")
        message = render(self.setup.prompt("unit_check", 1), values)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": message}]
        admitted = self.admit_call(pool, messages, role="unit_check")
        if admitted is None:
            return "blocked"
        self.submit(
            "unit-check",
            pool,
            admitted,
            messages,
            unit_ids=[identifier],
            shown=list(meta["shown"]),
            deadline=self.clock.work_end,
        )
        if identifier not in self.requeued:
            self.unit_checks_started += 1
        if meta.get("cut"):
            self.counts["slices_cut"] += 1
        return "started"

    def verify_candidates(self) -> list[Finding]:
        """The deep-check findings that wait for their verification, in rank order, up to verify_max_findings in all.

        A finding of the free-roaming session always stays in the output, so it
        gets no verification (and no score that the single agent does not give).
        """
        alive = sorted(
            (item for item in self.findings.values() if item.dropped is None and item.locations and item.source != FREE_SOURCE),
            key=rank_key,
        )
        started = sum(1 for item in alive if item.verify is not None) + len(self.verify_running) + len(self.verify_failed)
        room = max(0, self.parameters.verify_max_findings - started)
        waiting = [
            item for item in alive if item.verify is None and item.id not in self.verify_running and item.id not in self.verify_failed
        ]
        if self.parameters.verify_votes == 1:
            return waiting[:room]
        # More verdicts for the findings that have fewer than verify_votes (they count once in verify_max_findings).
        more = [
            item
            for item in alive
            if item.verify is not None
            and item.id not in self.verify_running
            and item.id not in self.verify_failed
            and len(self.votes.get(item.id, ())) < self.parameters.verify_votes
        ]
        return waiting[:room] + more

    def claim_messages(
        self, role: str, path: str, line: int, end_line: int, cwe: str | None
    ) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
        """The blind verification of one place (phase 4 and the triage): the smallest unit that
        holds the line, its routes and the claim, never the reason of a unit check."""
        unit = containing_unit(self.units, path, line)
        routes = unit_routes(unit, self.routes_by_path.get(path, [])) if unit is not None else []
        message, meta = claim_message(
            path=path,
            line=line,
            end_line=end_line,
            cwe=cwe,
            files=self.files,
            unit=unit,
            routes=routes,
            max_chars=self.parameters.slice_max_chars // 2,
            header_lines=self.parameters.header_lines,
        )
        if message is None:
            return None, meta
        return [{"role": "system", "content": self.setup.prompt(role)}, {"role": "user", "content": message}], meta

    def try_triage(self, lead_id: str) -> str:
        """The triage call of a lead: "started", "skip" (no call) or "blocked" (wait for tokens)."""
        lead = self.leads[lead_id]
        if lead.unit_id in self.unit_workers:
            lead.triage_status = "not-needed"
            self.counts["triage_not_needed"] += 1
            self.leads_dirty = True
            return "skip"
        messages, meta = self.claim_messages("triage", lead.path, lead.line, lead.end_line, lead.cwe)
        if messages is None:
            self.triage_ended(lead, "failed")
            return "skip"
        admitted = self.admit_call("triage", messages, role="triage")
        estimate = estimate_tokens("".join(str(item["content"]) for item in messages)) + self.parameters.estimate_answer_tokens
        if admitted is None and self.budget.pool_remaining("triage") < estimate:
            # Each lead gets its triage call: the reserve, then the deep-check pool, give the triage
            # pool the tokens of the next waiting leads (at most 20 calls at a time).
            need = estimate * min(20, max(1, len(self.triage_queue)))
            for source in ("reserve", "deep_check"):
                short = need - self.budget.pool_remaining("triage")
                if short <= 0:
                    break
                self.roll("triage-short", source, "triage", short)
            admitted = self.admit_call("triage", messages, role="triage")
        if admitted is None:
            if self.calls_of(("triage",)) == 0 and self.budget.pool_remaining("triage") < estimate:
                # The triage pool is spent: the lead goes to the deep checks without a score.
                self.triage_ended(lead, "skipped")
                return "skip"
            return "blocked"
        self.submit(
            "triage",
            "triage",
            admitted,
            messages,
            unit_ids=[lead.unit_id],
            lead_id=lead.id,
            shown=[(1, self.parameters.header_lines), (meta["start"], meta["end"])],
            deadline=self.clock.work_end,
        )
        lead.triage_status = "running"
        self.leads_dirty = True
        return "started"

    def triage_ended(self, lead: Lead, status: str, verdict: dict[str, Any] | None = None) -> None:
        lead.triage_status = status
        if verdict is not None:
            lead.triage_verdict, lead.triage_score = verdict.get("verdict"), verdict.get("keep_score")
        self.counts[{"done": "triaged", "failed": "triage_failed", "skipped": "triage_skipped"}[status]] += 1
        if lead.triage_verdict == "safe":
            self.counts["triage_safe"] += 1
        self.leads_dirty = True
        self.sort_leads()

    def triage_done(self, task: CallTask, result: CallResult) -> None:
        """The keep score of the blind verification orders the unit of the lead for the deep checks."""
        lead = self.leads.get(task.lead_id or "")
        status = result.status
        verdict: dict[str, Any] | None = None
        if result.ok:
            try:
                verdict = self.setup.protocol("triage").parser(result.text)
            except ParseError:
                status = "parse-error"
        if lead is None:
            return
        self.triage_ended(lead, "done" if verdict is not None else "failed", verdict)
        row = {
            **result.ledger(),
            "phase": "triage",
            "task": task.id,
            "unit_id": lead.unit_id,
            "lead_id": lead.id,
            "status": status,
            "verdict": (verdict or {}).get("verdict"),
            "keep_score": (verdict or {}).get("keep_score"),
        }
        self.ledger.append(row)

    def submit_verify(self, finding: Finding) -> bool:
        first = finding.locations[0]
        messages, meta = self.claim_messages(
            "verify", first["path"], first["line_start"], first["line_end"], finding.cwe[0] if finding.cwe else None
        )
        if messages is None:
            self.verify_failed.add(finding.id)
            finding.verify_note = "the code of the finding cannot be read"
            return False
        admitted = self.admit_call("verify", messages, role="verify")
        if admitted is None:
            return False
        self.submit(
            "verify",
            "verify",
            admitted,
            messages,
            finding_id=finding.id,
            shown=[(1, self.parameters.header_lines), (meta["start"], meta["end"])],
            deadline=self.clock.verify_end,
        )
        self.verify_running.add(finding.id)
        return True

    def deep_check_prompt(self, unit: dict[str, Any], lines: str) -> str:
        """The task of a deep check of ``unit`` with its ``lines`` of interest, then the answer contract and the schema."""
        start, end = unit_range(unit)
        symbol = unit.get("symbol")
        values = {
            "path": str(unit["path"]),
            "start_line": str(start),
            "end_line": str(end),
            "symbol": f" ({symbol})" if isinstance(symbol, str) and symbol else "",
            "lines": lines,
        }
        protocol = self.setup.protocol("deep_check")
        template = self.setup.prompts[protocol.prompts[0]]
        parts = [render(template, values), *(self.setup.prompts[name] for name in protocol.prompts[1:])]
        return "\n\n".join(part.strip() for part in parts) + "\n"

    def worker_prompt(self, unit_id: str) -> str:
        """The task of the deep check of a unit: the unit and the lines of interest of all its leads."""
        unit = self.unit_index[unit_id]
        leads = sorted((self.leads[identifier] for identifier in self.unit_leads[unit_id]), key=lambda lead: lead.line)
        default = target_cwe(unit) or "any"
        lines = "\n".join(
            f"  - line {lead.line} (weakness class to check: {lead.cwe or default}), which reads: "
            f"{lead.quote or '(the line has no quoted text)'}"
            for lead in leads
        )
        return self.deep_check_prompt(unit, lines)

    def start_worker(self, unit_id: str, pool: str) -> bool:
        """Start the one deep check of a unit with all leads of the unit at this time."""
        name = self.next_id("t")
        leads = [self.leads[identifier] for identifier in self.unit_leads[unit_id]]
        self.unit_workers[unit_id] = name
        try:
            session = self.tasks.prepare(name, self.work / TASKS / name)
        except OSError as error:
            self.counts["worker_setup_errors"] += 1
            row = {"phase": "deep-check", "task": name, "unit_id": unit_id, "status": "setup-error", "leads": len(leads)}
            self.ledger.append({**row, "error": type(error).__name__})
            for lead in leads:
                lead.status = "setup-error"
            self.leads_dirty = True
            return False
        seconds = int(min(self.parameters.worker_seconds, self.clock.remaining(self.clock.work_end)))
        prompt = self.worker_prompt(unit_id)
        try:
            self.tasks.start(
                session, token_budget=self.parameters.worker_tokens, seconds=seconds, prompt=prompt, model=self.models["deep_check"]
            )
        except OSError as error:
            row = {"phase": "deep-check", "task": name, "unit_id": unit_id, "status": "start-error", "leads": len(leads)}
            self.ledger.append({**row, "error": type(error).__name__})
            for lead in leads:
                lead.status = "start-error"
            self.leads_dirty = True
            return False
        session.extra.update(
            pool=pool,
            cap=self.parameters.worker_tokens,
            charged=0,
            unit=unit_id,
            leads=[lead.id for lead in leads],
            seconds=seconds,
            model=self.models["deep_check"],
        )
        self.sessions[name] = session
        self.budget.start(name, pool, self.parameters.worker_tokens, reserve=self.session_reserve(session))
        for lead in leads:
            lead.status, lead.worker = "deep-check", name
            if lead.triage_status == "pending" and lead.id in self.triage_queue:
                self.triage_queue.remove(lead.id)
                lead.triage_status = "not-needed"
                self.counts["triage_not_needed"] += 1
        self.leads_dirty = True
        self.counts["deep_checked"] += 1
        self.mark("deep_check")
        return True

    def poll_sessions(self) -> None:
        entries = ([(self.free_name, self.free)] if self.free is not None else []) + list(self.sessions.items())
        for name, session in entries:
            if session is None or name in self.ended_sessions:
                continue
            total = session.poll_tokens()
            self.charge_session(name, session, total)
            self.absorb_searches(name, session.take_searches())
            self.session_refusals(name, session.refusals())
            if not session.running():
                self.session_ended(name, session)

    def charge_session(self, name: str, session: PiSession, total: int) -> None:
        delta = total - int(session.extra.get("charged", 0))
        if delta > 0:
            self.budget.charge(session.extra["pool"], delta)
            session.extra["charged"] = total
        reserve = self.session_reserve(session)
        if name == self.free_name:
            self.budget.update(name, self.budget.free_pending(total), reserve=reserve)
        else:
            self.budget.update(name, int(session.extra["cap"]) - total, reserve=reserve)

    def session_refusals(self, name: str, refusals: int) -> None:
        """A reply of a session that ends with the budget refusal of the gateway: no new work."""
        seen = int(self.refusal_counts.get(name, 0))
        if refusals > seen:
            self.refusal_counts[name] = refusals
            self.counts["session_refusals"] += refusals - seen
            if not self.budget_refused:
                self.budget_refused = True
                self.record["budget_refused_by"] = {"task": name, "seconds": self.elapsed()}

    def session_ended(self, name: str, session: PiSession) -> None:
        self.ended_sessions.add(name)
        outcome = session.outcome(answer_tokens=self.parameters.estimate_answer_tokens)
        # A session that ends without an answer did not do its work.
        self.counts["sessions_answered" if outcome.document is not None else "sessions_no_answer"] += 1
        # The tokens of the session hold the estimate of each call that a stop killed.
        self.counts["killed_calls"] += outcome.killed_calls
        self.counts["killed_tokens"] += outcome.killed_tokens
        self.charge_session(name, session, outcome.tokens)
        self.absorb_searches(name, session.take_searches())
        self.session_refusals(name, outcome.refusals)
        self.budget.finish(name)
        if name == self.free_name:
            self.mark("free_session", end=True)
            self.free_ended(outcome)
        elif session.extra.get("kind") in ("focus", "sweep"):
            self.mark(session.extra["kind"], end=True)
            self.pass_ended(name, session, outcome)
        else:
            self.mark(session.extra["pool"], end=True)
            self.worker_ended(name, session, outcome)

    def free_ended(self, outcome: Any) -> None:
        entry = self.record.setdefault("free_session", {})
        entry.update(outcome.record(), ended_seconds=self.elapsed())
        # The tokens that the free-roaming session did not use go to the deep checks.
        self.roll("free-done", FREE_POOL, "deep_check")
        items = (outcome.document or {}).get("findings") or []
        row = {
            "phase": "free-roaming",
            "task": self.free_name,
            "status": "answer" if outcome.document else (outcome.error or "no-answer"),
            "tokens": outcome.tokens,
            "seconds": round(outcome.seconds, 1),
            "exit": outcome.exit,
            "stopped": outcome.stopped,
            "findings": len(items),
        }
        self.ledger.append(row)
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            self.order += 1
            finding = finding_from_item(item, identifier=f"R{index + 1:03d}", source=FREE_SOURCE, order=self.order)
            self.add_finding(finding)
            self.counts["free_findings"] += 1

    def overlaps_lead(self, finding: Finding, lead: Lead) -> bool:
        radius = self.parameters.dedup_radius_lines
        return any(
            location["path"] == lead.path and max(location["line_start"], lead.line) - min(location["line_end"], lead.end_line) <= radius
            for location in finding.locations
        )

    def worker_ended(self, name: str, session: PiSession, outcome: Any) -> None:
        """The findings of a deep check join the output candidates; its leads keep a status for the record."""
        unit_id = session.extra["unit"]
        leads = [self.leads[identifier] for identifier in session.extra["leads"]]
        parsed = self.setup.protocol("deep_check").parser(outcome.document) if outcome.document else None
        on_leads: set[str] = set()
        reported = 0
        unit = self.unit_index[unit_id]
        unit_score = max((lead.queue_score for lead in leads), default=self.unit_score.get(unit_id, 0.0))
        for index, item in enumerate((parsed or {}).get("findings") or []):
            self.order += 1
            finding = finding_from_item(item, identifier=f"{name}-{index + 1}", source="nearby", order=self.order)
            finding.unit_id, finding.unit_score = unit_id, unit_score
            first_path = finding.reported[0]["path"] if finding.reported else ""
            if resolve_path(first_path, self.files, self.known_paths) == unit["path"]:
                finding.unit_range = unit_range(unit)
            self.place(finding)
            matched = [lead for lead in leads if finding.locations and self.overlaps_lead(finding, lead)]
            finding.lead_id = matched[0].id if matched else (leads[0].id if leads else None)
            if matched:
                finding.source = "deep-check"
                on_leads.update(lead.id for lead in matched)
            else:
                self.counts["nearby"] += 1
            self.add_finding(finding)
            reported += 1
        if outcome.document is None:
            status = "no-answer"
        elif on_leads:
            status = "reported"
        elif reported:
            status = "other"
        else:
            status = "nothing"
        self.counts[f"deep_{status.replace('-', '_')}"] += 1
        for lead in leads:
            # A lead of a deep check that reported on another lead of its unit: "other".
            lead.status = "reported" if lead.id in on_leads else ("other" if status == "reported" else status)
        self.leads_dirty = True
        row = {
            "phase": "deep-check",
            "task": name,
            "unit_id": unit_id,
            "lead_id": leads[0].id if leads else None,
            "leads": len(leads),
            "status": status,
            "tokens": outcome.tokens,
            "seconds": round(outcome.seconds, 1),
            "exit": outcome.exit,
            "stopped": outcome.stopped,
            "findings": reported,
            "token_budget": session.extra["cap"],
        }
        self.ledger.append(row)
        more = {"pool": session.extra["pool"], "error": outcome.error, "final_turn": outcome.final_turn}
        append_jsonl(self.work / WORKERS_FILE, {**row, **more, "wall_clock_input": session.extra.get("seconds")})

    def focus_lenses(self) -> list[tuple[str, str]]:
        """The focus lenses that wait, in order; a repository with native code starts with memory safety."""
        if self.focus_waiting is None:
            lenses = []
            for line in read_prompt(FOCUS_LENSES).splitlines():
                name, _, text = line.partition(":")
                if name.strip() and text.strip():
                    lenses.append((name.strip(), text.strip()))
            native = any(str(unit["path"]).lower().endswith(NATIVE_SUFFIXES) for unit in self.units)
            lenses.sort(key=lambda lens: 0 if native and lens[0] == "memory" else 1)
            self.focus_waiting = lenses
            self.lens_texts = dict(lenses)
        return self.focus_waiting

    def next_pass(self) -> tuple[str, str] | None:
        """The next pass: a focus session (its lens), then a deep check of the sweep (its unit); None when none is left."""
        lenses = self.focus_lenses()
        if lenses:
            return "focus", lenses[0][0]
        if self.sweep_queue is None:
            # The checked units without a lead, in the order of their checks (the order of the queue).
            self.sweep_queue = [unit for unit in dict.fromkeys(self.checked_order) if not self.unit_leads.get(unit)]
        while self.sweep_queue and self.sweep_queue[0] in self.unit_workers:
            self.sweep_queue.pop(0)
        return ("sweep", self.sweep_queue[0]) if self.sweep_queue else None

    def take_pass(self, kind: str) -> None:
        if kind == "focus" and self.focus_waiting:
            self.focus_waiting.pop(0)
        elif kind == "sweep" and self.sweep_queue:
            self.sweep_queue.pop(0)

    def focus_prompt(self, lens: str) -> str:
        """The audit prompt of the free-roaming session after a paragraph with one focus."""
        paragraph = render(read_prompt(FOCUS_PROMPT).strip(), {"focus": self.lens_texts[lens]})
        return paragraph + "\n\n" + self.plain.prompt

    def sweep_prompt(self, unit_id: str) -> str:
        """The deep-check task of a unit without a lead: the lines of its signals, else the whole unit."""
        unit = self.unit_index[unit_id]
        start, _ = unit_range(unit)
        source = self.files.lines(str(unit["path"])) or []

        def quote(line: int) -> str:
            text = source[line - 1].strip() if 1 <= line <= len(source) else ""
            return text or "(the line has no quoted text)"

        lines = [
            f"  - line {line} (weakness class to check: {cwe or label}), which reads: {quote(line)}"
            for cwe, label, line in unit_classes(unit)
            if line
        ]
        listed = "\n".join(lines) or f"  - line {start} (weakness class to check: any), which reads: {quote(start)}"
        return self.deep_check_prompt(unit, listed)

    def start_pass(self, kind: str, target: str, pool: str) -> bool:
        """Start a focus session (``target`` is its lens) or a deep check of the sweep (``target`` is its unit)."""
        name = self.next_id("f" if kind == "focus" else "s")
        unit_id = target if kind == "sweep" else None
        try:
            session = self.tasks.prepare(name, self.work / TASKS / name)
        except OSError as error:
            self.counts["worker_setup_errors"] += 1
            self.ledger.append({"phase": kind, "task": name, "unit_id": unit_id, "status": "setup-error", "error": type(error).__name__})
            return False
        if kind == "focus":
            tokens, model = self.parameters.focus_tokens, self.models["free_roaming"]
            seconds = int(self.clock.remaining(self.clock.work_end))
            prompt = self.focus_prompt(target)
        else:
            tokens, model = self.parameters.worker_tokens, self.models["deep_check"]
            seconds = int(min(self.parameters.worker_seconds, self.clock.remaining(self.clock.work_end)))
            prompt = self.sweep_prompt(target)
            self.unit_workers[target] = name
        try:
            self.tasks.start(session, token_budget=tokens, seconds=seconds, prompt=prompt, model=model)
        except OSError as error:
            self.ledger.append({"phase": kind, "task": name, "unit_id": unit_id, "status": "start-error", "error": type(error).__name__})
            return False
        session.extra.update(
            pool=pool,
            cap=tokens,
            charged=0,
            unit=unit_id,
            leads=[],
            seconds=seconds,
            model=model,
            kind=kind,
            lens=target if kind == "focus" else None,
        )
        self.sessions[name] = session
        self.budget.start(name, pool, tokens, reserve=self.session_reserve(session))
        self.counts[f"{kind}_started"] += 1
        self.mark(kind)
        return True

    def pass_ended(self, name: str, session: PiSession, outcome: Any) -> None:
        """The findings of a focus session or of a deep check of the sweep join the output candidates."""
        kind = session.extra["kind"]
        unit_id = session.extra.get("unit")
        unit = self.unit_index.get(unit_id) if unit_id else None
        parsed = self.setup.protocol("deep_check").parser(outcome.document) if outcome.document else None
        reported = 0
        for index, item in enumerate((parsed or {}).get("findings") or []):
            self.order += 1
            finding = finding_from_item(
                item, identifier=f"{name}-{index + 1}", source=FOCUS_SOURCE if kind == "focus" else SWEEP_SOURCE, order=self.order
            )
            if unit is not None and unit_id is not None:
                finding.unit_id, finding.unit_score = unit_id, self.unit_score.get(unit_id, 0.0)
                first_path = finding.reported[0]["path"] if finding.reported else ""
                if resolve_path(first_path, self.files, self.known_paths) == unit["path"]:
                    finding.unit_range = unit_range(unit)
            self.place(finding)
            self.add_finding(finding)
            reported += 1
        status = "no-answer" if outcome.document is None else ("reported" if reported else "nothing")
        self.counts[f"{kind}_{status.replace('-', '_')}"] += 1
        self.counts[f"{kind}_findings"] += reported
        row = {
            "phase": kind,
            "task": name,
            "unit_id": unit_id,
            "status": status,
            "tokens": outcome.tokens,
            "seconds": round(outcome.seconds, 1),
            "exit": outcome.exit,
            "stopped": outcome.stopped,
            "findings": reported,
            "token_budget": session.extra["cap"],
        }
        self.ledger.append(row)
        more = {"pool": session.extra["pool"], "lens": session.extra.get("lens"), "error": outcome.error}
        append_jsonl(self.work / WORKERS_FILE, {**row, **more, "final_turn": outcome.final_turn})

    def harvest_calls(self) -> None:
        for future in [item for item in self.calls if item.done()]:
            task = self.calls.pop(future)
            try:
                result = future.result()
            except Exception as error:  # noqa: BLE001 - a call error is a result of the call
                result = CallResult(status="error", error=type(error).__name__)
            self.budget.finish(task.id, result.total_tokens)
            self.mark(task.pool, end=True)
            if result.status == BUDGET_REFUSED:
                self.budget_refused = True
            try:
                if task.kind == "rating":
                    self.rating_done(task, result)
                elif task.kind == "unit-check":
                    self.unit_check_done(task, result)
                elif task.kind == "verify":
                    self.verify_done(task, result)
                elif task.kind == "triage":
                    self.triage_done(task, result)
            except Exception as error:  # noqa: BLE001 - one bad answer must not stop the run
                self.counts["processing_errors"] += 1
                if task.finding_id is not None:
                    # The finding is not verified again.
                    self.verify_running.discard(task.finding_id)
                    self.verify_failed.add(task.finding_id)
                    if task.finding_id in self.findings and self.findings[task.finding_id].verify is None:
                        self.findings[task.finding_id].verify_note = "the answer of the verification cannot be read"
                if task.lead_id in self.leads and not self.leads[task.lead_id].triaged:
                    self.triage_ended(self.leads[task.lead_id], "failed")
                self.ledger.append({"phase": task.kind, "task": task.id, "status": "processing-error", "error": type(error).__name__})

    def rating_done(self, task: CallTask, result: CallResult) -> None:
        ratings: dict[str, tuple[int, str | None]] = {}
        status = result.status
        if result.ok:
            try:
                ratings = self.setup.protocol("rating").parser(result.text, task.unit_ids)
            except ParseError:
                status = "parse-error"
        self.ratings.update(ratings)
        self.counts["rated"] = len(self.ratings)
        self.counts["rating_calls"] += 1
        self.ledger.append({**result.ledger(), "phase": "rating", "task": task.id, "status": status, "rated": len(ratings)})

    def unit_check_done(self, task: CallTask, result: CallResult) -> None:
        identifier = task.unit_ids[0]
        unit = self.unit_index[identifier]
        if result.status == BUDGET_REFUSED:
            # The gateway refused the call for the budget: the unit is not checked, and it waits in the queue.
            self.queue.insert(0, identifier)
            self.counts["unit_checks_refused"] += 1
            self.ledger.append({**result.ledger(), "phase": task.kind, "task": task.id, "unit_id": identifier})
            return
        if not result.ok and identifier not in self.requeued:
            # A failed call (rate limit, timeout, transport) gets one more
            # place at the head of the queue.
            self.requeued.add(identifier)
            self.queue.insert(0, identifier)
            self.counts["unit_checks_requeued"] += 1
            self.ledger.append({**result.ledger(), "phase": task.kind, "task": task.id, "unit_id": identifier})
            return
        status = result.status
        candidates: list[dict[str, Any]] = []
        if result.ok:
            try:
                candidates = self.setup.protocol("unit_check").parser(result.text)["candidates"]
            except ParseError:
                status = "parse-error"
        if status != result.status or not result.ok:
            # The call failed again, or its answer cannot be read: the unit is not checked.
            self.unit_failed.add(identifier)
            self.counts["unit_checks_failed"] += 1
            row = {**result.ledger(), "phase": task.kind, "task": task.id, "unit_id": identifier, "status": status}
            self.ledger.append({**row, "candidates": 0, "verdict": None})
            return
        self.checked.add(identifier)
        self.checked_order.append(identifier)
        made = 0
        strongest: str | None = None
        for candidate in candidates:
            lead = self.make_lead(unit, candidate, task.kind)
            if lead is not None:
                made += 1
            confidence = candidate.get("confidence") or "medium"
            if strongest is None or CONFIDENCE_RANK.get(confidence, 9) < CONFIDENCE_RANK.get(strongest, 9):
                strongest = confidence
        self.counts["checked"] += 1
        if candidates:
            self.counts["flagged_checks"] += 1
        self.window["checks"] += 1
        self.window["leads"] += made
        row = {**result.ledger(), "phase": task.kind, "task": task.id, "unit_id": identifier, "status": status}
        self.ledger.append({**row, "candidates": len(candidates), "verdict": strongest})

    def make_lead(self, unit: dict[str, Any], candidate: dict[str, Any], source: str) -> Lead | None:
        """A lead at the resolved line of a candidate; None without a line or near an earlier lead."""
        path = unit["path"]
        if self.paths.excluded(path):
            self.counts["leads_excluded"] += 1
            return None
        lines = self.files.lines(path) or []
        start, end = unit_range(unit)
        line = candidate.get("sink_line")
        quote = candidate.get("sink_quote") or ""
        if line is None and not quote:
            self.counts["candidates_without_line"] += 1
            return None
        claimed = line if line is not None and 1 <= line <= len(lines) else start
        cwe = candidate.get("cwe")
        confidence = candidate.get("confidence") or "medium"
        # The line comes from the quote of the answer, near the claimed line
        # or in the unit (phase 4 rules); the lead is not an output finding.
        probe = Finding(
            id="lead",
            source=source,
            order=0,
            title="",
            severity="medium",
            evidence="",
            exploit_conditions="",
            cwe=[cwe] if cwe else [],
            reported=[{"path": path, "line_start": claimed, "line_end": claimed}],
            quotes=[quote] if quote else [],
            unit_range=(start, end),
        )
        self.place(probe)
        if not probe.locations:
            self.counts["candidates_unplaced"] += 1
            return None
        first = probe.locations[0]
        for other in self.leads.values():
            if other.path == first["path"] and abs(other.line - first["line_start"]) <= 3:
                if CONFIDENCE_RANK.get(confidence, 9) < CONFIDENCE_RANK.get(other.confidence, 9):
                    # The counts by confidence follow the lead.
                    self.counts[f"leads_{other.confidence}"] -= 1
                    self.counts[f"leads_{confidence}"] += 1
                    other.confidence = confidence
                    self.sort_leads()
                    self.leads_dirty = True
                self.counts["leads_merged"] += 1
                return None
        lead = Lead(
            id=f"L{len(self.leads) + 1:04d}",
            unit_id=unit["id"],
            path=first["path"],
            line=first["line_start"],
            end_line=first["line_end"],
            quote=quote,
            cwe=cwe,
            confidence=confidence,
            source=source,
            queue_score=self.unit_score.get(unit["id"], 0.0),
            resolution=(probe.resolution or {}).get("method"),
        )
        self.leads[lead.id] = lead
        self.counts[f"leads_{confidence}"] += 1
        self.leads_dirty = True
        unit_id = unit["id"]
        if unit_id in self.unit_workers:
            # One deep check for each unit: the unit had its deep check, so the lead needs no triage call.
            lead.status, lead.worker = "unit-had-worker", self.unit_workers[unit_id]
            lead.triage_status = "not-needed"
            self.counts["leads_after_worker"] += 1
            self.counts["triage_not_needed"] += 1
            return lead
        self.unit_leads.setdefault(unit_id, []).append(lead.id)
        if unit_id not in self.task_queue:
            self.task_queue.append(unit_id)
        self.sort_leads()
        # The triage call of the lead: best confidence first, then the queue score.
        self.triage_queue.append(lead.id)
        self.triage_queue.sort(
            key=lambda identifier: (
                CONFIDENCE_RANK.get(self.leads[identifier].confidence, 9),
                -self.leads[identifier].queue_score,
                identifier,
            )
        )
        return lead

    def sort_leads(self) -> None:
        """The queue of the units with leads: the units with a triaged lead first, by the rank of
        their best triaged lead (``Lead.rank``); a unit whose leads wait for their triage waits."""

        def key(unit_id: str) -> tuple[int, tuple[Any, ...], str]:
            ranks = [lead.rank() for lead in (self.leads[identifier] for identifier in self.unit_leads[unit_id]) if lead.triaged]
            return (0, min(ranks), unit_id) if ranks else (1, (), unit_id)

        self.task_queue.sort(key=key)

    def next_unit(self) -> str | None:
        """The unit of the next deep check: the first unit of the queue with a triaged lead."""
        for unit_id in self.task_queue:
            if any(self.leads[identifier].triaged for identifier in self.unit_leads[unit_id]):
                return unit_id
        return None

    def verify_done(self, task: CallTask, result: CallResult) -> None:
        """The score of the blind verification ranks the finding; it drops nothing."""
        identifier = task.finding_id or ""
        self.verify_running.discard(identifier)
        finding = self.findings.get(identifier)
        status = result.status
        verdict: dict[str, Any] | None = None
        if result.ok:
            try:
                verdict = self.setup.protocol("verify").parser(result.text)
            except ParseError:
                status = "parse-error"
        if finding is None:
            return
        if verdict is None:
            self.verify_failed.add(identifier)
            if finding.verify is None:
                finding.verify_note = verify_problem(result.status, status)
                self.dirty = True
        elif self.parameters.verify_votes == 1:
            finding.verify = finding.first_verify = verdict
            self.counts["verified"] += 1
            self.dirty = True
        else:
            votes = self.votes.setdefault(identifier, [])
            votes.append(verdict)
            if len(votes) == 1:
                # The verdict of a standard run: the first vote (the tier-1 rank uses it).
                finding.first_verify = verdict
                self.counts["verified"] += 1
            self.counts["verify_votes"] += 1
            finding.verify = combine_votes(votes)
            self.dirty = True
        row = {**result.ledger(), "phase": "verify", "task": task.id, "status": status}
        self.ledger.append({**row, "verdict": (verdict or {}).get("verdict"), "keep_score": (verdict or {}).get("keep_score")})

    def note_unverified(self) -> None:
        """The reason of each finding that the run verifies and that has no verification at the end."""
        alive = [item for item in self.findings.values() if item.dropped is None and item.locations and item.source != FREE_SOURCE]
        started = sum(1 for item in alive if item.verify is not None) + len(self.verify_failed) + len(self.verify_running)
        for finding in alive:
            if finding.verify is not None or finding.verify_note is not None:
                continue
            if finding.id in self.verify_running:
                finding.verify_note = "the run stopped during its verification"
            elif self.stop_new_work in (STOP_MONEY, STOP_MONEY_LEFT):
                finding.verify_note = "no verification starts after 85% of the cost cap"
            elif self.budget_refused:
                finding.verify_note = "the budget stopped the model calls before its verification"
            elif started >= self.parameters.verify_max_findings:
                finding.verify_note = "the run reached its limit of verifications before this finding"
            else:
                finding.verify_note = "the run stopped before its verification"

    def place(self, finding: Finding) -> None:
        if finding.source in (FREE_SOURCE, FOCUS_SOURCE):
            # The output of an agent session on the whole repository: its locations stay as it reported them.
            finding.resolution = None
            finding.locations = [dict(item) for item in finding.reported]
            return
        finding.resolution = resolve_first(finding, self.files, self.known_paths, self.signals_by_path, self.parameters)
        finding.locations = final_locations(finding, finding.resolution, self.files, self.known_paths, self.parameters)
        if finding.resolution is not None:
            self.counts[f"resolved_{finding.resolution['method']}"] += 1

    def add_finding(self, finding: Finding) -> None:
        if finding.resolution is None and not finding.locations:
            self.place(finding)
        if finding.source != FREE_SOURCE and finding.locations:
            # A security fix changes production code: a deep-check finding in a
            # test, docs, example, fixture, generated or non-code file is no output.
            excluded = self.paths.excluded(finding.locations[0]["path"])
            if excluded:
                finding.dropped = f"excluded-{excluded}"
                self.counts["findings_excluded"] += 1
        self.findings[finding.id] = finding
        self.dirty = True

    def write_findings(self, *, final: bool) -> list[Finding]:
        kept, removed = select_output(self.findings.values(), self.parameters)
        items = [finding_item(finding, rank) for rank, finding in enumerate(kept, start=1)]
        document = {
            "schema": FINDINGS_SCHEMA,
            "version": FUNNEL_VERSION,
            "final": final,
            "written_at": now_text(),
            "findings": items,
            "removed": removed,
        }
        atomic_write_json(self.work / FINDINGS_FILE, document)
        self.counts["output"] = len(kept)
        return kept

    def summary(self) -> dict[str, Any]:
        reasons = Counter(item["reason"] for item in select_output(self.findings.values(), self.parameters)[1])
        flagged = {lead.unit_id for lead in self.leads.values()}
        sources = Counter(finding.source for finding in self.findings.values())
        return {
            "schema": SUMMARY_SCHEMA,
            "version": FUNNEL_VERSION,
            "protocols": dict(self.setup.protocols),
            "free_session_protocol": self.setup.free_session_protocol,
            "models": dict(self.models),
            "elapsed_seconds": self.elapsed(),
            "phase_seconds": {phase: [round(value, 1) for value in times] for phase, times in sorted(self.phase_times.items())},
            "tokens": self.budget.record(),
            "funnel": {
                "units": len(self.units),
                "rated": len(self.ratings),
                # The unit checks of phase 2 that gave an answer; a unit that cannot be read and a unit check
                # that failed again after its requeue (or whose answer cannot be read) count apart.
                "checked": self.counts["checked"],
                "units_unreadable": self.counts["units_unreadable"],
                "unit_checks_failed": self.counts["unit_checks_failed"],
                "unit_checks_refused": self.counts["unit_checks_refused"],
                # The units that phase 2 can check: the units of the queue (the units outside tests, docs and
                # data files, and the windows of search hits).
                "units_to_check": len(self.units) - self.counts["units_excluded"],
                "sessions_answered": self.counts["sessions_answered"],
                "sessions_no_answer": self.counts["sessions_no_answer"],
                "flagged_units": len(flagged),
                "leads": len(self.leads),
                **{f"leads_{name}": sum(1 for lead in self.leads.values() if lead.confidence == name) for name in CONFIDENCES},
                "triaged": self.counts["triaged"],
                "triage_safe": self.counts["triage_safe"],
                "triage_failed": self.counts["triage_failed"],
                "triage_skipped": self.counts["triage_skipped"],
                "triage_not_needed": self.counts["triage_not_needed"],
                "deep_checked": self.counts["deep_checked"],
                "deep_reported": self.counts["deep_reported"],
                "deep_other": self.counts["deep_other"],
                "deep_nothing": self.counts["deep_nothing"],
                "deep_no_answer": self.counts["deep_no_answer"],
                "free_findings": self.counts["free_findings"],
                "findings": len(self.findings),
                "findings_by_source": dict(sorted(sources.items())),
                "verified": self.counts["verified"],
                "output": self.counts["output"],
                "removed": dict(sorted(reasons.items())),
                "units_left": len(self.queue),
                "leads_left": self.leads_left(),
                "units_with_leads_left": len(self.task_queue),
                "search_hits": self.counts["search_hits"],
                "hit_units": self.counts["hit_units"],
                "hit_windows": self.counts["hit_windows"],
                "hit_units_checked": sum(1 for identifier in self.hit_bonus if identifier in self.checked),
            },
            "pacing": {
                "large_queue": self.large_queue,
                "planned_checks": self.planned_checks,
                "unit_checks_started": self.unit_checks_started,
                "deep_release": self.deep_release(),
                "open": self.pace_open,
            },
            "counts": dict(sorted(self.counts.items())),
            "client": self.client.counters.record(),
            "stop": {"reason": self.stop_reason, "new_work": self.stop_new_work},
        }

    def leads_left(self) -> int:
        return sum(len(self.unit_leads[unit_id]) for unit_id in self.task_queue)

    def write_summary(self) -> None:
        atomic_write_json(self.work / SUMMARY_FILE, self.summary())
        self.write_leads()

    def write_leads(self) -> None:
        atomic_write_json(self.work / LEADS_FILE, [lead.record() for lead in self.leads.values()])
        self.leads_dirty = False

    def write_record(self) -> None:
        self.record["budget"] = self.budget.record()
        self.record["counts"] = dict(sorted(self.counts.items()))
        atomic_write_json(self.work / RECORD_FILE, self.record)

    def finish(self) -> int:
        self.stop_event.set()
        # The sessions stop at the same time. After SIGTERM the caller waits a
        # short grace before SIGKILL.
        grace = TERMINATED_STOP_GRACE if self.terminated or self.clock.past(self.clock.end) else END_STOP_GRACE
        left = [
            (name, session)
            for name, session in [(self.free_name, self.free), *self.sessions.items()]
            if session is not None and name not in self.ended_sessions
        ]
        stop_sessions([session for _, session in left], "runner-end", grace)
        for name, session in left:
            self.session_ended(name, session)
        self.executor.shutdown(wait=False, cancel_futures=True)
        abandoned = len(self.calls)
        for task in self.calls.values():
            self.budget.finish(task.id)
        self.calls.clear()
        self.stop_reason = self.stop_reason or self.stop_new_work or STOP_QUEUE
        self.note_unverified()
        kept = self.write_findings(final=True)
        self.record["stop"] = {
            "reason": self.stop_reason,
            "new_work": self.stop_new_work,
            "units_left": len(self.queue),
            "leads_left": self.leads_left(),
            "units_with_leads_left": len(self.task_queue),
            "abandoned_calls": abandoned,
            "seconds": self.elapsed(),
        }
        self.record["outputs"] = {"findings": len(kept), "candidates": len(self.findings)}
        self.record["budget_refused"] = self.budget_refused
        self.record["client"] = self.client.counters.record()
        self.write_summary()
        self.write_record()
        return EXIT_TERMINATED if self.terminated else 0


def verify_problem(call_status: str, status: str) -> str:
    """Why one verification gave no verdict, from the status of its call and of its answer."""
    if call_status == BUDGET_REFUSED:
        return "the gateway refused the verification for the budget"
    if call_status in (STOPPED, DEADLINE):
        return "the run stopped during the verification"
    if call_status == TIMEOUT:
        return "the verification call timed out"
    if status == "parse-error":
        return "the answer of the verification cannot be read"
    return "the verification call failed"


def repository_files(root: Path, limit: int) -> int:
    """The regular files of the repository outside the folders without code of the project, counted up to ``limit``.

    The count of the router of the hybrid (``router.count_files``): version
    control, dependencies, virtual environments, vendored code and build
    output are left out at any depth. Links are not followed and do not
    count, and a folder that cannot be read does not count.
    """
    from ..router import count_files

    return count_files(root, limit).files


def parse_pairs(values: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for value in values:
        name, separator, rest = value.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or "\0" in rest:
            raise ValueError(f"an agent variable needs NAME=VALUE, not {value!r}")
        pairs.append((name, rest))
    return pairs


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sentrytower.funnel", description="Run the funnel engine on one repository.")
    parser.add_argument("--spec", type=Path, help="the spec file of the run (written by sentrytower audit)")
    parser.add_argument("--phase0", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--repository", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--deadline-seconds", type=float, help=argparse.SUPPRESS)
    parser.add_argument("--max-units", type=int, default=5000, help=argparse.SUPPRESS)
    return parser


def phase0_main(args: argparse.Namespace) -> int:
    """Run ``funnel.inventory.build_inventory`` and write its result (the phase-0 process)."""
    from .inventory import build_inventory

    repository = Path(args.repository or Path.cwd()).absolute()

    def log(message: object) -> None:
        print(f"inventory: {message}"[:500], file=sys.stderr, flush=True)

    inventory = build_inventory(
        repository,
        deadline_seconds=float(args.deadline_seconds or 1500.0),
        max_units=int(args.max_units),
        log=log,
    )
    atomic_write_json(args.output, inventory)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    args = parser.parse_args(argv)
    if args.phase0:
        if args.output is None:
            parser.error("--phase0 needs --output")
        return phase0_main(args)
    if args.spec is None:
        parser.error("--spec is required")
    try:
        spec = RunSpec.from_document(json.loads(args.spec.read_text(encoding="utf-8")))
    except (OSError, ValueError) as problem:
        print(f"funnel: {problem}", file=sys.stderr, flush=True)
        return EXIT_REFUSED
    return run_main(spec)


def run_main(spec: RunSpec) -> int:
    """One funnel run: the record, the signal handlers and the orchestrator."""
    work = spec.work_dir
    work.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "version": FUNNEL_VERSION,
        "started_at": now_text(),
        "error": None,
        "terminated": None,
        "exit": None,
    }
    code = EXIT_REFUSED
    orchestrator: Orchestrator | None = None
    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

    def on_signal(number: int, _frame: object) -> None:
        record["terminated"] = signal.Signals(number).name
        if orchestrator is not None:
            orchestrator.terminated = True
            orchestrator.stop_event.set()
            orchestrator.wake.set()
        else:
            raise SystemExit(EXIT_TERMINATED)

    for number in previous:
        signal.signal(number, on_signal)
    try:
        try:
            parameters = Parameters.from_record({**Parameters().record(), **spec.parameters})
            from ..agent.runner import AGENT_PROTOCOL

            setup = load_setup(parameters, free_session_protocol=AGENT_PROTOCOL)
            orchestrator = Orchestrator(spec=spec, setup=setup, record=record)
        except (OSError, ValueError) as problem:
            # The orchestrator starts no session and makes no model call.
            record["error"] = str(problem)
            print(f"funnel: {problem}", file=sys.stderr, flush=True)
            return EXIT_REFUSED
        code = orchestrator.run()
    except Exception as error:  # noqa: BLE001 - the record and the findings file must still be written
        record["error"] = f"orchestrator error: {type(error).__name__}: {error}"
        traceback.print_exc()
        code = EXIT_ERROR
        if orchestrator is not None:
            try:
                orchestrator.terminated = True
                orchestrator.stop_reason = "error"
                orchestrator.finish()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        record["exit"] = code
        record["ended_at"] = now_text()
        try:
            atomic_write_json(work / RECORD_FILE, record)
        except OSError as error:
            print(f"funnel: cannot write the record: {type(error).__name__}", file=sys.stderr, flush=True)
    return code


def exit_now(code: int) -> None:
    """End the process: a model call that still runs in a thread must not hold the exit."""
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
