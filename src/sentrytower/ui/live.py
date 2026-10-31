"""The live view of an audit: the agent, the phases of the engine, what the agent reads now, tokens and cost.

``LiveAudit`` is the log of an audit in a terminal. ``run_audit`` calls
``route_known`` when the route is known, ``engine_started`` when the engine
starts and ``tick`` while it runs. The view reads the state of the engine
from the files of the run: the records of the funnel (``funnel-run.json``,
``summary.json``) and the session files of the agents, whose tool calls
give the activity line ("reading src/app.py"). It shows no text of the
model and no code.
"""

from __future__ import annotations

import io
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..audit import Log
from ..policies import BUILTIN_POLICIES
from .mascot import BADGE, art, beside
from .screen import Screen
from .term import PLAIN, Caps, Line, Style, cells
from .theme import Theme
from .widgets import ASCII, Symbols, elapsed_text, money, progress_bar, tokens_text

POLL_SECONDS = 0.5
FRAME_SECONDS = 0.1
QUIET_ACTIVITY_SECONDS = 25.0
# The activity line of a phase while no agent tool call is recent.
PHASE_ACTIVITY = {
    "Map the code": "mapping the code units",
    "Check each unit": "checking the units one by one",
    "Dig into leads": "tracing the leads in depth",
    "Verify and rank": "verifying and ranking the findings",
    "Explore and trace": "exploring the repository",
}


def model_label(models: dict[str, str]) -> str:
    distinct = sorted(set(models.values()))
    if len(distinct) > 1:
        return f"{len(distinct)} models"
    model = distinct[0] if distinct else "?"
    policy = BUILTIN_POLICIES.get(model)
    if policy is not None:
        return policy.name.split(" ", 1)[1] if policy.name.lower().startswith("z.ai ") else policy.name
    return model


def hours_text(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds // 60} min"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


@dataclass
class Activity:
    text: str
    at: float


@dataclass
class SessionTail:
    """New tool calls of the agent session files below some folders (each file read from where it stopped)."""

    folders: list[Path]
    repository: Path
    offsets: dict[Path, int] = field(default_factory=dict)
    reads: int = 0
    searches: int = 0
    files_read: set[str] = field(default_factory=set)
    last: Activity | None = None

    def poll(self) -> None:
        for folder in self.folders:
            if not folder.is_dir():
                continue
            for path in folder.rglob("*.jsonl"):
                self._read(path)

    def _read(self, path: Path) -> None:
        start = self.offsets.get(path, 0)
        try:
            size = path.stat().st_size
            if size <= start:
                return
            with path.open("rb") as stream:
                stream.seek(start)
                data = stream.read(size - start)
        except OSError:
            return
        end = data.rfind(b"\n")
        if end < 0:
            return
        self.offsets[path] = start + end + 1
        # JSON lines split on "\n" only, as the session readers split them (``bytes.splitlines`` also splits on "\r").
        for raw in data[:end].split(b"\n"):
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            message = entry.get("message") if isinstance(entry, dict) else None
            if not isinstance(message, dict) or message.get("role") != "assistant":
                continue
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "toolCall":
                    arguments = block.get("arguments")
                    self._tool(str(block.get("name") or ""), arguments if isinstance(arguments, dict) else {})

    def _relative(self, value: Any) -> str:
        text = str(value or ".").strip() or "."
        for root in (str(self.repository), str(self.repository.resolve())):
            if text == root:
                return "."
            if text.startswith(root + "/"):
                return text[len(root) + 1 :]
        return text.removeprefix("./")

    def _tool(self, name: str, arguments: dict[str, Any]) -> None:
        if name == "read":
            path = self._relative(arguments.get("path"))
            self.reads += 1
            self.files_read.add(path)
            text = f"reading {path}"
        elif name == "grep":
            self.searches += 1
            pattern = str(arguments.get("pattern") or "")[:48]
            where = self._relative(arguments.get("path")) if arguments.get("path") else ""
            text = f'searching for "{pattern}"' + (f" in {where}" if where not in ("", ".") else "")
        elif name == "find":
            self.searches += 1
            text = f"finding files {str(arguments.get('pattern') or '')[:48]}".rstrip()
        elif name == "ls":
            text = f"looking at {self._relative(arguments.get('path'))}/"
        else:
            text = f"using {name}"
        self.last = Activity(text, time.monotonic())


@dataclass
class Phase:
    title: str
    state: str = "pending"  # pending, active, done
    detail: Line = field(default_factory=list)
    seconds: float | None = None


class LiveAudit(Log):
    """The log of an audit in a terminal: one live region, redrawn while the engine runs."""

    live = True

    def __init__(self, screen: Screen, theme: Theme, caps: Caps, *, agent_name: str, agent_color: str) -> None:
        super().__init__(quiet=False, verbose=False, stream=io.StringIO())
        self.screen = screen
        self.theme = theme
        self.caps = caps
        self.sym = Symbols() if caps.unicode else ASCII
        self.agent_name = agent_name
        self.agent_color = agent_color
        self.repository: Path | None = None
        self.route = ""
        self.header: list[Line] = []
        self.snapshot: Callable[[], dict[str, Any]] | None = None
        self.work: Path | None = None
        self.sessions: Path | None = None
        self.tail: SessionTail | None = None
        self.state: dict[str, Any] = {}
        self.engine_started_at: float | None = None
        self.last_poll = 0.0
        self.last_frame = 0.0
        self.frame = 0
        self.budget: dict[str, Any] = {}
        self.stopping = False
        self.warnings: list[str] = []

    # Plain lines of run_audit: kept, not shown (the view shows the same facts).
    def info(self, text: str) -> None:
        self.stream.write(text + "\n")

    def debug(self, text: str) -> None:
        return None

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        self.screen.print([[(f"{self.sym.warning} ", self.theme.caution), (text, PLAIN)]])

    def route_known(
        self,
        *,
        repository: Path,
        files: int,
        more: bool,
        route: str,
        models: dict[str, str],
        max_tokens: int,
        wall_clock_seconds: int,
        max_cost_usd: float | None,
    ) -> None:
        self.repository = repository
        self.route = route
        self.budget = {"tokens": max_tokens, "seconds": wall_clock_seconds, "cost": max_cost_usd}
        engine = "funnel engine" if route == "funnel" else "single-agent engine"
        count = f"more than {files - 1:,} files" if more else f"{files:,} files"
        cap = f"cap {money(max_cost_usd)}" if max_cost_usd else "no cost cap"
        dot = self.sym.dot
        facts = f"{count} {dot} {engine} {dot} {model_label(models)} {dot} {cap} {dot} {hours_text(wall_clock_seconds)}"
        self.header = [
            [(self.agent_name, self.theme.name), (" is auditing ", PLAIN), (repository.name, self.theme.bold)],
            [(facts, self.theme.dim)],
        ]
        self._draw()

    def engine_started(self, *, route: str, work: Path, sessions: Path, snapshot: Callable[[], dict[str, Any]]) -> None:
        self.route = route
        self.work = work
        self.sessions = sessions
        self.snapshot = snapshot
        self.engine_started_at = time.monotonic()
        folders = [sessions] + ([work / "tasks"] if route == "funnel" else [])
        self.tail = SessionTail(folders, self.repository or Path())
        self._draw()

    def tick(self) -> None:
        now = time.monotonic()
        if now - self.last_frame < FRAME_SECONDS:
            return
        self.last_frame = now
        if now - self.last_poll >= POLL_SECONDS:
            self.last_poll = now
            self._poll()
        self.frame += 1
        self._draw()

    def interrupted(self) -> None:
        self.stopping = True
        self._draw()

    def _poll(self) -> None:
        if self.snapshot is not None:
            try:
                self.state.update(self.snapshot())
            except Exception:  # noqa: BLE001 - a view never stops the run
                pass
        if self.tail is not None:
            self.tail.poll()
        if self.route == "funnel" and self.work is not None:
            self.state["record"] = _read_json(self.work / "funnel-run.json") or self.state.get("record") or {}
            self.state["summary"] = _read_json(self.work / "summary.json") or self.state.get("summary") or {}

    def phases(self) -> list[Phase]:
        if self.route != "funnel":
            tail = self.tail
            detail: Line = []
            if tail is not None and (tail.reads or tail.searches):
                read_count, searches = len(tail.files_read), tail.searches
                reads = f"{read_count} file{'s' if read_count != 1 else ''} read"
                detail = [(f"{reads} {self.sym.dot} {searches} search{'es' if searches != 1 else ''}", self.theme.dim)]
            return [Phase("Explore and trace", "active", detail)]
        record = self.state.get("record") or {}
        summary = self.state.get("summary") or {}
        counts = summary.get("funnel") or {}
        phase0 = record.get("phase0") or {}
        times = summary.get("phase_seconds") or {}
        units = counts.get("units") or phase0.get("units")
        planned = int((record.get("pacing") or {}).get("planned_checks") or 0)
        checked = int(counts.get("checked") or 0)
        left = counts.get("units_left")
        leads = int(counts.get("leads") or 0)
        deep = int(counts.get("deep_checked") or 0)
        verified = int(counts.get("verified") or 0)
        stop = (record.get("stop") or {}).get("reason")
        # The queue grows while the agents' searches add units, so the total is the checks done and the
        # units left (at most the cap of unit checks), not the plan at the start of the checks.
        cap = int((record.get("parameters") or {}).get("max_unit_checks") or 0)
        total = checked + int(left) if isinstance(left, int) else planned
        total = max(checked, min(total, cap) if cap else total)
        mapped = bool(phase0.get("status")) or bool(units)
        mapping = Phase("Map the code", "done" if mapped else "active")
        if mapped and units:
            files = phase0.get("files")
            mapping.detail = [
                (f"{int(units):,} code units" + (f" in {int(files):,} files" if isinstance(files, int) else ""), self.theme.dim)
            ]
            mapping.seconds = phase0.get("seconds")
        checking = Phase("Check each unit")
        if mapped:
            finished = bool(stop) or bool(cap and checked >= cap) or (left == 0 and checked > 0)
            checking.state = "done" if finished else "active"
            if total:
                fraction = checked / total
                checking.detail = [
                    (f"{checked:,} of {total:,} ", PLAIN),
                    *progress_bar(fraction, 16, self.theme, self.sym),
                    (f" {round(fraction * 100):>3}%", self.theme.dim),
                ]
            elif "rating" in times and "unit_check" not in times:
                checking.detail = [("ranking the units", self.theme.dim)]
        digging = Phase("Dig into leads")
        if leads or deep:
            digging.state = "done" if stop else "active"
            digging.detail = [(f"{leads} leads" + (f" {self.sym.dot} {deep} checked in depth" if deep else ""), self.theme.dim)]
        verifying = Phase("Verify and rank", "active" if stop or verified else "pending")
        if verified:
            verifying.detail = [(f"{verified} verified", self.theme.dim)]
        return [mapping, checking, digging, verifying]

    def _mark(self, phase: Phase) -> tuple[str, Style]:
        if phase.state == "done":
            return self.sym.check, self.theme.good
        if phase.state == "active":
            return self.sym.spinner[self.frame % len(self.sym.spinner)], self.theme.mark
        return self.sym.off, self.theme.dim

    def frame_lines(self) -> list[Line]:
        rows: list[Line] = [*self.header, []]
        phases = self.phases() if self.engine_started_at is not None else [Phase("Count the files", "done")]
        width = max(cells(phase.title) for phase in phases)
        for phase in phases:
            mark, style = self._mark(phase)
            line: Line = [
                (f"{mark} ", style),
                (phase.title + " " * (width - cells(phase.title)) + "   ", self.theme.bold if phase.state == "active" else PLAIN),
            ]
            line += phase.detail
            rows.append(line)
        left = art(self.agent_color, BADGE, self.caps.color)
        body = beside(left, rows, gap=3) if left else rows
        lines: list[Line] = [*body, []]
        activity = self.tail.last if self.tail is not None else None
        spinner = self.sym.spinner[self.frame % len(self.sym.spinner)]
        if self.stopping:
            lines.append([(f"  {self.sym.warning} ", self.theme.caution), ("stopping; writing the report of the work so far", PLAIN)])
        elif activity is not None and time.monotonic() - activity.at < QUIET_ACTIVITY_SECONDS:
            lines.append([(f"  {spinner} ", self.theme.mark), (activity.text, self.theme.dim)])
        elif self.engine_started_at is not None:
            active = next((phase.title for phase in phases if phase.state == "active"), "")
            lines.append([(f"  {spinner} ", self.theme.mark), (PHASE_ACTIVITY.get(active, "working"), self.theme.dim)])
        lines.append([("  " + ("─" if self.caps.unicode else "-") * 60, self.theme.dim)])
        lines.append(self._footer())
        lines.append([("  ctrl-c stops the audit and keeps the report of the work so far", self.theme.dim)])
        return lines

    def _footer(self) -> Line:
        started = self.engine_started_at or self.started
        elapsed = time.monotonic() - started
        tokens = self.state.get("tokens") or 0
        cost = self.state.get("cost")
        line: Line = [("  ", PLAIN), (elapsed_text(elapsed), self.theme.bold), (" elapsed", self.theme.dim)]
        line += [
            (f" {self.sym.dot} ", self.theme.dim),
            (tokens_text(tokens), self.theme.bold),
            (f" of {tokens_text(self.budget.get('tokens'))} tokens", self.theme.dim),
        ]
        if cost is not None:
            line += [(f" {self.sym.dot} ", self.theme.dim), (money(cost), self.theme.bold)]
            if self.budget.get("cost"):
                line.append((f" of {money(self.budget['cost'])}", self.theme.dim))
        if self.route == "funnel":
            found = ((self.state.get("summary") or {}).get("funnel") or {}).get("findings")
            if found:
                # Candidates: the verification, the ranking and the caps keep the best of them.
                line += [(f" {self.sym.dot} ", self.theme.dim), (str(found), self.theme.bold), (" candidate findings", self.theme.dim)]
        return line

    def _draw(self) -> None:
        self.screen.draw(self.frame_lines())

    def close(self) -> None:
        self.screen.clear()
