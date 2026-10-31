"""The agent route with a budget of more than one standard run: the whole-repository session, then slice sessions.

The single agent of a large repository reads a small part of it and stops on
its own. With a larger budget this engine runs that session first, with the
budget of a standard run, then spends the rest on agent sessions that each
audit one slice of the repository in depth: a set of folders with about the
same amount of source code (no tests, docs, examples, vendored, generated or
build code). The count of slices is the count of standard sessions that the
rest of the budget buys, less a share for the verifications.

With a cost cap the money plans the slices: their count is what the money
left before the soft stop (85% of the cap) buys at the observed price of a
token (the estimate before the first spend), less a share for the
verifications. No slice and no verification starts after the soft stop (the
gateway says so, ``GET /budget``); the running slices get their final turns.
When the dollars end the run (``money.extend``) and a round of slices ends
below the soft stop, a new round audits finer slices, while the repository
splits into more of them (at most ``MAX_ROUNDS`` rounds).

The first location of each finding is the location that the output gives
it (``answer_places``). A finding of a slice that repeats an earlier finding
(the same file, within ``dedup_radius_lines``) is a duplicate. Each other
finding gets ``verify_votes`` blind verifications (the verify prompt of the
funnel, the code around the line, never the reasoning of the session) and
stays unless the majority verdict is "safe". The engine writes
``deep.json`` with its stop: ``budget`` (the soft stop), ``time-stop`` (a
planned slice did not start for lack of time), ``done`` or ``terminated``;
the parent reads the answers of the sessions and the decision for each
finding.

    python -P -m sentrytower.agent.deep --spec SPEC

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..findings import ENGINE_AGENT, from_agent
from ..funnel.inventory import census
from ..funnel.model_client import BUDGET_REFUSED, DEADLINE, STOPPED, ModelClient
from ..funnel.protocols import ParseError, combine_votes, parse_verify, read_prompt, render
from ..funnel.slices import SourceFiles, claim_message
from ..funnel.workers import TEMPLATE_AGENT, PiSession, PlainCommand, TaskSessions, stop_sessions
from ..limits import read_budget
from ..router import ROUTE_AGENT
from .answer import read_findings

SPEC_SCHEMA = "sentrytower-deep-spec-v1"
RECORD_FILE = "deep.json"
SLICE_PROMPT = "agent-slice.txt"
VERIFY_PROMPT = "funnel-verify.txt"
# The path tags of the inventory whose files are no slice: they hold no production code.
NOT_SOURCE_TAGS = frozenset({"test", "fixtures", "example", "docs", "vendor", "generated", "build", "benchmark"})
NOT_SOURCE_LANGUAGES = frozenset({"other", "binary"})
# The share of the rest of the budget that stays for the verifications.
VERIFY_SHARE = 0.05
# No slice session starts with less wall clock than this.
MIN_SESSION_SECONDS = 600
POLL_SECONDS = 1.0
STOP_GRACE_SECONDS = 10.0
# The code of one blind verification and the first lines of the file in its message.
VERIFY_MAX_CHARS = 20_000
VERIFY_HEADER_LINES = 40
VERIFY_THREADS = 8
VERIFY_TIMEOUT_SECONDS = 780.0
# The rounds of slices while the money of the run lasts, and the reading of the money.
MAX_ROUNDS = 4
MONEY_POLL_SECONDS = 2.0
MONEY_STOP = "no verification starts after 85% of the cost cap"
# The stop of a run whose wall clock left too little time for a planned slice (the stop name of the funnel).
TIME_STOP = "time-stop"


class Terminated(Exception):  # noqa: N818 - a signal, not an error
    """SIGTERM: the parent stops the engine."""


def _on_sigterm(number: int, frame: Any) -> None:
    raise Terminated


@dataclass(frozen=True)
class Scope:
    """A folder with everything below it, or only the files directly in it (``recursive`` False)."""

    path: str
    recursive: bool

    def text(self) -> str:
        folder = self.path or "the root folder"
        if self.recursive:
            return f"{self.path}/ and everything below it" if self.path else "the whole repository"
        return f"the files directly in {folder} (not its subfolders)"


class _Census:
    """The time budget of the census of the inventory: no limit."""

    def at(self, fraction: float) -> float:
        return float("inf")


def source_files(repository: Path) -> list[tuple[str, int]]:
    """The source files of a repository and their sizes: code that is not a test, docs, example, vendored or built."""
    records, _, _ = census(str(repository), _Census(), None)
    return [
        (record.path, record.size)
        for record in records
        if record.lang not in NOT_SOURCE_LANGUAGES and not set(record.tags) & NOT_SOURCE_TAGS
    ]


def make_slices(files: list[tuple[str, int]], count: int) -> list[list[Scope]]:
    """At most ``count`` slices of about the same code size, each a list of scopes, in path order.

    The largest slice that holds folders splits into its folders and the
    files directly in it, until there are ``count`` slices or no slice can
    split; then the two smallest neighbours merge until there are at most
    ``count``.
    """
    if count < 1 or not files:
        return []
    sizes: dict[str, int] = {}
    direct: dict[str, int] = {}
    children: dict[str, set[str]] = {}
    for path, size in files:
        parts = path.split("/")
        folder = "/".join(parts[:-1])
        direct[folder] = direct.get(folder, 0) + max(1, size)
        for depth in range(len(parts)):
            prefix = "/".join(parts[:depth])
            sizes[prefix] = sizes.get(prefix, 0) + max(1, size)
            if depth + 1 < len(parts):
                children.setdefault(prefix, set()).add("/".join(parts[: depth + 1]))

    def size_of(scope: Scope) -> int:
        return sizes.get(scope.path, 0) if scope.recursive else direct.get(scope.path, 0)

    groups: list[list[Scope]] = [[Scope("", True)]]
    while len(groups) < count:
        splittable = [group for group in groups if len(group) == 1 and group[0].recursive and children.get(group[0].path)]
        if not splittable:
            break
        largest = max(splittable, key=lambda group: size_of(group[0]))
        scope = largest[0]
        pieces = [[Scope(child, True)] for child in sorted(children[scope.path])]
        if direct.get(scope.path):
            pieces.insert(0, [Scope(scope.path, False)])
        index = groups.index(largest)
        groups[index : index + 1] = pieces
    while len(groups) > count:
        weights = [sum(size_of(scope) for scope in group) for group in groups]
        pair = min(range(len(groups) - 1), key=lambda index: weights[index] + weights[index + 1])
        groups[pair : pair + 2] = [groups[pair] + groups[pair + 1]]
    return groups


def answer_places(document: dict[str, Any] | None, repository: Path) -> dict[int, tuple[str, int, int]]:
    """The first location of each finding of an answer, by the index of the finding, as the output gives it.

    The output reads an answer with ``agent.answer.read_findings`` and
    converts each finding with ``findings.from_agent``; the same reading
    here keeps each location that the output keeps (a path or line alias,
    a line as text, a ``path:N`` suffix, one location object, a path in the
    repository folder). A finding without a valid location has no entry.
    """
    found, _ = read_findings(document or {}, cwd=str(repository), roots=(str(repository),))
    places: dict[int, tuple[str, int, int]] = {}
    for item in found:
        locations = from_agent(item, rank=item.index + 1, route=ROUTE_AGENT, engine=ENGINE_AGENT).locations
        if locations:
            places[item.index] = (locations[0].path, locations[0].start_line, locations[0].end_line)
    return places


def same_place(first: tuple[str, int, int], second: tuple[str, int, int], radius: int) -> bool:
    return first[0] == second[0] and max(first[1], second[1]) - min(first[2], second[2]) <= radius


@dataclass
class Spec:
    repository: Path
    work_dir: Path
    base_session_dir: Path
    token_ceiling: int
    wall_clock_seconds: int
    session_tokens: int
    max_sessions: int
    agent_command: list[str]
    agent_env: list[tuple[str, str]]
    model_base_url: str
    agent_model: str
    verify_model: str
    completion_ceilings: dict[str, int]
    verify_votes: int
    dedup_radius_lines: int
    # The cost cap of the run (None without a cap): cap_usd, soft_stop_usd, price_per_million (the estimate) and
    # extend (dollars end the run).
    money: dict[str, Any] | None = None

    @classmethod
    def load(cls, path: Path) -> Spec:
        document = json.loads(path.read_text())
        if document.get("schema") != SPEC_SCHEMA:
            raise ValueError(f"the spec must have the schema {SPEC_SCHEMA}")
        return cls(
            repository=Path(document["repository"]),
            work_dir=Path(document["work_dir"]),
            base_session_dir=Path(document["base_session_dir"]),
            token_ceiling=int(document["token_ceiling"]),
            wall_clock_seconds=int(document["wall_clock_seconds"]),
            session_tokens=int(document["session_tokens"]),
            max_sessions=max(1, int(document["max_sessions"])),
            agent_command=[str(part) for part in document["agent_command"]],
            agent_env=[(str(name), str(value)) for name, value in (document.get("agent_env") or {}).items()],
            model_base_url=str(document["model_base_url"]),
            agent_model=str(document["agent_model"]),
            verify_model=str(document["verify_model"]),
            completion_ceilings={str(name): int(value) for name, value in (document.get("completion_ceilings") or {}).items()},
            verify_votes=max(1, int(document.get("verify_votes") or 1)),
            dedup_radius_lines=int(document.get("dedup_radius_lines") or 10),
            money=dict(document["money"]) if isinstance(document.get("money"), dict) else None,
        )


class Deep:
    """The whole-repository session, then the slice sessions, and a blind verification of each new finding.

    The record (``deep.json``) changes after each step: a slice that starts,
    a slice that ends with its findings, each verification. Each write goes
    to a temporary file and then replaces the record in one rename, so the
    parent reads what finished when the engine stops (SIGTERM at the wall
    clock or after Ctrl-C, or SIGKILL after the grace). A finding without a
    verification (the run stopped first, the budget refused it, the call
    failed) keeps the status ``waiting`` or ``unverified`` with a reason.
    """

    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.started = time.monotonic()
        self.plain = PlainCommand(spec.agent_command)
        self.tasks = TaskSessions(self.plain, spec.agent_env, cwd=spec.repository, base_env=dict(os.environ))
        self.sessions: list[PiSession] = []
        self.record: dict[str, Any] = {"schema": "sentrytower-deep-v1", "slices": [], "findings": [], "stop": None}
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        # The first locations of the findings so far: a later finding at the same place is a duplicate.
        self.known: list[tuple[str, int, int]] = []
        self.verifier = ThreadPoolExecutor(max_workers=VERIFY_THREADS, thread_name_prefix="verify")
        self.verifications: list[Future[None]] = []
        self.client: ModelClient | None = None
        self.money_state: dict[str, Any] | None = None
        self.money_read_at = float("-inf")

    def read_money(self, *, force: bool = False) -> dict[str, Any] | None:
        """The money of the run from the gateway (at most every MONEY_POLL_SECONDS), or None without a cap."""
        if self.spec.money is None:
            return None
        with self.lock:
            now = time.monotonic()
            due = force or now - self.money_read_at >= MONEY_POLL_SECONDS
            if due:
                self.money_read_at = now
        if due:
            # The request runs outside the lock: the threads of the verifications write the record meanwhile.
            state = read_budget(self.spec.model_base_url)
            with self.lock:
                self.money_state = state or self.money_state
        with self.lock:
            return self.money_state

    def money_stopped(self) -> bool:
        """85% of the cost cap is spent (or the provider refused the run): no slice and no verification starts."""
        state = self.read_money()
        return bool(state and state.get("stop"))

    def remaining_seconds(self) -> float:
        return self.spec.wall_clock_seconds - (time.monotonic() - self.started)

    def write(self) -> None:
        with self.lock:
            text = json.dumps(self.record, indent=2) + "\n"
            path = self.spec.work_dir / RECORD_FILE
            staging = path.with_name(f".{path.name}.tmp")
            staging.write_text(text)
            os.replace(staging, path)

    def run_sessions(self, sessions: list[PiSession]) -> None:
        """Start the sessions, at most ``max_sessions`` at the same time; take the findings of each one that ends."""
        waiting = list(sessions)
        running: list[PiSession] = []
        while waiting or running:
            for session in [session for session in running if not session.running()]:
                running.remove(session)
                self.slice_ended(session)
            if waiting and self.money_stopped():
                for session in waiting:
                    session.extra["skipped"] = "budget"
                    self.slice_entry(session).update(status="skipped", skipped="budget")
                self.record["money_stop"] = True
                waiting = []
            while waiting and len(running) < self.spec.max_sessions and self.remaining_seconds() > MIN_SESSION_SECONDS:
                session = waiting.pop(0)
                seconds = int(self.remaining_seconds() - MIN_SESSION_SECONDS / 2)
                tokens, prompt = session.extra["tokens"], session.extra["prompt"]
                self.tasks.start(session, token_budget=tokens, seconds=seconds, prompt=prompt, model=self.spec.agent_model)
                self.sessions.append(session)
                running.append(session)
                self.slice_started(session)
            if not running and (not waiting or self.remaining_seconds() <= MIN_SESSION_SECONDS):
                for session in waiting:
                    session.extra["skipped"] = "time"
                    self.slice_entry(session).update(status="skipped", skipped="time")
                self.write()
                return
            time.sleep(POLL_SECONDS)

    def slice_count(self, base_tokens: int) -> int:
        """The slices that the rest of the budget buys, less a share for the verifications.

        When dollars end the run, the count is what the money left before the
        soft stop buys (at the observed price of a token, else the estimate);
        else what the tokens left buy, and no more than the money buys.
        """
        rest = self.spec.token_ceiling - base_tokens
        by_tokens = max(0, int(rest * (1 - VERIFY_SHARE) // self.spec.session_tokens))
        state = self.read_money(force=True) if self.spec.money is not None else None
        if self.spec.money is None or state is None or state.get("soft_stop_usd") is None:
            return by_tokens
        spent, tokens = float(state.get("spent_usd") or 0.0), int(state.get("tokens") or 0)
        estimate = float(self.spec.money.get("price_per_million") or 0.0) / 1_000_000
        price = spent / tokens if spent > 0 and tokens > 0 else estimate
        if price <= 0:
            return by_tokens
        by_money = max(0, int((float(state["soft_stop_usd"]) - spent) * (1 - VERIFY_SHARE) // (self.spec.session_tokens * price)))
        return by_money if self.spec.money.get("extend") else min(by_tokens, by_money)

    def slice_sessions(self, count: int, first: int = 1) -> list[PiSession]:
        """The sessions of ``count`` slices of the repository, numbered from ``first``."""
        slices = make_slices(source_files(self.spec.repository), count) if count >= 1 else []
        if slices and self.tasks.agent_from:
            self.tasks.use_template(self.spec.work_dir / TEMPLATE_AGENT)
        prompt_template = read_prompt(SLICE_PROMPT).strip()
        sessions = []
        for number, scopes in enumerate(slices, first):
            name = f"slice-{number:03d}"
            session = self.tasks.prepare(name, self.spec.work_dir / "slices" / name)
            paragraph = render(prompt_template, {"scopes": "\n".join(f"- {scope.text()}" for scope in scopes)})
            session.extra.update(
                tokens=self.spec.session_tokens,
                prompt=paragraph + "\n\n" + self.plain.prompt,
                scopes=[{"path": scope.path, "recursive": scope.recursive} for scope in scopes],
            )
            sessions.append(session)
            with self.lock:
                self.record["slices"].append(
                    {"name": name, "scopes": session.extra["scopes"], "session_dir": str(session.session_dir), "status": "planned"}
                )
        self.record["planned_slices"] = int(self.record.get("planned_slices") or 0) + len(slices)
        return sessions

    def slice_entry(self, session: PiSession) -> dict[str, Any]:
        with self.lock:
            return next(entry for entry in self.record["slices"] if entry["name"] == session.name)

    def slice_started(self, session: PiSession) -> None:
        self.slice_entry(session).update(status="running")
        self.write()

    def base_ended(self, base: PiSession) -> int:
        """The record of the whole-repository session; its findings are the first known places. Returns its tokens."""
        outcome = base.outcome()
        self.known.extend(answer_places(outcome.document, self.spec.repository).values())
        self.record["base"] = {
            "tokens": outcome.tokens,
            "seconds": round(time.monotonic() - self.started, 1),
            "answer": outcome.document is not None,
        }
        self.write()
        return outcome.tokens

    def slice_ended(self, session: PiSession, *, verify: bool = True) -> None:
        """The findings of a slice that ended: duplicates, findings without a location, and new findings to verify.

        The session counts as collected only when its entries are in the
        record, and the entries of a session go into the record once. A
        SIGTERM at any point thus leaves the rest to the stop (``stop``),
        which collects each slice session again.
        """
        if session.extra.get("collected"):
            return
        result = session.outcome()
        items = (result.document or {}).get("findings") or []
        places = answer_places(result.document, self.spec.repository)
        entries: list[dict[str, Any]] = []
        with self.lock:
            self.slice_entry(session).update(
                status="ended",
                tokens=result.tokens,
                seconds=round(result.seconds, 1),
                exit=result.exit,
                stopped=result.stopped,
                answer=result.document is not None,
                findings=len(items),
            )
            if not any(entry.get("session") == session.name for entry in self.record["findings"]):
                known = list(self.known)
                for index, item in enumerate(items):
                    entry: dict[str, Any] = {"session": session.name, "session_dir": str(session.session_dir), "index": index}
                    place = places.get(index)
                    if place is None:
                        entry["status"] = "no-location"
                    elif any(same_place(place, other, self.spec.dedup_radius_lines) for other in known):
                        entry["status"] = "duplicate"
                    else:
                        known.append(place)
                        cwe = item.get("cwe")
                        entry.update(location=list(place), cwe=cwe[0] if isinstance(cwe, list) and cwe else None, status="waiting")
                    entries.append(entry)
                self.record["findings"].extend(entries)
                self.known = known
            session.extra["collected"] = True
        self.write()
        for entry in entries:
            if entry["status"] == "waiting" and verify and not self.stop_event.is_set():
                self.verifications.append(self.verifier.submit(self.verify_one, entry))

    def verify_one(self, entry: dict[str, Any]) -> None:
        """``verify_votes`` blind verifications of one finding; the verdict is the majority, the score the mean."""
        if self.client is None:
            with self.lock:
                if self.client is None:
                    self.client = ModelClient(
                        self.spec.model_base_url,
                        self.spec.verify_model,
                        temperature=1.0,
                        timeout_seconds=VERIFY_TIMEOUT_SECONDS,
                        stop_event=self.stop_event,
                        max_completion_tokens=self.spec.completion_ceilings.get(self.spec.verify_model, 0),
                        completion_ceilings=self.spec.completion_ceilings,
                    )
        client = self.client
        path, line, end = entry["location"]
        message, _ = claim_message(
            path=path,
            line=line,
            end_line=end,
            cwe=entry.get("cwe"),
            files=SourceFiles(self.spec.repository),
            unit=None,
            routes=[],
            max_chars=VERIFY_MAX_CHARS,
            header_lines=VERIFY_HEADER_LINES,
        )
        if message is None:
            with self.lock:
                entry.update(status="unverified", reason="the code of the finding cannot be read")
            self.write()
            return
        system = read_prompt(VERIFY_PROMPT).strip()
        with self.lock:
            entry["status"] = "verifying"
        votes: list[dict[str, Any]] = []
        problem: str | None = None
        for _ in range(self.spec.verify_votes):
            if self.stop_event.is_set():
                problem = problem or "the run stopped before its verification"
                break
            if self.money_stopped():
                problem = problem or MONEY_STOP
                break
            result = client.complete([{"role": "system", "content": system}, {"role": "user", "content": message}], role="verify")
            if result.status == BUDGET_REFUSED:
                problem = "the gateway refused the verification for the budget"
                break
            if not result.ok:
                problem = (
                    "the run stopped during its verification" if result.status in (STOPPED, DEADLINE) else "the verification call failed"
                )
                continue
            try:
                votes.append(parse_verify(result.text))
            except ParseError:
                problem = "the answer of the verification cannot be read"
        with self.lock:
            if not votes:
                entry.update(status="unverified", reason=problem or "the verification call failed")
            else:
                combined = combine_votes(votes)
                entry.update(
                    verdict=combined["verdict"],
                    keep_score=combined["keep_score"],
                    votes=combined.get("votes"),
                    first_verdict=votes[0].get("verdict"),
                    first_score=votes[0].get("keep_score"),
                )
                entry["status"] = "safe" if combined["verdict"] == "safe" else "kept"
        self.write()

    def finish_verifications(self) -> None:
        for future in list(self.verifications):
            future.result()

    def stop(self) -> None:
        """SIGTERM: stop the sessions, keep the findings of the slices that ended, start no verification."""
        self.stop_event.set()
        stop_sessions(self.sessions, "terminated", STOP_GRACE_SECONDS)
        for session in self.sessions:
            if session.name.startswith("slice-") and session.process is not None:
                self.slice_ended(session, verify=False)
        self.verifier.shutdown(wait=False, cancel_futures=True)
        self.record["stop"] = "terminated"

    def run(self) -> int:
        base = PiSession(
            "base",
            list(self.spec.agent_command),
            self.tasks.environment(),
            self.spec.repository,
            self.spec.base_session_dir,
            self.spec.work_dir / "base",
        )
        try:
            self.write()
            self.sessions.append(base.start())
            while base.running():
                time.sleep(POLL_SECONDS)
            base_tokens = self.base_ended(base)
            count = self.slice_count(base_tokens)
            slices = self.slice_sessions(count)
            self.write()
            self.run_sessions(slices)
            rounds = 1
            # Dollars end the run: while a round ends below the soft stop, finer slices buy more depth.
            while (self.spec.money or {}).get("extend") and slices and rounds < MAX_ROUNDS and not self.money_stopped():
                affordable = self.slice_count(base_tokens)
                more = max(len(slices) + 1, affordable)
                if (
                    affordable < 1
                    or len(make_slices(source_files(self.spec.repository), more)) <= len(slices)
                    or self.remaining_seconds() <= MIN_SESSION_SECONDS
                ):
                    break
                rounds += 1
                slices = self.slice_sessions(more, first=int(self.record["planned_slices"]) + 1)
                self.record["rounds"] = rounds
                self.write()
                self.run_sessions(slices)
            self.finish_verifications()
            if self.record.get("money_stop") or self.money_stopped():
                self.record["stop"] = "budget"
            elif any(entry.get("skipped") == "time" for entry in self.record["slices"]):
                # Slices that never started for lack of time: the wall clock ended the work, not the plan.
                self.record["stop"] = TIME_STOP
            else:
                self.record["stop"] = "done"
        except Terminated:
            try:
                self.stop()
            except Terminated:
                self.record["stop"] = "terminated"
        self.record["seconds"] = round(time.monotonic() - self.started, 1)
        self.write()
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentrytower-deep", description="The agent route with a budget of more than one standard run.")
    parser.add_argument("--spec", type=Path, required=True)
    args = parser.parse_args(argv)
    spec = Spec.load(args.spec)
    spec.work_dir.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, _on_sigterm)
    return Deep(spec).run()


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # A verification that still waits for the model in a thread must not hold the exit.
    os._exit(code)
