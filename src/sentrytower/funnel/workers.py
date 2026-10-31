"""The agent sessions of a run: the sessions of the funnel and of the deep engine of the agent route.

The caller gives the engine the command of the single agent: the agent
runner (``python -m sentrytower.agent.runner``) with its options, ``--``,
and the Pi command with the prompt as its last part. Each agent session of
the run comes from this one command, so each session has the provider
route, the tools, the extension and the sampling of the single agent:

- The free-roaming session is the command with two new inputs: the token
  budget and the wall clock of the session. Its prompt is the audit prompt
  of the single agent.
- A task session (a deep check, a focus session or a deep check of the
  sweep of the funnel, a slice of the agent route) is the command with a
  new token budget, wall clock, session folder, agent folder and prompt
  (``TaskSessions``). Each task session gets its own copy of the Pi agent
  folder (Pi keeps lock files there) and its own session folder, so the
  files of two sessions never meet.
- In a multi-model configuration, a session of another role gets the model
  of its role (``--model``).

The agent runner applies its own rules to each session: the blank-reply
restarts, the token reserve and the final turn, and the hard limits. The
orchestrator reads the tokens and the answer of a session with the session
readers of the agent package, and the outputs of the grep and find calls of
the session for the queue (``hits.py``).

The session files do not hold a call that a stop killed: the runner stopped
the turn (its reserve or a hard limit) or the session got SIGTERM while the
agent waited for the model. The gateway still counts that call. Thus the
tokens of an ended session add one call for each such stop: the tokens of
the last recorded call (the context that the next call sends again) and the
answer estimate. A reply that ends with the budget refusal of the gateway
(``REFUSAL_TEXTS``) is a refusal for the run.

Standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..agent.session import BLANK_SESSIONS, read_answer
from ..limits import REFUSAL_TEXTS
from ..programs import program_environment
from .hits import SEARCH_TOOLS

RUNNER_RECORD = "runner.json"
AGENT_VARIABLES = ("PI_CODING_AGENT_DIR", "PI_PACKAGE_DIR")
# The copy of the agent folder that each task session copies, and the folders of a task session.
TEMPLATE_AGENT = "agent-template"
TASK_AGENT = "pi-agent"
TASK_SESSIONS = "pi-sessions"


def _single(argv: list[str], option: str) -> int:
    positions = [index for index, part in enumerate(argv) if part == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise ValueError(f"the agent command needs one {option}")
    return positions[0]


class PlainCommand:
    """The command of the single agent: the runner part, ``--``, and the Pi part with the prompt last."""

    def __init__(self, argv: list[str]) -> None:
        if "--" not in argv:
            raise ValueError("the agent command has no -- before the Pi command")
        self.argv = list(argv)
        self.split = argv.index("--")
        runner, pi = self.runner_part(), self.pi_part()
        if len(pi) < 2:
            raise ValueError("the agent command has no Pi command and prompt")
        for option in ("--session-dir", "--token-budget", "--wall-clock-seconds"):
            _single(runner, option)
        session = runner[_single(runner, "--session-dir") + 1]
        if pi[_single(pi[:-1], "--session-dir") + 1] != session:
            raise ValueError("the runner and Pi have different session folders")
        self.session_dir = session
        self.prompt = pi[-1]

    def runner_part(self) -> list[str]:
        return self.argv[: self.split]

    def pi_part(self) -> list[str]:
        return self.argv[self.split + 1 :]

    def with_inputs(
        self,
        *,
        token_budget: int,
        seconds: int,
        session_dir: str | None = None,
        prompt: str | None = None,
        agent_from: str | None = None,
        agent_to: str | None = None,
        model: str | None = None,
    ) -> list[str]:
        """The command with new budget inputs, and optionally a new session folder, agent folder, prompt and model."""
        runner, pi = self.runner_part(), self.pi_part()
        runner[_single(runner, "--token-budget") + 1] = str(int(token_budget))
        runner[_single(runner, "--wall-clock-seconds") + 1] = str(int(seconds))
        if session_dir is not None:
            runner[_single(runner, "--session-dir") + 1] = session_dir
            pi[_single(pi[:-1], "--session-dir") + 1] = session_dir
        if agent_from is not None and agent_to is not None:
            for index, part in enumerate(pi[:-1]):
                if index and pi[index - 1] in ("--extension", "-e"):
                    pi[index] = replace_prefix(part, agent_from, agent_to)
        if model is not None:
            pi[_single(pi[:-1], "--model") + 1] = model
        if prompt is not None:
            pi[-1] = prompt
        return [*runner, "--", *pi]


def replace_prefix(value: str, old: str, new: str) -> str:
    old = old.rstrip("/")
    if value == old:
        return new
    if value.startswith(old + "/"):
        return new.rstrip("/") + value[len(old) :]
    return value


def session_environment(
    base: dict[str, str], pairs: list[tuple[str, str]], *, agent_from: str | None = None, agent_to: str | None = None
) -> dict[str, str]:
    """The environment of an agent session: the environment of the run and the agent variables.

    PATH keeps its absolute entries only (``programs.search_path``): the
    session runs in the audited repository.
    """
    environment = program_environment({**base, **dict(pairs)})
    if agent_from is not None and agent_to is not None:
        for name in AGENT_VARIABLES:
            if name in environment:
                environment[name] = replace_prefix(environment[name], agent_from, agent_to)
    return environment


def copy_agent_directory(source: Path, target: Path) -> None:
    """A copy of a Pi agent folder: links stay links, lock folders of Pi are not copied."""
    shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns("*.lock"))


class SessionTokens:
    """The tokens and the search outputs that the agent records in the session files of one session folder.

    It reads only the new bytes of each ``*.jsonl`` file of the folder and of
    the folder of the blank sessions that the runner moves next to it
    (``blank-sessions``). A file counts by its inode, so a file that the
    runner moves keeps its count, and a restart after a blank first reply
    hides no tokens. Each grep or find output that does not report an error
    is kept with the arguments of its call until ``take_searches``.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.offsets: dict[tuple[int, int], int] = {}
        self.pending: dict[tuple[int, int], bytes] = {}
        self.totals: dict[tuple[int, int], int] = {}
        self.calls: dict[str, tuple[str, Any]] = {}
        self.searches: list[tuple[str, Any, str]] = []
        # The tokens of the last recorded call, and the replies that end
        # with the budget refusal of the gateway.
        self.last_call = 0
        self.refusals = 0

    def _files(self) -> list[Path]:
        found: list[Path] = []
        for folder in (self.directory, self.directory.parent / BLANK_SESSIONS):
            if folder.is_dir():
                found.extend(sorted(folder.glob("*.jsonl")))
        return found

    def poll(self) -> int:
        for path in self._files():
            try:
                status = path.stat()
                key = (status.st_dev, status.st_ino)
                with path.open("rb") as stream:
                    stream.seek(self.offsets.get(key, 0))
                    chunk = stream.read()
            except OSError:
                continue
            self.offsets[key] = self.offsets.get(key, 0) + len(chunk)
            *lines, rest = (self.pending.get(key, b"") + chunk).split(b"\n")
            self.pending[key] = rest
            for line in lines:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = entry.get("message") if isinstance(entry, dict) and entry.get("type") == "message" else None
                if isinstance(message, dict):
                    self._message(key, message)
        return self.total()

    def _message(self, key: tuple[int, int], message: dict[str, Any]) -> None:
        role = message.get("role")
        content = found if isinstance(found := message.get("content"), list) else []
        if role == "assistant":
            usage = given if isinstance(given := message.get("usage"), dict) else {}
            tokens = int(usage.get("totalTokens") or 0)
            self.totals[key] = self.totals.get(key, 0) + tokens
            if tokens > 0:
                self.last_call = tokens
            error = message.get("errorMessage")
            if isinstance(error, str) and any(text in error for text in REFUSAL_TEXTS):
                self.refusals += 1
            for part in content:
                if isinstance(part, dict) and part.get("type") == "toolCall" and part.get("name") in SEARCH_TOOLS:
                    self.calls[str(part.get("id"))] = (str(part["name"]), part.get("arguments"))
        elif role == "toolResult" and message.get("toolName") in SEARCH_TOOLS:
            call = self.calls.pop(str(message.get("toolCallId")), None)
            if call is not None and not message.get("isError"):
                text = "".join(part["text"] for part in content if isinstance(part, dict) and isinstance(part.get("text"), str))
                self.searches.append((call[0], call[1], text))

    def take_searches(self) -> list[tuple[str, Any, str]]:
        """The search outputs read since the last call: (tool, arguments, output text)."""
        searches, self.searches = self.searches, []
        return searches

    def total(self) -> int:
        return sum(self.totals.values())


@dataclass
class SessionOutcome:
    """What one ended agent session gave."""

    exit: int | None
    tokens: int
    seconds: float
    runner: dict[str, Any] | None
    document: dict[str, Any] | None
    error: str | None = None
    stopped: str | None = None
    final_turn: str | None = None
    killed_calls: int = 0
    killed_tokens: int = 0
    refusals: int = 0

    def record(self) -> dict[str, Any]:
        return {
            "exit": self.exit,
            "tokens": self.tokens,
            "killed_calls": self.killed_calls,
            "killed_tokens": self.killed_tokens,
            "refusals": self.refusals,
            "seconds": round(self.seconds, 1),
            "error": self.error,
            "stopped": self.stopped,
            "final_turn": self.final_turn,
            "findings": len((self.document or {}).get("findings") or []) if self.document else None,
        }


@dataclass
class PiSession:
    """One agent runner process in its own process group."""

    name: str
    argv: list[str]
    environment: dict[str, str]
    cwd: Path
    session_dir: Path
    log_dir: Path
    process: subprocess.Popen[bytes] | None = None
    started: float = 0.0
    ended: float | None = None
    tokens: SessionTokens | None = None
    stopped_by_runner: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # The copy of the agent folder of a task session; None for a session in the agent folder of the run.
    agent_dir: Path | None = None

    def start(self) -> PiSession:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.tokens = SessionTokens(self.session_dir)
        self.started = time.monotonic()
        with (self.log_dir / "stdout.log").open("ab") as stdout, (self.log_dir / "stderr.log").open("ab") as stderr:
            self.process = subprocess.Popen(
                self.argv,
                env=self.environment,
                cwd=self.cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        return self

    def poll_tokens(self) -> int:
        return self.tokens.poll() if self.tokens is not None else 0

    def take_searches(self) -> list[tuple[str, Any, str]]:
        """The grep and find outputs that the last polls read."""
        return self.tokens.take_searches() if self.tokens is not None else []

    def running(self) -> bool:
        if self.process is None:
            return False
        if self.process.poll() is None:
            return True
        if self.ended is None:
            self.ended = time.monotonic()
            # Each process that stays in the group of the session gets SIGKILL.
            _signal_group(self.process, signal.SIGKILL)
        return False

    def refusals(self) -> int:
        """The replies of the session that end with the budget refusal of the gateway."""
        return self.tokens.refusals if self.tokens is not None else 0

    def outcome(self, answer_tokens: int = 0) -> SessionOutcome:
        """The runner record and the findings document of the ended session.

        The tokens add each call that a stop killed (``killed_calls``): the
        tokens of the last recorded call and ``answer_tokens``.
        """
        runner_path = self.session_dir / RUNNER_RECORD
        runner: dict[str, Any] | None = None
        try:
            runner = json.loads(runner_path.read_text())
        except (OSError, ValueError):
            runner = None
        tokens = self.poll_tokens()
        if isinstance(runner, dict) and isinstance(runner.get("tokens_at_end"), int):
            tokens = max(tokens, runner["tokens_at_end"])
        killed = killed_calls(runner if isinstance(runner, dict) else None, self.stopped_by_runner)
        last_call = self.tokens.last_call if self.tokens is not None else 0
        killed_tokens = killed * (last_call + max(0, int(answer_tokens)))
        tokens += killed_tokens
        seconds = (self.ended or time.monotonic()) - self.started
        document, error = read_answer(self.session_dir)
        return SessionOutcome(
            exit=self.process.returncode if self.process is not None else None,
            tokens=tokens,
            seconds=seconds,
            runner=runner if isinstance(runner, dict) else None,
            document=document,
            error=error,
            stopped=self.stopped_by_runner or (runner or {}).get("stopped") or (runner or {}).get("final_stopped"),
            final_turn=(runner or {}).get("final_turn"),
            killed_calls=killed,
            killed_tokens=killed_tokens,
            refusals=self.refusals(),
        )


class TaskSessions:
    """The sessions of a run from the command of the single agent; the task sessions each in its own folder.

    ``prepare`` gives the session of a task in the folder of the task: the
    copy of the agent template in ``pi-agent`` (after ``use_template``) and
    the environment, whose agent variables point at the copy. ``start``
    gives the session its command, with the inputs of the task and the
    extensions of the copy, and starts it. The session files go to
    ``pi-sessions``.
    """

    def __init__(self, plain: PlainCommand, pairs: list[tuple[str, str]], *, cwd: Path, base_env: dict[str, str]) -> None:
        self.plain = plain
        self.pairs = list(pairs)
        self.cwd = cwd
        self.base_env = base_env
        self.agent_from = dict(self.pairs).get("PI_CODING_AGENT_DIR")
        self.template: Path | None = None

    def environment(self, agent_to: Path | None = None) -> dict[str, str]:
        """The environment of a session; with ``agent_to`` the agent variables point at that copy of the agent folder."""
        return session_environment(self.base_env, self.pairs, agent_from=self.agent_from, agent_to=str(agent_to) if agent_to else None)

    def use_template(self, template: Path) -> None:
        """A clean copy of the agent folder (made once): each task session from here on copies it."""
        assert self.agent_from is not None
        if not template.exists():
            copy_agent_directory(Path(self.agent_from), template)
        self.template = template

    def prepare(self, name: str, folder: Path) -> PiSession:
        """The session of a task in ``folder``, not started; the OSError of a copy that fails goes to the caller."""
        agent_to = None
        if self.template is not None and self.agent_from:
            agent_to = folder / TASK_AGENT
            copy_agent_directory(self.template, agent_to)
        return PiSession(name, [], self.environment(agent_to), self.cwd, folder / TASK_SESSIONS, folder, agent_dir=agent_to)

    def start(self, session: PiSession, *, token_budget: int, seconds: int, prompt: str, model: str) -> PiSession:
        """Start a prepared session with the inputs of its task; the OSError of a start that fails goes to the caller."""
        session.argv = self.plain.with_inputs(
            token_budget=token_budget,
            seconds=seconds,
            session_dir=str(session.session_dir),
            prompt=prompt,
            agent_from=self.agent_from,
            agent_to=str(session.agent_dir) if session.agent_dir else None,
            model=model,
        )
        return session.start()


def killed_calls(runner: dict[str, Any] | None, stopped_by_runner: str | None) -> int:
    """The model calls that a stop of the session killed: one for each turn that
    the runner stopped at a limit, and one when the session got SIGTERM."""
    turns = found if isinstance(runner, dict) and isinstance(found := runner.get("turns"), list) else []
    count = sum(1 for turn in turns if isinstance(turn, dict) and turn.get("stopped"))
    if (runner or {}).get("terminated") or (runner is None and stopped_by_runner):
        count += 1
    return count


def stop_sessions(sessions: list[PiSession], reason: str, grace: float) -> None:
    """Stop the sessions at the same time: SIGTERM to each process group, SIGKILL to each
    group that still runs after ``grace`` seconds. The whole stop takes at most about ``grace``."""
    running = [session for session in sessions if session.process is not None and session.process.poll() is None]
    for session in running:
        session.stopped_by_runner = reason
        _signal_group(session.process, signal.SIGTERM)  # type: ignore[arg-type]
    deadline = time.monotonic() + max(0.0, grace)
    for session in running:
        try:
            session.process.wait(timeout=max(0.0, deadline - time.monotonic()))  # type: ignore[union-attr]
        except subprocess.TimeoutExpired:
            pass
    for session in running:
        if session.process.poll() is None:  # type: ignore[union-attr]
            _signal_group(session.process, signal.SIGKILL)  # type: ignore[arg-type]
            session.process.wait()  # type: ignore[union-attr]
        session.running()


def _signal_group(process: subprocess.Popen[Any], number: int) -> None:
    try:
        os.killpg(process.pid, number)
    except (ProcessLookupError, PermissionError):
        pass
