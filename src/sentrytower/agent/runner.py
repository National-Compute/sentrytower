"""Run one agent session with a token reserve, hard limits and at most one final turn.

This is the runner of the single agent (protocol ``agent-v2.4``): the Pi
coding agent in print mode with the tools read, grep, find and ls. The
funnel uses the same runner for its free-roaming session and for each deep
check, with other budget inputs and another task prompt.

Usage::

    python -m sentrytower.agent.runner --session-dir DIR --final-message TEXT \\
        --token-budget N --wall-clock-seconds S [--reserve-fraction F] \\
        [--limit-fraction F] [--budget-url URL] -- PI_ARGV... PROMPT

The Pi arguments contain ``--session-dir DIR``; the prompt is the last one.

Budget. The agent has no budget of its own. The runner counts the tokens
that the agent records in its session file. It stops the first turn when
the count reaches ``1 - reserve`` of the token budget (the token reserve).
It stops every turn at ``limit`` of the token budget or of the wall clock
(the hard limits), before the model gateway refuses calls and before the
caller stops the run.

Blank first reply. A reply is blank when it did not end with an error (stop
reason ``stop``, ``length``, or ``toolUse``), it has no tool call, and its
text blocks have no character other than white space. A session has a blank
first reply when its file is complete, no reply in it has a tool call, and
its last reply is blank. When the agent ends a first turn by itself with
exit code 0 and the session has a blank first reply, the runner moves the
session file to ``blank-sessions/attempt-N.jsonl`` next to the session
folder. Then it starts the audit again with the same command and prompt, in
a new session. It does this at most ``BLANK_RESTARTS`` times, and not after
the token reserve or a hard limit. The tokens of each attempt count toward
the reserve and the limits.

Money. With ``--budget-url`` (the model gateway of the run), the runner
reads the money of the run while the first turn runs. When the gateway says
that new work must stop (85% of the cost cap is spent), the runner stops the
first turn as at the token reserve, starts no new session after a blank
reply, and gives the session its final turn: the answer comes inside the
last 15% of the cap.

Final turn. The runner resumes the session one time with the final message
and the same tools and settings when the agent stopped at the token
reserve or at the money stop, or when it stopped normally but its last
reply holds no findings JSON object. A run that ends with an error or at a hard limit gets no final
turn. Before the final turn, the runner repairs a last session line that the
stop cut, and it continues its token count after the repaired end of the
file.

The runner writes ``runner.json`` next to the session, also when it gets
SIGTERM, and exits with the exit code of the last agent process. The record
holds numbers, codes and paths only, never prompt or answer text.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..limits import read_budget
from ..programs import program_environment
from .session import (
    blank_reply,
    blank_session_file,
    extract_findings_document,
    final_text,
    find_session,
    has_tool_call,
    read_session,
)

AGENT_PROTOCOL = "agent-v2.4"
AGENT_TOOLS = ("read", "grep", "find", "ls")
# The runner starts the audit again at most this many times, each time in a
# new session, when the first reply of the session is blank: no text and no
# tool call. Some provider endpoints send such a reply to the audit prompt.
BLANK_RESTARTS = 2
BLANK_RESTART_REASON = "blank-first-reply"
# Share of the token budget that the first turn may not use.
RESERVE_FRACTION = 0.25
# Every turn stops at this share of the token budget and of the wall clock,
# before the gateway refuses calls or the caller stops the run.
LIMIT_FRACTION = 0.95
RUNNER_RECORD = "runner.json"
POLL_SECONDS = 2.0
# The runner reads the money of the run at most this often.
BUDGET_POLL_SECONDS = 4.0
BUDGET_STOP = "budget"
STOP_GRACE_SECONDS = 30.0
# The runner did not start the agent (EX_SOFTWARE), or it got SIGTERM.
EXIT_REFUSED = 70
EXIT_TERMINATED = 143
PRIVATE_TMP = "pi-tmp"
RECORD_SCHEMA_VERSION = 1


class Terminated(Exception):  # noqa: N818 - a signal, not an error
    """The runner got SIGTERM: the caller stopped the run."""


def _on_sigterm(_signum: int, _frame: object) -> None:
    raise Terminated()


class SessionTokens:
    """Sum the token usage that the agent records for each reply, reading only new lines."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path: Path | None = None
        self.offset = 0
        self.pending = b""
        self.total = 0

    def poll(self) -> int:
        if self.path is None:
            sessions = sorted(self.directory.glob("*.jsonl")) if self.directory.is_dir() else []
            if not sessions:
                return self.total
            self.path = sessions[0]
        try:
            with self.path.open("rb") as stream:
                stream.seek(self.offset)
                chunk = stream.read()
        except OSError:
            return self.total
        self.offset += len(chunk)
        *lines, self.pending = (self.pending + chunk).split(b"\n")
        for line in lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = entry.get("message") if isinstance(entry, dict) and entry.get("type") == "message" else None
            if isinstance(message, dict) and message.get("role") == "assistant":
                self.total += int((message.get("usage") or {}).get("totalTokens") or 0)
        return self.total

    def resync(self) -> None:
        """Continue after the current end of the file. Call it after a repair.

        A repair completes the cut last line or removes it. A completed line
        is counted. The agent then appends at the new end of the file, before
        the old offset, so reading must continue from that end.
        """
        self.poll()
        if self.path is not None:
            try:
                self.offset = self.path.stat().st_size
            except OSError:
                pass
        self.pending = b""

    def next_session(self) -> None:
        """Keep the total and count the next session file from its start.

        Call it after the agent ended and the runner moved the counted
        session file out of the folder. The agent then writes a new session
        file there.
        """
        self.path = None
        self.offset = 0
        self.pending = b""


def stop_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


class MoneyStop:
    """Whether the gateway of the run says that new work must stop (``GET /budget``), read at most every few seconds."""

    def __init__(self, url: str | None) -> None:
        self.url = url
        self.read_at = float("-inf")
        self.stopped = False

    def __call__(self) -> bool:
        if self.url is None or self.stopped:
            return self.stopped
        now = time.monotonic()
        if now - self.read_at >= BUDGET_POLL_SECONDS:
            self.read_at = now
            state = read_budget(self.url)
            self.stopped = bool(state and state.get("stop"))
        return self.stopped


def run_turn(
    argv: list[str],
    tokens: SessionTokens,
    *,
    token_stops: list[tuple[int, str]],
    time_stop: tuple[float, str] | None,
    started: float,
    environment: dict[str, str] | None = None,
    money_stop: MoneyStop | None = None,
) -> tuple[int, str | None]:
    """Run one agent turn and stop it at the first limit that it reaches.

    ``token_stops`` holds (token count, reason) pairs. ``time_stop`` is
    (seconds since the runner started, reason). ``money_stop`` stops the
    turn when the gateway says that new work must stop (reason ``budget``).
    Returns the exit code and the stop reason, or None when the agent ended
    by itself.
    """
    process = subprocess.Popen(argv, env=environment)
    try:
        while True:
            try:
                code = process.wait(timeout=POLL_SECONDS)
                tokens.poll()
                return code, None
            except subprocess.TimeoutExpired:
                pass
            count = tokens.poll()
            reason = next((why for limit, why in sorted(token_stops) if count >= limit), None)
            if reason is None and time_stop is not None and time.monotonic() - started >= time_stop[0]:
                reason = time_stop[1]
            if reason is None and money_stop is not None and money_stop():
                reason = BUDGET_STOP
            if reason is not None:
                stop_process(process)
                tokens.poll()
                return process.returncode, reason
    except BaseException:
        stop_process(process)
        raise


def repair_session(session: Path) -> bool:
    """Complete or drop a last line that a stop cut; the agent cannot resume over it."""
    data = session.read_bytes()
    if not data or data.endswith(b"\n"):
        return False
    cut = data.rfind(b"\n") + 1
    try:
        json.loads(data[cut:])
    except json.JSONDecodeError:
        with session.open("r+b") as stream:
            stream.truncate(cut)
        return True
    with session.open("ab") as stream:
        stream.write(b"\n")
    return True


def needs_final_turn(session_directory: Path) -> tuple[bool, Path | None]:
    """Whether the session ended normally without a findings JSON object."""
    try:
        session = find_session(session_directory)
        _, messages, _ = read_session(session)
    except (OSError, ValueError):
        return False, None
    assistant = [message for message in messages if message.get("role") == "assistant"]
    if not assistant or assistant[-1].get("stopReason") not in {"stop", "length"}:
        return False, session
    try:
        extract_findings_document(final_text(assistant[-1]))
    except ValueError:
        return True, session
    return False, session


def blank_first_reply(session_directory: Path) -> tuple[Path, dict[str, Any]] | None:
    """The session and its last reply when the session has a blank first reply.

    The session file must be complete, no reply in it may have a tool call,
    and its last reply must be blank (``blank_reply``). When a request fails,
    the agent keeps the failed reply in the session and sends the request
    again. Thus the last reply is the one that ended the turn. None
    otherwise, also when there is no single session file.
    """
    try:
        session = find_session(session_directory)
        _, messages, truncated = read_session(session)
    except (OSError, ValueError):
        return None
    assistant = [message for message in messages if message.get("role") == "assistant"]
    if truncated or not assistant or any(has_tool_call(message) for message in assistant):
        return None
    return (session, assistant[-1]) if blank_reply(assistant[-1]) else None


def replace_blank_session(session_directory: Path, session: Path, reply: dict[str, Any], attempt: int) -> dict[str, Any]:
    """Move a blank session next to the session folder; return its record.

    The agent then starts the new session in an empty session folder, as at
    the first attempt.
    """
    kept = blank_session_file(attempt)
    target = session_directory.parent / kept
    target.parent.mkdir(parents=True, exist_ok=True)
    os.replace(session, target)
    usage = found if isinstance(found := reply.get("usage"), dict) else {}
    content = given if isinstance(given := reply.get("content"), list) else []
    return {
        "attempt": attempt,
        "file": kept.as_posix(),
        "agent_session": session.name,
        "stop_reason": reply.get("stopReason"),
        "content_types": sorted({str(block.get("type")) for block in content if isinstance(block, dict)}),
        "output_tokens": usage.get("output"),
        "total_tokens": usage.get("totalTokens"),
    }


def final_turn_argv(pi_argv: list[str], session: Path, message: str) -> list[str]:
    """The first agent command, resumed on ``session``, with ``message`` as the prompt."""
    if "--session-dir" not in pi_argv[:-1]:
        raise ValueError("the agent command has no --session-dir")
    index = pi_argv.index("--session-dir")
    return [*pi_argv[:index], "--session", str(session), *pi_argv[index + 2 : -1], message]


def write_record(path: Path, record: dict[str, Any]) -> None:
    """Replace the record in one step, so a reader never sees a partial file."""
    staging = path.with_name(f".{path.name}.tmp")
    staging.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(staging, path)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentrytower-agent", description="Run one agent session with a budget.")
    parser.add_argument("--session-dir", type=Path, required=True)
    parser.add_argument("--final-message", required=True)
    parser.add_argument("--token-budget", type=int, help="the token budget of the session")
    parser.add_argument("--wall-clock-seconds", type=float, help="the wall clock of the session")
    parser.add_argument("--reserve-fraction", type=float, default=RESERVE_FRACTION)
    parser.add_argument("--limit-fraction", type=float, default=LIMIT_FRACTION)
    parser.add_argument("--budget-url", help="the model gateway of the run: stop the first turn when the money says so")
    parser.add_argument("pi_argv", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    args = parser.parse_args(argv)
    pi_argv = args.pi_argv[1:] if args.pi_argv[:1] == ["--"] else args.pi_argv
    if len(pi_argv) < 2:
        parser.error("give the agent command and the prompt after --")
    if not 0 <= args.reserve_fraction < 1 or not 0 < args.limit_fraction <= 1:
        parser.error("--reserve-fraction must be in [0, 1) and --limit-fraction in (0, 1]")
    started = time.monotonic()
    budget = args.token_budget or None
    clock = args.wall_clock_seconds or None
    reserve_tokens = int(budget * (1 - args.reserve_fraction)) if budget else None
    limit_tokens = int(budget * args.limit_fraction) if budget else None
    limit_seconds = clock * args.limit_fraction if clock else None
    session_directory: Path = args.session_dir
    session_directory.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "protocol": AGENT_PROTOCOL,
        "limits": {
            "token_budget": budget,
            "wall_clock_seconds": clock,
            "reserve_tokens": reserve_tokens,
            "limit_tokens": limit_tokens,
            "limit_seconds": limit_seconds,
        },
        "turns": [],
        # The last first-turn attempt that started: first, restart-1, or
        # restart-2. Its session gives the answer, after the final turn if
        # one follows. None means that the agent did not start.
        "audit_turn": None,
        # The new sessions after a blank first reply. "skipped" gives the
        # reason when the runner did not start a new session after a blank
        # first reply: restart-limit, token-limit, time-limit, or token-reserve.
        "blank_restarts": {"count": 0, "reason": None, "skipped": None, "sessions": []},
        "stopped": None,
        "final_turn": None,
        "final_stopped": None,
        "final_skipped": None,
        "session_repaired": False,
        "terminated": None,
        "error": None,
        "exit": None,
    }
    tokens = SessionTokens(session_directory)
    token_limit = [(limit_tokens, "token-limit")] if limit_tokens is not None else []
    time_limit = (limit_seconds, "time-limit") if limit_seconds is not None else None
    money_stop = MoneyStop(args.budget_url) if args.budget_url else None
    code = EXIT_REFUSED
    previous = signal.signal(signal.SIGTERM, _on_sigterm)
    try:
        # The agent runs in the audited repository: its PATH keeps the absolute entries only.
        environment = program_environment(os.environ)
        private_tmp = session_directory.parent / PRIVATE_TMP
        private_tmp.mkdir(parents=True, exist_ok=True)
        # The agent keeps the cache of its extension loader here.
        environment["TMPDIR"] = str(private_tmp)

        def turn(name: str, command: list[str], stops: list[tuple[int, str]], money: MoneyStop | None = None) -> tuple[int, str | None]:
            exit_code, stopped = run_turn(
                command, tokens, token_stops=stops, time_stop=time_limit, started=started, environment=environment, money_stop=money
            )
            record["turns"].append(
                {
                    "turn": name,
                    "exit": exit_code,
                    "stopped": stopped,
                    "tokens_at_end": tokens.total,
                    "seconds_at_end": round(time.monotonic() - started, 1),
                }
            )
            return exit_code, stopped

        first_stops = [*token_limit]
        if reserve_tokens is not None:
            first_stops.append((reserve_tokens, "token-reserve"))
        record["audit_turn"] = "first"
        code, stopped = turn("first", pi_argv, first_stops, money_stop)
        restarts = record["blank_restarts"]
        while stopped is None and code == 0:
            blank = blank_first_reply(session_directory)
            if blank is None:
                break
            restarts["reason"] = BLANK_RESTART_REASON
            if restarts["count"] >= BLANK_RESTARTS:
                restarts["skipped"] = "restart-limit"
            elif limit_tokens is not None and tokens.poll() >= limit_tokens:
                restarts["skipped"] = "token-limit"
            elif limit_seconds is not None and time.monotonic() - started >= limit_seconds:
                restarts["skipped"] = "time-limit"
            elif reserve_tokens is not None and tokens.poll() >= reserve_tokens:
                restarts["skipped"] = "token-reserve"
            elif money_stop is not None and money_stop():
                restarts["skipped"] = BUDGET_STOP
            if restarts["skipped"] is not None:
                break
            attempt = restarts["count"] + 1
            # Count the restart before the move. Then a SIGTERM between the
            # two steps cannot leave a moved session that the count omits.
            restarts["count"] = attempt
            restarts["sessions"].append(replace_blank_session(session_directory, *blank, attempt))
            tokens.next_session()
            record["audit_turn"] = f"restart-{attempt}"
            print(f"agent: blank first reply, restart {attempt}", file=sys.stderr, flush=True)
            code, stopped = turn(f"restart-{attempt}", pi_argv, first_stops, money_stop)
        record["stopped"] = stopped
        session: Path | None = None
        if stopped in ("token-reserve", BUDGET_STOP):
            try:
                session = find_session(session_directory)
                record["final_turn"] = stopped
            except (OSError, ValueError):
                session = None
        elif stopped is None and code == 0:
            missing, found = needs_final_turn(session_directory)
            if missing and found is not None:
                session = found
                record["final_turn"] = "no-answer"
        if session is not None:
            if limit_tokens is not None and tokens.poll() >= limit_tokens:
                record["final_skipped"] = "token-limit"
            elif limit_seconds is not None and time.monotonic() - started >= limit_seconds:
                record["final_skipped"] = "time-limit"
            else:
                record["session_repaired"] = repair_session(session)
                if record["session_repaired"]:
                    # The repair moved the end of the file under the count.
                    tokens.resync()
                print(f"agent: final turn ({record['final_turn']})", file=sys.stderr, flush=True)
                code, record["final_stopped"] = turn("final", final_turn_argv(pi_argv, session, args.final_message), token_limit)
    except OSError as problem:
        record["error"] = f"{type(problem).__name__}: {problem.strerror or problem}"[:300]
        print(f"agent: the agent cannot start: {type(problem).__name__}", file=sys.stderr, flush=True)
        code = EXIT_REFUSED
    except Terminated:
        record["terminated"] = "SIGTERM"
        code = EXIT_TERMINATED
    finally:
        signal.signal(signal.SIGTERM, previous)
        record["exit"] = code
        record["tokens_at_end"] = tokens.poll()
        record["seconds_at_end"] = round(time.monotonic() - started, 1)
        write_record(session_directory / RUNNER_RECORD, record)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
