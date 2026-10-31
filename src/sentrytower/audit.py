"""One audit: count the files, route the repository, run the engine behind the model gateway, write the outputs.

The parent process (this module) holds the provider key and the gateway.
The engines run as child processes with a scrubbed environment: they get
the URL of the loopback gateway and a random credential of the run, never
the provider key or another secret of the environment. On Linux the parent
is not dumpable, so that another process of the same user cannot read its
memory or its environment. The tools of each agent session reach only the
repository (the repository guard of ``agent.pi``).

- Funnel route (1,000 files or fewer): ``python -m sentrytower.funnel`` with
  a spec file; the funnel starts the free-roaming agent session, the
  inventory and the deep-check sessions itself.
- Agent route (more than 1,000 files): the agent runner with the audit
  prompt, the whole token ceiling and the whole wall clock.

The token ceiling of the run comes from the cost cap and the prices of the
models of the route, or from ``max_tokens`` (``Config.token_plan``).

The parent enforces the wall clock of the run: at the limit it sends
SIGTERM to the process group of the engine, then SIGKILL after a grace. It
does the same when the provider refuses the key, the account or the route
(HTTP 401, 402, 403 or 404): no later model call can succeed.

Each run gets one result (``result.py``; ``run.json`` ``result``): the
status, why the run stopped, the spend, the checked units and the model
calls. The status is ``failed`` after a provider refusal or when the output
of the engine cannot be read, ``incomplete`` after an engine crash, an
answer that is missing, more than 20% of failed model calls (or each call
failed), or a funnel that did not do its work (its inventory failed, it
checked no code unit or more than 20% of its unit checks failed, or more
than half of its agent sessions gave no answer), and ``interrupted`` after
SIGINT or SIGTERM. Each output states the result with the same sentences.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from typing import Any, Callable, Mapping

from . import __version__
from .agent import pi
from .agent.answer import read_findings
from .agent.deep import RECORD_FILE as DEEP_RECORD
from .agent.deep import SPEC_SCHEMA as DEEP_SPEC_SCHEMA
from .agent.runner import RUNNER_RECORD
from .agent.session import find_session, read_answer, read_session
from .budget import (
    SOFT_STOP_FRACTION,
    SOURCE_COST_CAP,
    SOURCE_STANDARD,
    STANDARD_TOKENS,
    VERIFY_VOTES,
    funnel_parameters,
    parallel_sessions,
)
from .config import AGENT_ROLE, Config, ConfigError
from .findings import (
    ENGINE_AGENT,
    ENGINE_FREE,
    OutputFinding,
    findings_document,
    from_agent,
    from_funnel_item,
    severity_counts,
)
from .funnel.orchestrator import SPEC_SCHEMA
from .funnel.resolve import FREE_SOURCE
from .gateway import DEFAULT_PARALLEL_REQUESTS, GatewayConfig, ModelGateway, Transport, proxy_problem
from .html_report import html_report
from .limits import CREDENTIAL_VARIABLE
from .programs import program_environment
from .report import markdown_report
from .result import (
    PREVIEW_LABEL,
    STATUS_COMPLETE,
    STATUS_FAILED,
    STATUS_INCOMPLETE,
    STATUS_INTERRUPTED,
    STOP_BUDGET,
    STOP_DONE,
    STOP_ENGINE,
    STOP_INTERRUPTED,
    STOP_PROVIDER,
    STOP_TOKENS,
    STOP_WALL_CLOCK,
    UNITS_AGENT,
    UNITS_FUNNEL,
    calls_record,
    failed_calls_failure,
    phase0_failure,
    provider_failure,
    result_lines,
    sessions_failure,
    stop_text,
    units_failure,
)
from .router import ROUTE_FUNNEL, RouteDecision, decide
from .sarif import DEFAULT_CATEGORY, sarif_document
from .ui.term import printable

RUN_SCHEMA_VERSION = "1.0.0"
FORMATS = ("json", "sarif", "markdown", "html")
OUTPUT_FILES = {"json": "findings.json", "sarif": "findings.sarif", "markdown": "report.md", "html": "report.html"}
RUN_FILE = "run.json"
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_RUN_FAILED = 4
EXIT_INTERRUPTED = 130
# The grace between SIGTERM and SIGKILL when the wall clock of the run ends, and after an interrupt.
STOP_GRACE_SECONDS = 15.0
INTERRUPT_GRACE_SECONDS = 5.0
POLL_SECONDS = 0.5
# The poll of a live terminal view: often enough for a smooth spinner.
LIVE_POLL_SECONDS = 0.1
PROGRESS_SECONDS = 60.0
# Variables that never reach an engine: secrets and proxies (the engines talk to the loopback gateway only).
_SECRET_NAME = re.compile(r"(?i)(api[_-]?key|token|secret|passw|credential|private[_-]?key|session[_-]?key|auth|cookie|webhook|dsn)")
_DROPPED = re.compile(r"(?i)^(https?_proxy|all_proxy|ftp_proxy|no_proxy|aws_.*|azure_.*|google_.*|gcp_.*|sentrytower_.*)$")
# A URL with a user part (``scheme://user:password@host``) holds a credential.
_URL_CREDENTIALS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/@\s]+@")
# A key of at least this length is also looked for inside the values of other variables.
_KEY_IN_VALUE_LENGTH = 16
# Random names for the staging file of an output file before a write gives up.
STAGING_ATTEMPTS = 100
# The run state below the state folder; in the container image the state folder is the home folder.
AGENT_FOLDER = Path(".local/share/pi-agent")
SESSION_FOLDER = Path(".local/share/pi-sessions")
WORK_FOLDER = Path(".local/state/review")
CONTROL_FOLDER = Path(".local/state/sentrytower")


class AuditError(RuntimeError):
    """An audit cannot run or did not finish. ``exit_code`` is the code of the command line."""

    def __init__(self, message: str, exit_code: int = EXIT_RUN_FAILED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class Log:
    """Progress lines on stderr: none with ``quiet``, more with ``verbose``. Never a secret or code.

    The hooks ``route_known``, ``engine_started``, ``tick`` and ``interrupted``
    do nothing here; the live view of a terminal (``ui.live.LiveAudit``) uses
    them. ``live`` asks ``_run_engine`` for frequent ticks.
    """

    live = False

    def __init__(self, *, quiet: bool = False, verbose: bool = False, stream: Any = None) -> None:
        self.quiet = quiet
        self.verbose = verbose
        self.stream = stream or sys.stderr
        self.started = time.monotonic()

    def _write(self, text: str) -> None:
        elapsed = time.monotonic() - self.started
        # A message can name a file of the audited repository: no control character of it reaches the terminal.
        self.stream.write(f"[{int(elapsed // 60):02d}:{int(elapsed % 60):02d}] {printable(text)}\n")
        self.stream.flush()

    def info(self, text: str) -> None:
        if not self.quiet:
            self._write(text)

    def debug(self, text: str) -> None:
        if self.verbose and not self.quiet:
            self._write(text)

    def warn(self, text: str) -> None:
        self._write(f"warning: {text}")

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
        """The route and the models are known. The plain log printed them already."""
        return None

    def engine_started(self, *, route: str, work: Path, sessions: Path, snapshot: Callable[[], dict[str, Any]]) -> None:
        """The engine runs. ``snapshot`` returns the token, cost and finding counts of the run so far."""
        return None

    def tick(self) -> None:
        return None

    def interrupted(self) -> None:
        return None


@dataclass
class AuditRequest:
    repository: Path
    out_dir: Path
    formats: tuple[str, ...] = FORMATS
    keep_state: bool = False
    state_dir: Path | None = None
    # The code-scanning category of findings.sarif, and a folder in front of each SARIF path (an audit of a
    # subfolder: code scanning reads a path from the root of the repository).
    sarif_category: str = DEFAULT_CATEGORY
    sarif_path_prefix: str = ""


@dataclass
class AuditOutcome:
    findings: list[OutputFinding]
    run: dict[str, Any]
    files: dict[str, Path] = field(default_factory=dict)
    exit_code: int = EXIT_OK


@dataclass(frozen=True)
class RunLayout:
    """The folders of the run state."""

    root: Path
    owned: bool

    @property
    def agent(self) -> Path:
        return self.root / AGENT_FOLDER

    @property
    def sessions(self) -> Path:
        return self.root / SESSION_FOLDER

    @property
    def work(self) -> Path:
        return self.root / WORK_FOLDER

    @property
    def control(self) -> Path:
        return self.root / CONTROL_FOLDER

    @classmethod
    def create(cls, state_dir: Path | None, repository: Path | None = None) -> RunLayout:
        """The run state in a new private temporary folder, or below ``state_dir``.

        A given state folder must belong to this user or to root (a system
        folder such as a container volume). The folders that the run creates
        below it are private (mode 0700), and each folder between the state
        folder and the run state must belong to this user: the run state
        holds code and the credential of the run. No folder on the path of
        the state folder in ``repository`` (the audited repository) may be a
        symbolic link (exit 2), as for the output folder.
        """
        if state_dir is None:
            layout = cls(Path(tempfile.mkdtemp(prefix="sentrytower-")), owned=True)
        else:
            root = state_dir.expanduser().absolute()
            if repository is not None and (link := _link_in_repository(root, repository)) is not None:
                raise AuditError(
                    f"the state folder {root} goes through the symbolic link {link} in the audited repository: "
                    "remove the link, or choose a state folder outside the repository",
                    EXIT_USAGE,
                )
            try:
                root.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as error:
                raise AuditError(f"the state folder {root} cannot be created: {type(error).__name__}", EXIT_ENVIRONMENT) from None
            root = root.resolve()
            _check_private_folder(root, root_owner=True)
            layout = cls(root, owned=False)
            for folder in (layout.agent, layout.sessions, layout.work, layout.control):
                if folder.exists():
                    raise AuditError(f"the state folder {root} holds the state of another run ({folder.relative_to(root)})", EXIT_USAGE)
        for folder in (layout.agent.parent, layout.work.parent, layout.control):
            layout._make(folder)
        return layout

    def _make(self, folder: Path) -> None:
        current = self.root
        for part in folder.relative_to(self.root).parts:
            current = current / part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as error:
                raise AuditError(f"the state folder {current} cannot be created: {type(error).__name__}", EXIT_ENVIRONMENT) from None
            _check_private_folder(current)

    def remove(self) -> None:
        if self.owned:
            shutil.rmtree(self.root, ignore_errors=True)
        else:
            for folder in (self.agent, self.sessions, self.work, self.control):
                shutil.rmtree(folder, ignore_errors=True)


def _check_private_folder(path: Path, *, root_owner: bool = False) -> None:
    """A folder of the run state must be a folder (not a link) of this user (or of root, with ``root_owner``)."""
    try:
        info = path.lstat()
    except OSError as error:
        raise AuditError(f"the state folder {path} cannot be read: {type(error).__name__}", EXIT_ENVIRONMENT) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AuditError(f"the state folder {path} is not a folder", EXIT_USAGE)
    if hasattr(os, "getuid") and info.st_uid != os.getuid() and not (root_owner and info.st_uid == 0):
        raise AuditError(f"the state folder {path} belongs to another user", EXIT_USAGE)


def engine_environment(
    base: Mapping[str, str],
    *,
    secret_names: tuple[str, ...] = (),
    secret_values: tuple[str, ...] = (),
    repository: Path | None = None,
) -> dict[str, str]:
    """The environment of an engine: the parent environment without secrets and proxies.

    A variable is left out when its name looks like a secret, when it is a
    proxy or cloud variable, when ``secret_names`` names it (the key
    variables of the provider), when its value is a URL with a user part, or
    when its value holds one of ``secret_values`` (the provider key).
    ``PYTHONSAFEPATH`` is set: the engines run in the audited repository,
    and Python must not import a module from it. For the same reason PATH
    keeps only its absolute entries outside ``repository``
    (``programs.search_path``): no program of the repository runs in place
    of node, rg or fd.
    """
    secrets = [value for value in secret_values if value]

    def secret(name: str, value: str) -> bool:
        if _SECRET_NAME.search(name) or _DROPPED.match(name) or name in secret_names or _URL_CREDENTIALS.search(value):
            return True
        return any(value.strip() == item or (len(item) >= _KEY_IN_VALUE_LENGTH and item in value) for item in secrets)

    environment = {name: value for name, value in base.items() if not secret(name, value)}
    environment["NO_PROXY"] = environment["no_proxy"] = "127.0.0.1,localhost"
    # Each Python process of an engine runs in the audited repository: no module of it goes on sys.path.
    environment["PYTHONSAFEPATH"] = "1"
    return program_environment(environment, outside=(repository,) if repository is not None else ())


def protect_parent_process() -> bool:
    """On Linux, make this process not dumpable (``PR_SET_DUMPABLE`` 0).

    Another process of the same user, such as an agent session, then cannot
    read the memory or the environment (``/proc/<pid>/environ``) of the
    parent, which hold the provider key. A child gets the default again when
    it starts a program. Returns True when the flag is set.
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return int(libc.prctl(4, 0, 0, 0, 0)) == 0  # PR_SET_DUMPABLE = 4
    except (OSError, AttributeError, ValueError):
        return False


def _inside(path: Path, folder: Path) -> bool:
    return path == folder or folder in path.parents


def _link_in_repository(folder: Path, repository: Path) -> Path | None:
    """The first symbolic link on the path of ``folder`` that is in ``repository`` (a resolved path), or None.

    A link outside the repository (for example /tmp on macOS) belongs to the
    user: the parts after it are checked in the folder that it names.
    """
    current = Path(folder.anchor)
    for part in folder.parts[1:]:
        if part == "..":
            current = current.parent
            continue
        candidate = current / part
        try:
            info = candidate.lstat()
        except OSError:
            # The rest of the path does not exist yet (the run creates it), or the write fails later.
            return None
        if not stat.S_ISLNK(info.st_mode):
            current = candidate
        elif _inside(candidate, repository):
            return candidate
        else:
            current = Path(os.path.realpath(candidate))
    return None


def _open_out_dir(out_dir: Path, repository: Path | None) -> int:
    """A descriptor of the output folder after its checks; a missing folder is created.

    The output folder is often in the audited repository (``sentrytower audit
    .`` writes ./sentrytower-results), and the repository decides what its
    folders hold. Thus the output folder must not be a symbolic link, no
    folder on its path in ``repository`` may be a link, and it must belong
    to this user. Each of these refusals is a usage error (exit 2).
    """
    folder = out_dir.expanduser().absolute()
    if repository is not None and (link := _link_in_repository(folder, repository)) is not None:
        raise AuditError(
            f"the output folder {out_dir} goes through the symbolic link {link} in the audited repository: "
            "remove the link, or choose an output folder outside the repository",
            EXIT_USAGE,
        )
    try:
        if not os.path.lexists(folder):
            folder.mkdir(parents=True, exist_ok=True)
        info = folder.lstat()
    except OSError as error:
        raise AuditError(f"the output folder {out_dir} cannot be written: {type(error).__name__}", EXIT_ENVIRONMENT) from None
    if stat.S_ISLNK(info.st_mode):
        raise AuditError(
            f"the output folder {out_dir} is a symbolic link: give the folder that it points to, or another folder", EXIT_USAGE
        )
    if not stat.S_ISDIR(info.st_mode):
        raise AuditError(f"the output folder {out_dir} is not a folder", EXIT_ENVIRONMENT)
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise AuditError(
            f"the output folder {out_dir} belongs to another user: choose a folder of your own "
            '(with docker run, add --user "$(id -u):$(id -g)")',
            EXIT_USAGE,
        )
    try:
        descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise AuditError(f"the output folder {out_dir} cannot be written: {type(error).__name__}", EXIT_ENVIRONMENT) from None
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
        os.close(descriptor)
        raise AuditError(f"the output folder {out_dir} changed during its checks", EXIT_USAGE)
    return descriptor


def _staging_file(folder: int, name: str) -> tuple[str, int]:
    """A new private file for ``name`` in the folder ``folder`` (a descriptor): its name and a descriptor.

    O_CREAT | O_EXCL | O_NOFOLLOW, mode 0600 and a random name: a file or a
    link that is already at the name is never opened, and the next name is
    tried.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for _ in range(STAGING_ATTEMPTS):
        staging = f".{name}.{token_hex(6)}.tmp"
        try:
            return staging, os.open(staging, flags, 0o600, dir_fd=folder)
        except FileExistsError:
            continue
    raise FileExistsError(f"no free staging name for {name}")


def _write_file(folder: int, name: str, data: bytes, mode: int) -> None:
    """Write ``data`` to ``name`` in the folder ``folder`` (a descriptor) in one rename.

    The data goes to a new staging file (``_staging_file``) and is synced;
    the file gets ``mode``; os.replace moves it to ``name``. The rename
    replaces a link at ``name`` and never follows it, and it fails
    (IsADirectoryError) when a folder has the name.
    """
    staging, descriptor = _staging_file(folder, name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(staging, name, src_dir_fd=folder, dst_dir_fd=folder)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staging, dir_fd=folder)
        raise


def _file_mode() -> int:
    """The mode of a new file of this process: 0o666 without the bits of the umask."""
    # A stricter mask for a moment: a file that another thread creates meanwhile gets fewer rights, never more.
    mask = os.umask(0o077)
    os.umask(mask)
    return 0o666 & ~mask


def _probe_out_dir(out_dir: Path, repository: Path | None = None) -> None:
    """Check the output folder and that the run can write it, before the run spends tokens.

    The checks of ``_open_out_dir``; then each name of an output file in the
    folder must be free or hold a regular file. A link or a folder at such a
    name is refused (exit 2).
    """
    folder = _open_out_dir(out_dir, repository)
    try:
        for name in (*OUTPUT_FILES.values(), RUN_FILE):
            try:
                info = os.stat(name, dir_fd=folder, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise AuditError(f"the output folder {out_dir} cannot be read: {type(error).__name__}", EXIT_ENVIRONMENT) from None
            if not stat.S_ISREG(info.st_mode):
                kind = "a symbolic link" if stat.S_ISLNK(info.st_mode) else "not a file"
                raise AuditError(f"{name} in the output folder {out_dir} is {kind}: remove it, or choose another output folder", EXIT_USAGE)
        try:
            staging, descriptor = _staging_file(folder, "sentrytower-probe")
            os.close(descriptor)
            os.unlink(staging, dir_fd=folder)
        except OSError as error:
            raise AuditError(f"the output folder {out_dir} cannot be written: {type(error).__name__}", EXIT_ENVIRONMENT) from None
    finally:
        os.close(folder)


def now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_engine(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    logs: Path,
    wall_clock_seconds: int,
    log: Log,
    progress: Callable[[], str | None],
    should_stop: Callable[[], str | None] = lambda: None,
) -> tuple[int | None, str | None]:
    """Run the engine in its own process group within the wall clock; return its exit code and the stop.

    The stop is None when the engine ended by itself, ``wall-clock`` at the
    wall clock of the run, ``interrupted`` after SIGINT or SIGTERM, or the
    reason that ``should_stop`` gives (``provider-error``: the provider
    refused the key, the account or the route, so no model call can succeed).
    """
    logs.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    stopped: str | None = None
    with (logs / "engine.stdout.log").open("ab") as stdout, (logs / "engine.stderr.log").open("ab") as stderr:
        process = subprocess.Popen(
            argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True
        )
        last_progress = started
        try:
            while process.poll() is None:
                time.sleep(LIVE_POLL_SECONDS if log.live else POLL_SECONDS)
                log.tick()
                now = time.monotonic()
                if now - last_progress >= PROGRESS_SECONDS:
                    last_progress = now
                    line = progress()
                    if line:
                        log.info(line)
                if now - started >= wall_clock_seconds:
                    stopped = "wall-clock"
                    log.warn("the wall clock of the run ended: stopping the engine")
                    _stop_group(process)
                    break
                reason = should_stop()
                if reason is not None:
                    stopped = reason
                    log.warn("the provider refused a model call: stopping the engine")
                    _stop_group(process)
                    break
        except KeyboardInterrupt:
            stopped = "interrupted"
            _stop_group(process, grace=INTERRUPT_GRACE_SECONDS)
            raise
        finally:
            if process.poll() is None:
                _stop_group(process)
    return process.returncode, stopped


def _stop_group(process: subprocess.Popen[bytes], *, grace: float = STOP_GRACE_SECONDS) -> None:
    for number, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 10.0)):
        try:
            os.killpg(process.pid, number)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _session_findings(session_dir: Path, roots: tuple[str, ...]) -> tuple[list[Any], dict[str, Any]]:
    """The findings of the answer of one agent session, and the state of the session."""
    document, error = read_answer(session_dir)
    state: dict[str, Any] = {"answer": document is not None, "error": error}
    if document is None:
        return [], state
    cwd = None
    try:
        header, _, _ = read_session(find_session(session_dir))
        cwd = header.get("cwd") if isinstance(header.get("cwd"), str) else None
    except (OSError, ValueError):
        pass
    findings, dropped = read_findings(document, cwd=cwd, roots=roots)
    state.update(items=len(document.get("findings") or []), dropped=len(dropped))
    return findings, state


_FREE_ID = re.compile(r"^R(?P<index>[0-9]{1,9})$")


def funnel_output(work: Path, sessions: Path, roots: tuple[str, ...]) -> tuple[list[OutputFinding], dict[str, Any]]:
    """The output of a funnel run in the rank order of its findings file.

    A free-roaming item is the finding of the free-roaming answer at the
    same place (``R<n>`` is item n of the answer); a deep-check item is read
    from the findings file (its first location is the resolved line).
    """
    document = _read_json(work / "findings.json")
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise AuditError("the funnel wrote no findings file")
    free, free_state = _session_findings(sessions, roots)
    by_index = {finding.index: finding for finding in free}
    output: list[OutputFinding] = []
    for item in document["findings"]:
        if not isinstance(item, dict):
            continue
        record = found if isinstance(found := item.get("funnel"), dict) else {}
        rank = len(output) + 1
        if record.get("source") == FREE_SOURCE:
            match = _FREE_ID.match(str(record.get("id") or ""))
            found = by_index.get(int(match.group("index")) - 1) if match else None
            if found is None:
                continue
            output.append(from_agent(found, rank=rank, route=ROUTE_FUNNEL, engine=ENGINE_FREE))
        else:
            output.append(from_funnel_item(item, rank=rank, route=ROUTE_FUNNEL, roots=roots))
        # Tier 1: the output of the standard rule; tier 2: the extra slots of a deeper run (resolve.select_output).
        output[-1].tier = 2 if record.get("output_tier") == 2 else 1
    return output, {"final": document.get("final"), "free_session": free_state}


# The statuses of a slice finding in the deep record that the output keeps: verified, or not verified yet.
SLICE_KEPT = "kept"
SLICE_UNVERIFIED = ("waiting", "verifying", "unverified")
SLICE_NOT_VERIFIED = "the run stopped before its verification"


def slice_findings(record: dict[str, Any], roots: tuple[str, ...], route: str, *, first_rank: int) -> list[OutputFinding]:
    """The findings of the slices that the deep engine kept: the verified ones by score, then the unverified ones.

    A finding without a verification (the run stopped first, the budget
    refused it, the call failed) stays, with the label ``unverified`` and
    its reason. A finding that the votes call safe, a duplicate and a
    finding without a location do not.
    """
    entries = [entry for entry in record.get("findings") or [] if isinstance(entry, dict)]
    kept = sorted(
        (entry for entry in entries if entry.get("status") == SLICE_KEPT), key=lambda entry: -float(entry.get("keep_score") or 0.0)
    )
    unverified = [entry for entry in entries if entry.get("status") in SLICE_UNVERIFIED]
    answers: dict[str, dict[int, Any]] = {}
    output: list[OutputFinding] = []
    for entry in [*kept, *unverified]:
        folder = str(entry.get("session_dir") or "")
        if folder not in answers:
            found, _ = _session_findings(Path(folder), roots)
            answers[folder] = {item.index: item for item in found}
        item = answers[folder].get(int(entry.get("index", -1)))
        if item is None:
            continue
        finding = from_agent(item, rank=first_rank + len(output), route=route, engine=ENGINE_AGENT)
        # Tier 2: the whole-repository session is the standard run; the slices are the further work.
        finding.tier = 2
        if entry.get("status") == SLICE_KEPT:
            score = entry.get("keep_score")
            finding.confidence = float(score) if isinstance(score, (int, float)) else None
            finding.verification = {"verdict": entry.get("verdict"), "keep_score": finding.confidence, "votes": entry.get("votes")}
            finding.verification_status = "verified"
        else:
            finding.verification_status = "unverified"
            finding.verification_reason = str(entry.get("reason") or SLICE_NOT_VERIFIED)
        output.append(finding)
    return output


def deep_summary(record: dict[str, Any]) -> dict[str, Any]:
    """The slices of a deep run of the agent route for run.json: counts only."""
    statuses: dict[str, int] = {}
    for entry in record.get("findings") or []:
        if isinstance(entry, dict):
            statuses[str(entry.get("status"))] = statuses.get(str(entry.get("status")), 0) + 1
    slices = [item for item in record.get("slices") or [] if isinstance(item, dict)]
    ran = [item for item in slices if item.get("status", "ended") in ("running", "ended")]
    return {
        "planned": record.get("planned_slices"),
        "ran": len(ran),
        "answered": sum(1 for item in ran if item.get("answer")),
        "tokens": sum(int(item.get("tokens") or 0) for item in slices),
        "findings": statuses,
        "stop": record.get("stop"),
    }


def engine_crash(exit_code: int | None, stopped: str | None, *, kind: str, record: dict[str, Any] | None) -> str | None:
    """Why the engine crashed, or None.

    ``kind`` is ``funnel``, ``deep`` (the agent route above the standard
    run) or ``agent``; ``record`` is the record of the engine (funnel-run.json,
    deep.json or the runner.json of the agent). A stop of the parent (the
    wall clock, an interrupt, a provider refusal) explains the exit code and
    a missing record. Else the funnel and the deep engine must exit with 0
    and leave their record. The agent runner must leave its record and exit
    with the code that the record holds: the code of the last Pi process,
    whose answer the run then checks; another code means that the runner
    itself failed.
    """
    if stopped is not None:
        return None
    name = {"funnel": "the funnel engine", "deep": "the deep engine of the agent route"}.get(kind, "the agent runner")
    if record is None:
        return f"{name} wrote no readable record (exit code {exit_code})"
    if kind != "agent":
        return None if exit_code in (0, None) else f"{name} ended with exit code {exit_code}"
    if record.get("error"):
        return f"the agent did not start ({str(record['error'])[:200]})"
    recorded = record.get("exit")
    if isinstance(recorded, int) and isinstance(exit_code, int) and exit_code % 256 != recorded % 256:
        return f"{name} ended with exit code {exit_code}"
    return None


def agent_stop(runner: dict[str, Any], deep_record: dict[str, Any] | None) -> str | None:
    """The stop of the agent route for the result: the stop of the deep engine, else the limit that stopped the agent."""
    if deep_record is not None:
        return str(deep_record["stop"]) if deep_record.get("stop") else None
    for key in ("final_stopped", "stopped"):
        if runner.get(key):
            return str(runner[key])
    return None


# The stops of the engines and the stop reasons of the result.
_STOP_REASONS = {
    "queue-empty": STOP_DONE,
    "unit-check-cap": STOP_DONE,
    "done": STOP_DONE,
    "token-stop": STOP_TOKENS,
    "budget-blocked": STOP_TOKENS,
    "token-limit": STOP_TOKENS,
    "token-reserve": STOP_TOKENS,
    "time-stop": STOP_WALL_CLOCK,
    "end-of-time": STOP_WALL_CLOCK,
    "time-limit": STOP_WALL_CLOCK,
    "budget-stop": STOP_BUDGET,
    "budget-left": STOP_BUDGET,
    "budget": STOP_BUDGET,
    "budget-refused": STOP_BUDGET,
    "terminated": STOP_ENGINE,
    "error": STOP_ENGINE,
}


def stop_reason_of(stopped: str | None, detail: str | None, refusals: list[dict[str, Any]]) -> str:
    """Why a run stopped that the engine ended (or the wall clock): one of the ``STOP_`` values of ``result``."""
    if stopped == "wall-clock":
        return STOP_WALL_CLOCK
    reason = _STOP_REASONS.get(str(detail), STOP_DONE if detail is None else STOP_ENGINE)
    if reason in (STOP_DONE, STOP_TOKENS, STOP_BUDGET) and refusals:
        # The gateway refused calls: the cost cap or the token ceiling of the gateway ended the work.
        return STOP_BUDGET if any(str(item.get("reason", "")).startswith("spend") for item in refusals) else STOP_TOKENS
    return reason


def files_read(folders: list[Path]) -> int:
    """The count of the files that the agent sessions below ``folders`` read (their read tool calls; no path is kept)."""
    paths: set[str] = set()
    for folder in folders:
        if not folder.is_dir():
            continue
        for session in folder.rglob("*.jsonl"):
            try:
                with session.open("rb") as stream:
                    for raw in stream:
                        if b'"toolCall"' not in raw:
                            continue
                        try:
                            entry = json.loads(raw)
                        except ValueError:
                            continue
                        message = entry.get("message") if isinstance(entry, dict) else None
                        for block in (message.get("content") or []) if isinstance(message, dict) else []:
                            if isinstance(block, dict) and block.get("type") == "toolCall" and block.get("name") == "read":
                                arguments = block.get("arguments")
                                if isinstance(arguments, dict) and isinstance(arguments.get("path"), str):
                                    paths.add(arguments["path"].removeprefix("./"))
            except OSError:
                continue
    return len(paths)


def run_audit(
    config: Config,
    request: AuditRequest,
    *,
    log: Log | None = None,
    environment: Mapping[str, str] | None = None,
    transport: Transport | None = None,
) -> AuditOutcome:
    """Run one audit and write its outputs. Raises ``AuditError`` when the audit cannot run."""
    log = log or Log()
    env = dict(os.environ if environment is None else environment)
    started_at, started = now_text(), time.monotonic()
    protect_parent_process()
    repository = request.repository.expanduser().resolve()
    if not repository.is_dir():
        raise AuditError(f"{request.repository} is not a folder", EXIT_USAGE)
    unknown = [item for item in request.formats if item not in FORMATS]
    if unknown:
        raise AuditError(f"unknown output formats: {', '.join(unknown)}", EXIT_USAGE)
    key, key_variable = config.api_key(env)
    if key is None and config.provider.require_api_key:
        raise AuditError("no provider key: set SENTRYTOWER_API_KEY (or OPENROUTER_API_KEY) in the environment", EXIT_ENVIRONMENT)
    pi_cli = pi.find_pi(config.tools.pi)
    if pi_cli is None:
        raise AuditError("the Pi CLI is not installed: run `sentrytower doctor` for the install steps", EXIT_ENVIRONMENT)
    tools = {name: pi.find_tool(name, getattr(config.tools, name)) for name in pi.NATIVE_TOOLS}
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        raise AuditError(f"missing tools: {', '.join(missing)} (ripgrep and fd); run `sentrytower doctor`", EXIT_ENVIRONMENT)
    try:
        version = pi.pi_version(pi_cli)
        pi.pi_package_directory(pi_cli)
    except (OSError, ValueError) as error:
        raise AuditError(f"the Pi CLI at {pi_cli} cannot be used: {error}", EXIT_ENVIRONMENT) from None
    for name, path in (("Pi CLI", pi_cli), *((label, found) for label, found in tools.items() if found is not None)):
        if _inside(path.resolve(), repository):
            raise AuditError(f"the {name} {path} is in the audited repository: SentryTower runs no program of the audited code", EXIT_USAGE)
    proxy = proxy_problem(config.provider.base_url)
    if proxy:
        raise AuditError(proxy, EXIT_ENVIRONMENT)
    warnings: list[str] = []
    if request.out_dir.expanduser().absolute().resolve().is_relative_to(repository):
        warnings.append("the output folder is in the audited repository: a later run reads the outputs of this run")
        log.warn(warnings[-1])
    if version != pi.PI_VERSION:
        warnings.append(f"Pi {version} is installed, not the pinned version {pi.PI_VERSION}: another version can change the model requests")
        log.warn(warnings[-1])

    decision: RouteDecision = decide(repository, config.large_repo_files)
    route = decision.route
    models = config.models_of(route)
    session_model = models["free_roaming"] if route == ROUTE_FUNNEL else models[AGENT_ROLE]
    ordered = list(dict.fromkeys([session_model, *models.values()]))
    try:
        # A cap that the person gave needs the prices of each model of the route: else it could not stop the run.
        config.check_cost_cap(route)
    except ConfigError as error:
        raise AuditError(str(error), EXIT_USAGE) from None
    cap = config.cost_cap(route)
    plan = config.token_plan(route)
    tokens = plan.tokens
    # A budget larger than the standard run buys depth: more of each step of the funnel and its passes, or the slices
    # of the agent route. The completion ceiling of each call stays the ceiling of its policy at every depth.
    policies = config.policies(ordered)
    factor = plan.depth
    deep = factor > 1
    # The soft stop at 85% of the cap: when dollars end the run, and on the agent route whenever the run has a cap (the
    # agent then writes its answer before the cap refuses its calls). The standard run of the funnel keeps its measured
    # pacing of 20M tokens: its cap is an upper limit only.
    soft_stop = cap is not None and (plan.money_ends or route != ROUTE_FUNNEL)
    log.info(
        f"{decision.files_counted}{'+' if decision.files_counted >= decision.counted_up_to else ''} files counted: "
        f"{'funnel engine' if route == ROUTE_FUNNEL else 'single-agent engine'}"
    )
    log.info("models: " + ", ".join(sorted(set(models.values()))) + ("" if len(set(models.values())) == 1 else " (multi-LLM)"))
    log.route_known(
        repository=repository,
        files=decision.files_counted,
        more=decision.files_counted >= decision.counted_up_to,
        route=route,
        models=models,
        max_tokens=tokens,
        wall_clock_seconds=config.budget.wall_clock_seconds,
        max_cost_usd=cap,
    )
    if cap is not None and plan.money_ends:
        log.info(f"cost cap ${cap:.2f}: no new work starts at 85% of it (${cap * SOFT_STOP_FRACTION:.2f})")
    elif cap is not None:
        standard = " of the standard run" if plan.source == SOURCE_STANDARD else ""
        answer = f"; the agent writes its answer at 85% of the cap (${cap * SOFT_STOP_FRACTION:.2f})" if soft_stop else ""
        log.info(f"cost cap ${cap:.2f}, an upper limit: the token plan{standard} ({tokens:,} tokens) ends the run{answer}")
    if deep:
        log.info(f"depth {factor:.2g} times the standard run ({PREVIEW_LABEL}); token plan {tokens:,} tokens")
    elif plan.source == SOURCE_COST_CAP:
        log.info(f"token plan: {tokens:,} tokens, what the cost cap buys; the money ends the run")
    for note in (plan.note, config.unpriced_note(route)):
        if note:
            warnings.append(note)
            log.warn(note)

    _probe_out_dir(request.out_dir, repository)
    layout = RunLayout.create(request.state_dir or (Path(config.state_dir) if config.state_dir else None), repository)
    run_id = uuid.uuid4().hex
    gateway_config = GatewayConfig(
        base_url=config.provider.base_url,
        api_key=key or "",
        policies=policies,
        # With a cap and depth (or a cap that buys less than the standard run), dollars end the run: no token ceiling.
        max_total_tokens=plan.gateway_tokens,
        max_cost_usd=cap,
        soft_stop_fraction=SOFT_STOP_FRACTION if soft_stop else None,
        # The default parallel requests grow with the depth factor; a value of the settings stays.
        max_parallel_requests=math.ceil(config.provider.max_parallel_requests * factor)
        if config.provider.max_parallel_requests == DEFAULT_PARALLEL_REQUESTS
        else config.provider.max_parallel_requests,
        headers=dict(config.provider.headers),
    )

    def on_call(event: dict[str, Any]) -> None:
        log.debug(
            f"model call {event['model']}: HTTP {event['status']}, {event['attempts']} attempt(s), "
            f"{event.get('tokens') or 0} tokens, {event['seconds']} s"
        )

    exit_code: int | None = None
    stopped: str | None = None
    interrupted = False
    engine: dict[str, Any] = {}
    findings: list[OutputFinding] = []
    engine_started = time.monotonic()
    with ModelGateway(gateway_config, transport=transport, on_call=on_call if log.verbose else None) as gateway:
        pi.write_agent_config(layout.agent, gateway.url, [policies[model] for model in ordered])
        package = pi.prepare_agent_directory(layout.agent, pi_cli=pi_cli, tools={name: path for name, path in tools.items() if path})
        agent_env = pi.agent_environment(layout.agent, package, gateway.token)
        command = pi.agent_command(
            pi_cli=pi_cli,
            session_directory=layout.sessions,
            agent_directory=layout.agent,
            model=session_model,
            prompt=pi.audit_prompt(),
            final=pi.final_message(),
            # The agent route of a deep run: the whole-repository session has the budget of a standard run.
            token_budget=min(tokens, STANDARD_TOKENS) if deep and route != ROUTE_FUNNEL else tokens,
            wall_clock_seconds=config.budget.wall_clock_seconds,
            # With a cap, each agent session ends its first turn when the gateway says that no new work may start
            # (85% of the cap with the soft stop, or a provider refusal) and writes its answer.
            budget_url=gateway.url if cap is not None else None,
        )
        base = engine_environment(env, secret_names=tuple(config.provider.api_key_env), secret_values=(key or "",), repository=repository)
        # The cost cap for the engines: the soft stop, the estimate of the price, and whether dollars end the run.
        money = (
            {
                "cap_usd": cap,
                "soft_stop_usd": round(cap * SOFT_STOP_FRACTION, 6) if soft_stop else None,
                "price_per_million": plan.price_per_million,
                "extend": plan.money_ends,
                "token_limit": plan.gateway_tokens,
            }
            if cap is not None
            else None
        )

        def progress() -> str | None:
            total = gateway.totals()["total"]
            cost = f", ${total['cost_usd']:.2f}" if isinstance(total.get("cost_usd"), float) else ""
            return f"{total['calls']} model calls, {total['total_tokens']:,} tokens{cost}"

        layout.control.mkdir(parents=True, exist_ok=True)
        if route == ROUTE_FUNNEL:
            layout.work.mkdir(parents=True, exist_ok=True)
            spec = {
                "schema": SPEC_SCHEMA,
                "repository": str(repository),
                "work_dir": str(layout.work),
                "token_ceiling": tokens,
                "wall_clock_seconds": config.budget.wall_clock_seconds,
                "model_base_url": gateway.url,
                "models": models,
                "completion_ceilings": {model: policies[model].max_completion_tokens for model in ordered},
                "agent_command": command,
                "agent_env": agent_env,
                "parameters": {
                    **funnel_parameters(tokens, config.funnel_parameters),
                    **dict(config.funnel_parameters),
                    "large_repo_files": config.large_repo_files,
                },
                "money": money,
            }
            spec_path = layout.control / "funnel-spec.json"
            # The spec holds the credential of the run: a new file, readable by this user only.
            descriptor = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(spec, indent=2) + "\n")
            # -P: the working folder is the audited repository; Python must not import a module from it.
            argv = [sys.executable, "-P", "-m", "sentrytower.funnel", "--spec", str(spec_path)]
            environment_of_engine = {**base, CREDENTIAL_VARIABLE: gateway.token}
            log.info("funnel engine started")
        elif deep:
            layout.work.mkdir(parents=True, exist_ok=True)
            deep_spec = {
                "schema": DEEP_SPEC_SCHEMA,
                "repository": str(repository),
                "work_dir": str(layout.work),
                "base_session_dir": str(layout.sessions),
                "token_ceiling": tokens,
                "wall_clock_seconds": config.budget.wall_clock_seconds,
                "session_tokens": STANDARD_TOKENS,
                "max_sessions": parallel_sessions(tokens),
                "agent_command": command,
                "agent_env": agent_env,
                "model_base_url": gateway.url,
                "agent_model": session_model,
                "verify_model": session_model,
                "completion_ceilings": {model: policies[model].max_completion_tokens for model in ordered},
                "verify_votes": VERIFY_VOTES,
                "money": money,
            }
            spec_path = layout.control / "deep-spec.json"
            descriptor = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(deep_spec, indent=2) + "\n")
            argv = [sys.executable, "-P", "-m", "sentrytower.agent.deep", "--spec", str(spec_path)]
            environment_of_engine = {**base, **agent_env}
            log.info("single-agent engine started, with slices for the rest of the budget")
        else:
            argv = command
            environment_of_engine = {**base, **agent_env}
            log.info("single-agent engine started")

        def snapshot() -> dict[str, Any]:
            current = gateway.totals()["total"]
            return {"tokens": current["total_tokens"], "cost": current.get("cost_usd"), "calls": current["calls"]}

        def should_stop() -> str | None:
            # A refused key, account or route: no model call of the run can succeed.
            return STOP_PROVIDER if gateway.provider_error is not None else None

        log.engine_started(route=route, work=layout.work, sessions=layout.sessions, snapshot=snapshot)
        try:
            exit_code, stopped = _run_engine(
                argv,
                cwd=repository,
                environment=environment_of_engine,
                logs=layout.control,
                wall_clock_seconds=config.budget.wall_clock_seconds,
                log=log,
                progress=progress,
                should_stop=should_stop,
            )
        except KeyboardInterrupt:
            # SIGINT or SIGTERM: the engine is stopped; write the outputs of what it finished.
            interrupted, stopped = True, "interrupted"
            log.interrupted()
            log.warn("interrupted: the engine is stopped; writing the outputs")
        usage = gateway.totals()
        refusals = list(gateway.refusals)
    engine_seconds = time.monotonic() - engine_started
    roots = (str(repository), str(request.repository))
    # The outcome of the engine: a problem makes the run incomplete (crash, no answer) or failed (no output).
    problem: str | None = None
    unreadable: str | None = None
    detail: str | None = None
    units: dict[str, Any] = {"kind": UNITS_FUNNEL if route == ROUTE_FUNNEL else UNITS_AGENT, "checked": 0, "failed": 0, "total": None}
    sessions: dict[str, Any] = {"answered": 0, "failed": 0}
    try:
        if route == ROUTE_FUNNEL:
            findings, state = funnel_output(layout.work, layout.sessions, roots)
            found_record = _read_json(layout.work / "funnel-run.json")
            record = found_record if isinstance(found_record, dict) else {}
            summary = _read_json(layout.work / "summary.json") or {}
            engine = {
                "name": "funnel",
                "version": record.get("version"),
                "exit": exit_code,
                "stop": (record.get("stop") or {}).get("reason"),
                "repository": record.get("repository"),
                "phase0": {key: (record.get("phase0") or {}).get(key) for key in ("status", "error", "seconds", "units", "files")},
                "free_session": {
                    key: (record.get("free_session") or {}).get(key) for key in ("started", "tokens", "seconds", "stopped", "findings")
                },
                "counts": summary.get("funnel"),
                "tokens_by_pool": (summary.get("tokens") or {}).get("used"),
                "output": state,
                "error": record.get("error"),
            }
            detail = engine["stop"]
            given = summary.get("funnel")
            counts: dict[str, Any] = given if isinstance(given, dict) else {}
            units.update(
                checked=int(counts.get("checked") or 0),
                failed=int(counts.get("unit_checks_failed") or 0) + int(counts.get("units_unreadable") or 0),
                total=counts.get("units_to_check") if isinstance(counts.get("units_to_check"), int) else None,
            )
            sessions.update(answered=int(counts.get("sessions_answered") or 0), failed=int(counts.get("sessions_no_answer") or 0))
            problem = engine_crash(exit_code, stopped, kind="funnel", record=found_record if isinstance(found_record, dict) else None)
            if problem is None and record.get("error"):
                problem = str(record["error"])
            elif problem is None and not state.get("final"):
                problem = "the funnel did not finish its findings file"
        else:
            agent_findings, state = _session_findings(layout.sessions, roots)
            findings = [from_agent(item, rank=rank, route=route, engine=ENGINE_AGENT) for rank, item in enumerate(agent_findings, 1)]
            found_deep = _read_json(layout.work / DEEP_RECORD) if deep else None
            deep_record = found_deep if isinstance(found_deep, dict) else None
            if deep_record is not None:
                findings += slice_findings(deep_record, roots, route, first_rank=len(findings) + 1)
            found_runner = _read_json(layout.sessions / RUNNER_RECORD)
            runner = found_runner if isinstance(found_runner, dict) else {}
            engine = {
                "name": "single-agent",
                "exit": exit_code,
                "stop": runner.get("stopped") or runner.get("final_stopped"),
                "turns": [
                    {key: turn.get(key) for key in ("turn", "exit", "stopped", "tokens_at_end", "seconds_at_end")}
                    for turn in runner.get("turns") or []
                ],
                "final_turn": runner.get("final_turn"),
                "blank_restarts": (runner.get("blank_restarts") or {}).get("count"),
                "output": state,
                "error": runner.get("error"),
            }
            if deep_record is not None:
                engine["slices"] = deep_summary(deep_record)
            detail = agent_stop(runner, deep_record)
            sessions.update(answered=int(bool(state["answer"])), failed=int(not state["answer"]))
            planned = 1
            if deep_record is not None:
                summary_of_slices = engine["slices"]
                planned += int(summary_of_slices.get("planned") or 0)
                sessions["answered"] += int(summary_of_slices.get("answered") or 0)
                sessions["failed"] += int(summary_of_slices.get("ran") or 0) - int(summary_of_slices.get("answered") or 0)
            units.update(
                checked=sessions["answered"],
                failed=sessions["failed"],
                total=planned,
                files_read=files_read([layout.sessions, layout.work / "slices"]),
            )
            problem = engine_crash(
                exit_code,
                stopped,
                kind="deep" if deep else "agent",
                record=deep_record if deep else (runner if isinstance(found_runner, dict) else None),
            )
            if problem is None and not state["answer"]:
                problem = f"the agent gave no findings answer ({state['error']})"
    except AuditError as error:
        unreadable = str(error)
    except Exception as error:  # noqa: BLE001 - the run record and the outputs must still be written
        unreadable = f"the output of the engine cannot be read ({type(error).__name__})"
    calls = calls_record(usage["total"])
    provider = usage["total"].get("provider_error")
    if interrupted:
        status, stop_reason, failure = STATUS_INTERRUPTED, STOP_INTERRUPTED, "the run was interrupted (SIGINT or SIGTERM)"
    elif provider is not None:
        status, stop_reason = STATUS_FAILED, STOP_PROVIDER
        failure = provider_failure(int(provider["status"]), str(provider.get("model") or session_model), key_variable)
    elif unreadable is not None:
        status, stop_reason, failure = STATUS_FAILED, STOP_ENGINE, unreadable
    else:
        stop_reason = stop_reason_of(stopped, detail, refusals)
        status, failure = STATUS_COMPLETE, None
        undone = failed_calls_failure(calls, usage["total"].get("failed_by") or {})
        if undone is None and route == ROUTE_FUNNEL:
            # The funnel ended: its inventory, its unit checks and its agent sessions must have done their work.
            undone = phase0_failure(engine.get("phase0") or {}) or units_failure(units)
            if undone is None and stop_reason not in (STOP_WALL_CLOCK, STOP_INTERRUPTED):
                # The wall clock and an interrupt end the running sessions: those stops explain a missing answer.
                undone = sessions_failure(sessions)
        if problem is not None:
            status, failure = STATUS_INCOMPLETE, problem
            if stop_reason == STOP_DONE:
                stop_reason = STOP_ENGINE
        elif undone is not None:
            status, failure = STATUS_INCOMPLETE, undone
    if stopped == "wall-clock" and status == STATUS_COMPLETE:
        warnings.append("the wall clock of the run ended before the engine finished")
    sentence = stop_text(
        stop_reason,
        route=route,
        detail=detail,
        cap_usd=cap,
        tokens=tokens,
        wall_clock_seconds=config.budget.wall_clock_seconds,
        provider_status=int(provider["status"]) if provider is not None else None,
        incomplete=status == STATUS_INCOMPLETE,
    )
    spent = usage["total"].get("cost_usd")
    if spent is None and not usage["total"].get("total_tokens"):
        # No counted token is no cost, whatever the prices: a run that the provider refused at once spent nothing.
        spent = 0.0
    result: dict[str, Any] = {
        "status": status,
        "stop_reason": stop_reason,
        "stop_text": sentence,
        "failure": failure,
        "spent_usd": spent,
        "cap_usd": cap,
        "units": units,
        "calls": calls,
        "depth_factor": round(factor, 3),
        "preview": factor > 1,
        "sessions": sessions,
    }
    if provider is not None and provider.get("message"):
        result["provider_message"] = provider["message"]
    total = usage["total"]
    run: dict[str, Any] = {
        "schema_version": RUN_SCHEMA_VERSION,
        "tool": {"name": "SentryTower", "version": __version__},
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": now_text(),
        "seconds": round(time.monotonic() - started, 1),
        "status": status,
        "failure": failure,
        "result": result,
        "repository": {
            "name": repository.name,
            "path": str(repository),
            "files_counted": decision.files_counted,
            "counted_up_to": decision.counted_up_to,
        },
        "route": route,
        "router": decision.record(),
        "models": models,
        "configuration": config.record(),
        "usage": usage,
        "budget": {
            "max_tokens": tokens,
            **plan.record(),
            "max_tokens_setting": config.budget.max_tokens,
            "depth_factor": round(factor, 3),
            "preview": deep,
            "completion_ceilings": {model: policies[model].max_completion_tokens for model in ordered},
            "wall_clock_seconds": config.budget.wall_clock_seconds,
            # The cap of the run (the default cap when no setting gives one), and the setting (0: no cap).
            "max_cost_usd": cap,
            "max_cost_usd_setting": config.budget.max_cost_usd,
            "soft_stop_usd": money["soft_stop_usd"] if money else None,
            "refusals": len(refusals),
            "token_ceiling_reached": any(item["reason"].startswith("token") for item in refusals),
            "cost_cap_reached": any(item["reason"].startswith("spend") for item in refusals),
            "wall_clock_reached": stopped == "wall-clock",
        },
        "stop": engine.get("stop") or stopped,
        "engine": engine,
        "timings": {
            "router_seconds": round(decision.seconds, 4),
            "engine_seconds": round(engine_seconds, 1),
            "total_seconds": round(time.monotonic() - started, 1),
        },
        "tools": {
            "pi": version,
            "python": ".".join(str(part) for part in sys.version_info[:3]),
        },
        "key_variable": key_variable,
        "findings": {"count": len(findings), "by_severity": severity_counts(findings)},
        "warnings": warnings,
    }
    files = write_outputs(
        findings,
        run,
        request.out_dir,
        request.formats,
        sarif_category=request.sarif_category,
        sarif_path_prefix=request.sarif_path_prefix,
        repository=repository,
    )
    if total.get("cost_usd") is not None:
        log.info(f"{total['calls']} model calls, {total['total_tokens']:,} tokens, ${total['cost_usd']:.4f} ({total['cost_source']})")
    else:
        log.info(f"{total['calls']} model calls, {total['total_tokens']:,} tokens")
    log.info(f"{len(findings)} findings; outputs in {request.out_dir}")
    if "html" in files:
        log.info(f"report: {files['html']}")
    if request.keep_state or status != STATUS_COMPLETE:
        log.info(f"run state kept in {layout.root}")
    else:
        layout.remove()
    code = EXIT_OK if status == STATUS_COMPLETE else (EXIT_INTERRUPTED if interrupted else EXIT_RUN_FAILED)
    # The last lines: the spend, why the run stopped, the checked units (the same sentences as each report).
    *lines, last = result_lines(result)
    for line in lines:
        log.info(line)
    if failure and status != STATUS_INTERRUPTED:
        log.warn(last)
    else:
        log.info(last)
    return AuditOutcome(findings=findings, run=run, files=files, exit_code=code)


def write_outputs(
    findings: list[OutputFinding],
    run: dict[str, Any],
    out_dir: Path,
    formats: tuple[str, ...],
    *,
    sarif_category: str = DEFAULT_CATEGORY,
    sarif_path_prefix: str = "",
    repository: Path | None = None,
) -> dict[str, Path]:
    """Write the selected output files and ``run.json``; each file in one rename.

    An output that cannot be built is left out with a warning in ``run.json``;
    ``run.json`` is always written. Each write goes through a descriptor of
    the output folder after the checks of ``_open_out_dir`` (``repository``
    is the audited repository): a new private staging file, then one rename
    that never follows a link at the name of the file (``_write_file``).
    """
    files: dict[str, Path] = {}
    builders: dict[str, Callable[[], str]] = {
        "json": lambda: json.dumps(findings_document(findings, run), indent=2, ensure_ascii=False) + "\n",
        "sarif": lambda: (
            json.dumps(sarif_document(findings, run, category=sarif_category, path_prefix=sarif_path_prefix), indent=2, ensure_ascii=False)
            + "\n"
        ),
        "markdown": lambda: markdown_report(findings, run),
        "html": lambda: html_report(findings, run),
    }
    run["outputs"] = {name: OUTPUT_FILES[name] for name in formats} | {"run": RUN_FILE}
    contents: dict[str, str] = {}
    for name in formats:
        try:
            contents[name] = builders[name]()
        except Exception as error:  # noqa: BLE001 - one broken output must not cost the others
            run["outputs"].pop(name, None)
            run.setdefault("warnings", []).append(f"{OUTPUT_FILES[name]} was not written ({type(error).__name__})")
    contents["run"] = json.dumps(run, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    folder = _open_out_dir(out_dir, repository)
    mode = _file_mode()
    try:
        for name, text in contents.items():
            filename = OUTPUT_FILES.get(name) or RUN_FILE
            try:
                # "replace": a lone surrogate (from a file name that is not UTF-8) cannot stop the write.
                _write_file(folder, filename, text.encode("utf-8", "replace"), mode)
            except OSError as error:
                raise AuditError(
                    f"{filename} cannot be written in the output folder {out_dir}: {type(error).__name__}", EXIT_ENVIRONMENT
                ) from None
            files[name] = out_dir / filename
        with contextlib.suppress(OSError):
            os.fsync(folder)
    finally:
        os.close(folder)
    return files


def output_files(out_dir: Path) -> dict[str, Path]:
    """The output files of an earlier run in ``out_dir``, the resolved folder that ``sentrytower last`` keeps.

    The folder must still be a folder of this user with no symbolic link on
    its path: a repository can change a folder of its own after the run.
    A file counts only when it is a regular file; a link at its name is left
    out. Raises AuditError (exit 2) when the folder fails a check.
    """
    if os.path.realpath(out_dir) != str(out_dir):
        raise AuditError(f"the output folder {out_dir} has a symbolic link on its path now: run the audit again", EXIT_USAGE)
    try:
        info = out_dir.lstat()
    except OSError as error:
        raise AuditError(f"the output folder {out_dir} cannot be read: {type(error).__name__}", EXIT_USAGE) from None
    if not stat.S_ISDIR(info.st_mode):
        raise AuditError(f"the output folder {out_dir} is not a folder", EXIT_USAGE)
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise AuditError(f"the output folder {out_dir} belongs to another user", EXIT_USAGE)
    files: dict[str, Path] = {}
    for name, filename in (*OUTPUT_FILES.items(), ("run", RUN_FILE)):
        try:
            if stat.S_ISREG((out_dir / filename).lstat().st_mode):
                files[name] = out_dir / filename
        except OSError:
            continue
    return files
