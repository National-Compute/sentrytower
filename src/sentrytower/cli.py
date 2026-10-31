"""The command line: ``sentrytower`` (the home screen), ``audit``, ``setup``, ``settings``, ``last``, ``doctor`` and ``version``.

In a terminal the commands are interactive: the agent, a guided setup, a
live view of the audit and a summary of the results (``ui``). Without a
terminal (CI, a pipe), with ``--plain``, ``-q`` or ``-v``, the output is the
plain progress lines of ``audit.Log`` and nothing asks a question.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import traceback
from pathlib import Path
from types import FrameType
from typing import Any

from . import __version__
from .agent.pi import PI_VERSION
from .audit import (
    EXIT_ENVIRONMENT,
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_RUN_FAILED,
    EXIT_USAGE,
    FORMATS,
    AuditError,
    AuditOutcome,
    AuditRequest,
    Log,
    output_files,
    run_audit,
)
from .budget import DEPTHS
from .config import Config, ConfigError, load_config, user_config_path
from .findings import SCHEMA_VERSION as FINDINGS_SCHEMA_VERSION
from .findings import at_or_above
from .result import PREVIEW_LABEL
from .sarif import DEFAULT_CATEGORY, normalize_prefix
from .ui.term import printable

DEFAULT_OUT = "sentrytower-results"
FORMAT_ALIASES = {"json": "json", "sarif": "sarif", "md": "markdown", "markdown": "markdown", "html": "html"}
EPILOG = """\
exit codes:
  0  the audit finished (with or without findings)
  1  --fail-on: a finding at or above the severity
  2  invalid command line or configuration (also: a cost cap for a model
     without prices)
  3  the environment is not ready (provider key, Pi CLI, ripgrep, fd)
  4  the run failed or is incomplete: the provider refused the key, the
     account or the route (HTTP 401, 402, 403, 404), more than 20% of the
     model calls failed, or the engine crashed
  130 interrupted

In a terminal, `sentrytower` opens the home screen and `sentrytower setup`
walks through the settings. The provider key comes from SENTRYTOWER_API_KEY
or OPENROUTER_API_KEY (or the system keychain, when setup saved it there).
"""


def _formats(value: str) -> tuple[str, ...]:
    parts = [part.strip().lower() for part in value.split(",") if part.strip()]
    if parts == ["all"]:
        return FORMATS
    selected = []
    for part in parts:
        if part not in FORMAT_ALIASES:
            raise argparse.ArgumentTypeError(f"unknown format {part!r}; use json, sarif, markdown, html or all")
        selected.append(FORMAT_ALIASES[part])
    if not selected:
        raise argparse.ArgumentTypeError("give at least one format")
    return tuple(dict.fromkeys(selected))


def _positive_int(value: str) -> int:
    try:
        number = int(value.replace("_", ""))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("the value must be positive")
    return number


def _money(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("the value must be a number of at least 0")
    return number


def _prefix(value: str) -> str:
    try:
        return normalize_prefix(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _category(value: str) -> str:
    text = value.strip().strip("/")
    if not text or any(character.isspace() for character in text):
        raise argparse.ArgumentTypeError("the category must be a word without spaces")
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentrytower",
        description="SentryTower: an LLM security audit of a source repository. It routes each repository "
        "to the engine that fits its size and writes the findings as JSON, SARIF, Markdown and HTML.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sentrytower {__version__}")
    parser.add_argument(
        "--profile", dest="global_profile", metavar="NAME", help="use the settings of a profile (~/.config/sentrytower/profiles/NAME.toml)"
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    audit = commands.add_parser(
        "audit",
        help="audit a repository and write the findings",
        description="Audit the repository at PATH. The router counts its files: 1,000 or fewer go to the funnel "
        "engine, more go to the single-agent engine. The findings go to --out.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit.add_argument(
        "path", type=Path, metavar="PATH", nargs="?", help="the repository to audit (read only); a terminal asks when it is missing"
    )
    audit.add_argument(
        "--out", type=Path, metavar="DIR", help=f"the output folder (default: run.out_dir of the settings, else ./{DEFAULT_OUT})"
    )
    audit.add_argument(
        "--config", type=Path, metavar="FILE", help="a TOML configuration file (default: SENTRYTOWER_CONFIG, else the settings of setup)"
    )
    audit.add_argument("--profile", metavar="NAME", help="use the settings of a profile")
    audit.add_argument(
        "--model",
        metavar="ID",
        help="one model for every role (default: deepseek/deepseek-v4.1-flash-1017); a terminal also takes a short name such as deepseek",
    )
    audit.add_argument(
        "--fast-model", metavar="ID", help="the model of the many short calls of the funnel (rating, unit checks, triage, verify)"
    )
    audit.add_argument("--agent-model", metavar="ID", help="the model of the agent sessions (deep checks, free roaming, single agent)")
    audit.add_argument("--base-url", metavar="URL", help="an OpenAI-compatible endpoint (default: OpenRouter)")
    audit.add_argument(
        "--max-tokens",
        type=_positive_int,
        metavar="N",
        help="an upper limit of the tokens of the run (default: the plan of the cost cap; 20000000 without a cap)",
    )
    audit.add_argument("--wall-clock", type=_positive_int, metavar="SECONDS", help="the wall clock of the run (default: 14400)")
    audit.add_argument(
        "--max-cost-usd",
        type=_money,
        metavar="USD",
        help="the cost cap of the run in US dollars: it buys the depth, no new work starts at 85%% of it, "
        "and the dollars end the run (default: $2, the measured standard run, when each model of the "
        "route has prices; 0: no cap)",
    )
    depths = ", ".join(f"{name} (${value:g})" for name, value in DEPTHS.items())
    audit.add_argument(
        "--depth",
        choices=tuple(DEPTHS),
        metavar="DEPTH",
        help=f"the depth of the audit: {depths}. Standard is the measured run; deep and max carry the label "
        f'"{PREVIEW_LABEL}". It sets --max-cost-usd when that is not given',
    )
    audit.add_argument(
        "--format",
        type=_formats,
        default=FORMATS,
        metavar="FORMATS",
        help="the outputs: json, sarif, markdown, html or all, comma-separated (default: all); run.json is always written",
    )
    audit.add_argument(
        "--open",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="open report.html in the browser when the audit ends (default: in a terminal yes, else no; run.open_report of the settings)",
    )
    audit.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        metavar="SEVERITY",
        help="exit 1 when a finding has this severity or a higher one (critical, high, medium, low)",
    )
    audit.add_argument(
        "--sarif-category",
        type=_category,
        default=DEFAULT_CATEGORY,
        metavar="NAME",
        help=f"the code-scanning category of findings.sarif (default: {DEFAULT_CATEGORY})",
    )
    audit.add_argument(
        "--sarif-path-prefix",
        type=_prefix,
        default="",
        metavar="DIR",
        help="put this repository folder in front of each path of findings.sarif "
        "(for the audit of a subfolder; code scanning reads paths from the repository root)",
    )
    audit.add_argument("--state-dir", type=Path, metavar="DIR", help="the folder of the run state (default: a temporary folder)")
    audit.add_argument("--keep-state", action="store_true", help="keep the run state (agent sessions, funnel records)")
    audit.add_argument("--plain", action="store_true", help="plain progress lines, also in a terminal (as in CI)")
    noise = audit.add_mutually_exclusive_group()
    noise.add_argument("-q", "--quiet", action="store_true", help="print warnings only")
    noise.add_argument("-v", "--verbose", action="store_true", help="print each model call (no prompt or answer text)")

    setup = commands.add_parser("setup", help="choose the agent, the models, the key and the budget (interactive)")
    setup.add_argument("--profile", metavar="NAME", help="write the settings of a profile instead of the default settings")

    settings = commands.add_parser("settings", help="show the settings in use and where they come from")
    settings.add_argument("--config", type=Path, metavar="FILE", help="a TOML configuration file")
    settings.add_argument("--profile", metavar="NAME", help="the settings of a profile")

    commands.add_parser("last", help="show the results of the last audit and open its report")

    doctor = commands.add_parser("doctor", help="check Python, Node.js, Pi, ripgrep, fd, the key and the endpoint")
    doctor.add_argument("--config", type=Path, metavar="FILE", help="a TOML configuration file")
    doctor.add_argument("--profile", metavar="NAME", help="the settings of a profile")
    doctor.add_argument("--offline", action="store_true", help="do not send the test request to the endpoint")
    doctor.add_argument("--json", action="store_true", help="print the checks as JSON")
    doctor.add_argument("--plain", action="store_true", help="plain text, also in a terminal")
    doctor.add_argument("-q", "--quiet", action="store_true", help="print nothing; the exit code tells the result")

    version = commands.add_parser("version", help="print the version of SentryTower and of its pinned components")
    version.add_argument("--json", action="store_true", help="print the versions as JSON")
    return parser


def _profile(args: argparse.Namespace) -> str | None:
    return getattr(args, "profile", None) or getattr(args, "global_profile", None)


def _cost_cap(args: argparse.Namespace) -> float | None:
    """--max-cost-usd, else the cost cap of --depth, else None (the settings decide)."""
    if args.max_cost_usd is not None:
        return float(args.max_cost_usd)
    return DEPTHS[args.depth] if getattr(args, "depth", None) else None


def _config(args: argparse.Namespace, **options: Any) -> Config:
    return load_config(getattr(args, "config", None), profile=_profile(args), **options)


class Ui:
    """The interactive pieces of one command: the terminal, the theme, the screen and the keys."""

    def __init__(self, config: Config | None, *, plain: bool = False) -> None:
        from .ui.screen import screen_for
        from .ui.term import detect
        from .ui.theme import theme_for

        theme_name = config.ui.theme if config is not None and config.ui.theme != "auto" else None
        self.caps = detect(plain=plain or bool(os.environ.get("SENTRYTOWER_PLAIN")), theme=theme_name)
        self.config = config
        color = config.ui.agent_color if config is not None else "sand"
        self.name = config.ui.agent_name if config is not None else "Juno"
        self.color = color
        self.theme = theme_for(color, self.caps.background)
        self.screen = screen_for(self.caps) if self.caps.interactive else None
        self.keys: Any = None
        self.prompter: Any = None

    @property
    def interactive(self) -> bool:
        return self.caps.interactive

    def __enter__(self) -> Ui:
        from .ui.keys import KeyReader
        from .ui.widgets import Prompter

        if self.screen is not None:
            self.keys = KeyReader().__enter__()
            self.prompter = Prompter(self.screen, self.keys, self.theme, self.caps)
        return self

    def __exit__(self, *args: object) -> None:
        if self.keys is not None:
            self.keys.__exit__(*args)
        if self.screen is not None:
            self.screen.close()

    def recolor(self, config: Config) -> None:
        from .ui.theme import theme_for

        self.config = config
        self.name, self.color = config.ui.agent_name, config.ui.agent_color
        self.theme = theme_for(self.color, self.caps.background)
        if self.prompter is not None:
            self.prompter.theme = self.theme


def _cancelled(ui: Ui, text: str) -> int:
    if ui.screen is not None:
        ui.screen.clear()
        sym = ui.prompter.sym if ui.prompter is not None else None
        ui.screen.print([[(f"{sym.stop if sym else 'x'}  ", ui.theme.caution), (text, ui.theme.dim)], []])
    return EXIT_INTERRUPTED


def _audit_request(args: argparse.Namespace, config: Config, path: Path) -> AuditRequest:
    """--out as given; else the results folder of the settings with one subfolder for each repository; else ./sentrytower-results."""
    if args.out is not None:
        out = args.out
    elif config.out_dir:
        out = Path(config.out_dir).expanduser() / (path.expanduser().resolve().name or "repository")
    else:
        out = Path(DEFAULT_OUT)
    return AuditRequest(
        repository=path,
        out_dir=out,
        formats=args.format,
        keep_state=args.keep_state,
        state_dir=args.state_dir,
        sarif_category=args.sarif_category,
        sarif_path_prefix=args.sarif_path_prefix,
    )


def _exit_code(outcome: AuditOutcome, fail_on: str | None, log: Log | None = None) -> int:
    if outcome.exit_code != EXIT_OK:
        return outcome.exit_code
    if fail_on and at_or_above(outcome.findings, fail_on):
        if log is not None:
            log.info(f"--fail-on {fail_on}: {len(at_or_above(outcome.findings, fail_on))} finding(s) at or above the threshold")
        return EXIT_FINDINGS
    return EXIT_OK


def _audit(args: argparse.Namespace) -> int:
    plain = args.plain or args.quiet or args.verbose
    try:
        config = _config(
            args,
            model=args.model,
            fast_model=args.fast_model,
            agent_model=args.agent_model,
            max_tokens=args.max_tokens,
            wall_clock_seconds=args.wall_clock,
            max_cost_usd=_cost_cap(args),
            base_url=args.base_url,
        )
    except ConfigError as error:
        print(f"sentrytower: configuration error: {printable(str(error))}", file=sys.stderr)
        return EXIT_USAGE
    ui = Ui(config, plain=plain)
    if ui.interactive:
        with ui:
            return _audit_live(args, ui, args.path)
    if args.path is None:
        print("sentrytower: give the repository to audit: sentrytower audit PATH", file=sys.stderr)
        return EXIT_USAGE
    log = Log(quiet=args.quiet, verbose=args.verbose)
    request = _audit_request(args, config, args.path)
    try:
        outcome = run_audit(config, request, log=log)
    except AuditError as error:
        print(f"sentrytower: {printable(str(error))}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("sentrytower: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as error:  # noqa: BLE001 - an unexpected error is a failed run, not a --fail-on result
        # The type only: a message can hold text of the model or of the audited code.
        print(f"sentrytower: the run failed with an unexpected error ({type(error).__name__})", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        return EXIT_RUN_FAILED
    if args.open:
        _open_report(outcome, log)
    return _exit_code(outcome, args.fail_on or config.fail_on, log)


def _open_report(outcome: AuditOutcome, log: Log) -> None:
    """Open the report of a plain run (``--open``), or say where it is."""
    from .ui.results import can_open, open_file, report_file

    report = report_file(outcome.files)
    if report is None:
        return
    if not can_open() or not open_file(report):
        log.info(f"the report cannot be opened here: {report}")


def _resolve_model(ui: Ui, args: argparse.Namespace, config: Config) -> Config:
    """A short model name of --model (deepseek) as the full ID of the endpoint's list, after a look at that list."""
    from .ui import catalog
    from .ui.widgets import Choice

    name = args.model
    if not name or "/" in name or ":" in name:
        return config
    assert ui.screen is not None and ui.prompter is not None
    key, _ = config.api_key()
    try:
        models = ui.prompter.wait("Looking up the model", lambda: catalog.fetch_models(config.provider.base_url, key=key))
    except (OSError, ValueError):
        return config
    found = catalog.resolve(name, models)
    if not found:
        raise ConfigError(f"no model of {config.provider.base_url} matches {name!r}")
    if len(found) == 1 or found[0].id.lower().split("/")[-1] == name.lower():
        chosen = found[0].id
        ui.screen.print(
            [[(f"{ui.prompter.sym.check}  ", ui.theme.good), (f"{name} ", ui.theme.dim), ("→ ", ui.theme.dim), (chosen, ui.theme.bold)], []]
        )
    else:
        choices = [Choice(model.id, model.id, columns=[model.id, model.context_text, model.price_text]) for model in found[:40]]
        chosen = str(ui.prompter.search(f"Which model is {name}?", choices).value)
    args.model = chosen
    return _config(
        args,
        model=chosen,
        fast_model=args.fast_model,
        agent_model=args.agent_model,
        max_tokens=args.max_tokens,
        wall_clock_seconds=args.wall_clock,
        max_cost_usd=_cost_cap(args),
        base_url=args.base_url,
    )


def _ask_folder(ui: Ui, question: str = "Which repository should I audit?") -> Path:
    def valid(text: str) -> str | None:
        return None if Path(text or ".").expanduser().is_dir() else "no such folder"

    answer = ui.prompter.text(
        question,
        default=".",
        validate=valid,
        hint="a folder · enter confirm · esc cancel",
        answer=lambda text: str(Path(text or ".").expanduser().resolve()),
    )
    return Path(answer or ".").expanduser()


def _audit_live(args: argparse.Namespace, ui: Ui, path: Path | None) -> int:
    from .ui.live import LiveAudit
    from .ui.results import can_open, open_file, remember, report_file, summary_lines
    from .ui.widgets import CancelledError, Choice

    assert ui.screen is not None and ui.prompter is not None
    config = ui.config
    assert config is not None
    try:
        if path is None:
            path = _ask_folder(ui)
        config = _resolve_model(ui, args, config)
    except CancelledError:
        return _cancelled(ui, "Nothing was audited.")
    except ConfigError as error:
        ui.screen.print([[("✗  ", ui.theme.bad), (f"configuration error: {error}", ui.theme.text)]])
        return EXIT_USAGE
    fail_on = args.fail_on or config.fail_on
    while True:
        live = LiveAudit(ui.screen, ui.theme, ui.caps, agent_name=ui.name, agent_color=ui.color)
        request = _audit_request(args, config, path)
        try:
            outcome = run_audit(config, request, log=live)
        except AuditError as error:
            live.close()
            ui.screen.print(
                [[("✗  ", ui.theme.bad), (str(error), ui.theme.text)], [("   Run sentrytower doctor for the fix.", ui.theme.dim)], []]
            )
            return error.exit_code
        except KeyboardInterrupt:
            # Ctrl-C before the engine started (run_audit handles it while the engine runs): no report.
            live.close()
            return _cancelled(ui, "Stopped before the engine started. Nothing was audited.")
        except Exception as error:  # noqa: BLE001 - the type only: a message can hold text of the model or the code
            live.close()
            ui.screen.print(
                [[("✗  ", ui.theme.bad), (f"the run failed with an unexpected error ({type(error).__name__})", ui.theme.text)], []]
            )
            return EXIT_RUN_FAILED
        live.close()
        remember(request.out_dir, outcome.run)
        summary = summary_lines(
            outcome.findings,
            outcome.run,
            outcome.files,
            theme=ui.theme,
            caps=ui.caps,
            agent_name=ui.name,
            agent_color=ui.color,
            width=ui.screen.width,
            shown_warnings=live.warnings,
        )
        ui.screen.print(summary)
        code = _exit_code(outcome, fail_on)
        if code == EXIT_FINDINGS:
            ui.screen.print([[(f"  --fail-on {fail_on}: ", ui.theme.caution), ("exit code 1", ui.theme.text)]])
        ui.keys.flush()
        report = report_file(outcome.files)
        opened = False
        if report is not None and (args.open if args.open is not None else config.open_report) and can_open():
            opened = open_file(report)
            if opened:
                line = [(f"  {ui.prompter.sym.check} ", ui.theme.good), ("Opened ", ui.theme.dim), (report.name, ui.theme.bold)]
                ui.screen.print([[*line, (" in the browser", ui.theme.dim)]])
        choices = []
        if report is not None:
            choices.append(Choice("open", "Open the report again" if opened else "Open the report", report.name))
        choices += [Choice("again", "Audit again", path.name), Choice("done", "Done")]
        try:
            ui.screen.print([[]])
            action = ui.prompter.select("What next?", choices, hint="↑↓ move · enter choose · esc done").value
        except CancelledError:
            action = "done"
        if action == "open" and report is not None:
            if not open_file(report):
                ui.screen.print([[("  The report is at ", ui.theme.dim), (str(report), ui.theme.bold)]])
            return code
        if action != "again":
            return code


def _count_files(path: Path) -> int:
    from .router import decide

    return decide(path).files_counted


def _setup(args: argparse.Namespace) -> int:
    from .doctor import run_checks
    from .ui.setup import Services, Setup
    from .ui.widgets import CancelledError

    try:
        config = load_config(profile=_profile(args)) if not _profile(args) or user_config_path(_profile(args)).is_file() else load_config()
    except ConfigError:
        config = Config(sources=("defaults",))
    ui = Ui(config)
    if not ui.interactive:
        print(
            "sentrytower setup asks questions: run it in a terminal. Without one, write the settings file "
            f"({user_config_path(_profile(args))}) or use SENTRYTOWER_* variables.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    with ui:
        assert ui.screen is not None
        services = Services(tool_checks=lambda checked: run_checks(checked, offline=True), count_files=_count_files)
        try:
            result = Setup(ui.prompter, environ=os.environ, config=config, profile=_profile(args), services=services).run()
        except CancelledError:
            return _cancelled(ui, "Setup stopped. Nothing was saved.")
        except ConfigError as error:
            ui.screen.print([[("✗  ", ui.theme.bad), (str(error), ui.theme.text)]])
            return EXIT_USAGE
        if result.audit is None:
            return EXIT_OK
        if result.key and not any(os.environ.get(name) for name in ("SENTRYTOWER_API_KEY", "OPENROUTER_API_KEY")):
            # A key that the person kept out of every file serves this process only.
            os.environ["SENTRYTOWER_API_KEY"] = result.key
        config = load_config(profile=_profile(args))
        ui.recolor(config)
        audit_args = build_parser().parse_args(["audit", str(result.audit)])
        audit_args.profile = _profile(args)
        return _audit_live(audit_args, ui, result.audit)


def _settings(args: argparse.Namespace) -> int:
    try:
        config = _config(args)
    except ConfigError as error:
        print(f"sentrytower: configuration error: {printable(str(error))}", file=sys.stderr)
        return EXIT_USAGE
    key, source = config.api_key()
    models = config.models
    distinct = sorted(set(models.values()))
    # The funnel has the higher price of a token, so its plan is the smaller one.
    plan = config.token_plan("funnel")
    cap = config.cost_cap("funnel")
    tokens = f"a plan of about {plan.tokens / 1_000_000:.0f}M tokens" if plan.source == "cost cap" else f"{plan.tokens:,} tokens"
    if plan.depth > 1:
        tokens += f" (depth {plan.depth:.2g}, {PREVIEW_LABEL})"
    rows = [
        ("agent", f"{config.ui.agent_name} ({config.ui.agent_color})"),
        ("endpoint", config.provider.base_url),
        ("key", f"found in {source}" if key else "not found: run sentrytower setup"),
        ("models", distinct[0] if len(distinct) == 1 else ", ".join(f"{role} {model}" for role, model in models.items())),
        ("budget", (f"cap ${cap:.2f}, " if cap else "no cost cap, ") + f"{tokens}, {config.budget.wall_clock_seconds // 60} min"),
        ("results", config.out_dir or f"./{DEFAULT_OUT}"),
        ("read from", ", ".join(config.sources)),
    ]
    ui = Ui(config)
    if not ui.interactive:
        for name, value in rows:
            print(f"{name:<12} {value}")
        return EXIT_OK
    from .ui.mascot import BADGE, art, beside

    lines = [[(f"{name:<12} ", ui.theme.dim), (value, ui.theme.text)] for name, value in rows]
    badge = art(ui.color, BADGE, ui.caps.color)
    with ui:
        assert ui.screen is not None
        footer = [("Change them with ", ui.theme.dim), ("sentrytower setup", ui.theme.bold), (".", ui.theme.dim)]
        ui.screen.print([*(beside(badge, lines, gap=3) if badge else lines), [], footer, []])
    return EXIT_OK


def _last(args: argparse.Namespace) -> int:
    from .ui.results import from_document, last_run, open_file, report_file, summary_lines
    from .ui.widgets import CancelledError, Choice

    record = last_run()
    folder = Path(str(record["out_dir"])) if record and record.get("out_dir") else None
    if folder is None or not (folder / "run.json").is_file():
        print("sentrytower: no audit yet; run sentrytower audit PATH", file=sys.stderr)
        return EXIT_USAGE
    try:
        # The folder can be in the audited repository: only its regular files count, never a link (output_files).
        files = output_files(folder)
    except AuditError as error:
        print(f"sentrytower: {printable(str(error))}", file=sys.stderr)
        return error.exit_code
    try:
        run = json.loads(files["run"].read_text())
        findings = from_document(json.loads(files["json"].read_text())) if "json" in files else []
    except (KeyError, OSError, ValueError):
        print(f"sentrytower: the outputs in {folder} cannot be read", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config()
    except ConfigError:
        config = Config(sources=("defaults",))
    ui = Ui(config)
    if not ui.interactive:
        print(f"{folder}: {len(findings)} findings, status {run.get('status')}")
        return EXIT_OK
    with ui:
        assert ui.screen is not None
        summary = summary_lines(
            findings, run, files, theme=ui.theme, caps=ui.caps, agent_name=ui.name, agent_color=ui.color, width=ui.screen.width
        )
        ui.screen.print(summary)
        report = report_file(files)
        if report is not None:
            try:
                ui.screen.print([[]])
                wanted = ui.prompter.select("Open the report?", [Choice(True, f"Open {report.name}"), Choice(False, "Done")]).value
                if wanted and not open_file(report):
                    ui.screen.print([[("  The report is at ", ui.theme.dim), (str(report), ui.theme.bold)]])
            except CancelledError:
                pass
    return EXIT_OK


def _doctor(args: argparse.Namespace) -> int:
    from .doctor import FAIL, render, run_checks

    try:
        config = _config(args)
    except ConfigError as error:
        print(f"sentrytower: configuration error: {printable(str(error))}", file=sys.stderr)
        return EXIT_USAGE
    ui = Ui(config, plain=args.plain or args.json or args.quiet)
    if ui.interactive:
        from .ui.checks import check_lines

        with ui:
            assert ui.screen is not None
            try:
                checks = ui.prompter.wait("Checking the tools, the key and the endpoint", lambda: run_checks(config, offline=args.offline))
            except Exception as error:  # noqa: BLE001 - doctor reports, it does not crash
                ui.screen.print(
                    [[("✗  ", ui.theme.bad), (f"doctor failed with an unexpected error ({type(error).__name__})", ui.theme.text)]]
                )
                return EXIT_ENVIRONMENT
            ui.screen.print([*check_lines(checks, ui.theme, ui.prompter.sym), []])
        return EXIT_ENVIRONMENT if any(check.status == FAIL for check in checks) else EXIT_OK
    try:
        checks = run_checks(config, offline=args.offline)
    except Exception as error:  # noqa: BLE001 - doctor reports, it does not crash
        print(f"sentrytower: doctor failed with an unexpected error ({type(error).__name__})", file=sys.stderr)
        return EXIT_ENVIRONMENT
    if not args.quiet:
        print(render(checks, as_json=args.json))
    return EXIT_ENVIRONMENT if any(check.status == FAIL for check in checks) else EXIT_OK


def _home(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    from .ui.home import home
    from .ui.results import last_run
    from .ui.widgets import CancelledError

    while True:
        try:
            config = load_config(profile=_profile(args))
        except ConfigError:
            config = Config(sources=("defaults",))
        ui = Ui(config)
        if not ui.interactive:
            parser.print_help()
            return EXIT_USAGE
        with ui:
            try:
                action = home(ui.prompter, config, profile=_profile(args), last=last_run())
            except CancelledError:
                return EXIT_OK
            if action == "audit":
                audit_args = parser.parse_args(["audit"])
                audit_args.profile = _profile(args)
                try:
                    path = _ask_folder(ui)
                except CancelledError:
                    continue
                return _audit_live(audit_args, ui, path)
        if action == "setup":
            return _setup(args)
        if action == "doctor":
            doctor_args = parser.parse_args(["doctor"])
            doctor_args.profile = _profile(args)
            _doctor(doctor_args)
            continue
        if action == "last":
            _last(args)
            continue
        if action == "settings":
            _settings(args)
            continue
        return EXIT_OK


def _version(args: argparse.Namespace) -> int:
    versions = {
        "sentrytower": __version__,
        "pi_coding_agent": PI_VERSION,
        "funnel": "v1.4",
        "agent_protocol": "agent-v2.4",
        "findings_schema": FINDINGS_SCHEMA_VERSION,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
    }
    if args.json:
        print(json.dumps(versions, indent=2))
    else:
        print(f"sentrytower {__version__} (funnel v1.4, agent protocol v2.4, Pi {PI_VERSION}, findings schema {FINDINGS_SCHEMA_VERSION})")
    return EXIT_OK


def _interrupt(number: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        try:
            return _home(parser, args)
        except KeyboardInterrupt:
            print("\nsentrytower: stopped", file=sys.stderr)
            return EXIT_INTERRUPTED
    if args.command == "audit":
        # SIGTERM (docker stop, a cancelled CI job) takes the path of Ctrl-C: the engine stops and the outputs are written.
        try:
            previous = signal.signal(signal.SIGTERM, _interrupt)
        except ValueError:  # not the main thread
            previous = None
        try:
            return _audit(args)
        finally:
            if previous is not None:
                signal.signal(signal.SIGTERM, previous)
    commands = {"setup": _setup, "settings": _settings, "last": _last, "doctor": _doctor, "version": _version}
    if args.command not in commands:
        parser.print_help()
        return EXIT_USAGE
    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        # A prompt turns Ctrl-C into a cancel; this is the rest (for example a check that hangs).
        print("\nsentrytower: stopped", file=sys.stderr)
        return EXIT_INTERRUPTED
