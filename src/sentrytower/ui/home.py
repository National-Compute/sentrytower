"""``sentrytower`` with no command in a terminal: the agent and a menu of what to do."""

from __future__ import annotations

from pathlib import Path

from .. import __version__
from ..config import Config, user_config_path
from .mascot import HERO, art, beside
from .term import PLAIN, Line
from .widgets import Choice, Prompter


def home(prompter: Prompter, config: Config, *, profile: str | None = None, last: dict | None = None) -> str:
    """Show the home screen; return the action: audit, setup, settings, doctor, last or quit."""
    theme, caps = prompter.theme, prompter.caps
    configured = user_config_path(profile).is_file() or any(source.startswith("file:") for source in config.sources)
    hero = art(config.ui.agent_color, HERO, caps.color)
    status = "ready to audit" if configured else "not set up yet"
    text: list[Line] = [
        [("SentryTower ", theme.bold), (__version__, theme.dim)],
        [(config.ui.agent_name, theme.name), (f" {prompter.sym.dot} {status}", theme.dim)],
        [],
        [("Security audits of source code by an AI agent.", PLAIN)],
        [("Findings with file, line and CWE, as JSON, SARIF and Markdown.", theme.dim)],
    ]
    block = beside(hero, text, gap=4, top=max(0, len(hero) // 2 - 3)) if hero else text
    prompter.intro([*block, []])
    choices = [
        Choice("audit", "Audit a repository", "the current folder or another one"),
        Choice("setup", "Set up models and budget", "about a minute", tag="start here" if not configured else ""),
        Choice("doctor", "Check my setup", "tools, key and endpoint"),
    ]
    if last and last.get("out_dir") and Path(str(last["out_dir"])).is_dir():
        choices.append(
            Choice("last", "Open the last report", f"{last.get('repository') or 'last run'}, {last.get('findings') or 0} findings")
        )
    if configured:
        choices.append(Choice("settings", "Show my settings"))
    choices.append(Choice("quit", "Quit"))
    default = 0 if configured else 1
    return str(
        prompter.select(
            "What would you like to do?",
            choices,
            default=default,
            hint=f"↑↓ move {prompter.sym.dot} enter choose {prompter.sym.dot} esc quit",
        ).value
    )
