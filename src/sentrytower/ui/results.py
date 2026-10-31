"""The results of an audit in the terminal: the findings by severity, the files and what to do next.

``summary_lines`` gives the summary of a finished run. ``remember`` keeps
the folder of the last run in ``~/.local/state/sentrytower/last-run.json``,
so ``sentrytower last`` shows it again. ``open_report`` opens the report of
a run in the browser (``report.html``, else ``report.md``) when this
computer has a screen for it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from ..findings import OutputFinding
from ..programs import which
from ..result import FAILURE_PREFIXES, PREVIEW_LABEL, result_lines
from .mascot import BADGE, art, beside
from .term import PLAIN, Caps, Line, cells, clip
from .theme import SEVERITY_ORDER, Theme
from .widgets import ASCII, Symbols, money, tilde, tokens_text

MAX_ROWS = 12
# The widest location column: a longer path loses its leading folders ("…/source/low.php:5").
LOCATION_CELLS = 34
LABELS = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "unknown": "INFO"}


def state_home(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    base = env.get("XDG_STATE_HOME") or str(Path(env.get("HOME") or Path.home()) / ".local" / "state")
    return Path(base) / "sentrytower"


def remember(out_dir: Path, run: dict[str, Any], environ: Mapping[str, str] | None = None) -> None:
    """Keep where the last run wrote its files (no finding, no code)."""
    path = state_home(environ) / "last-run.json"
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        record = {
            "out_dir": str(out_dir.resolve()),
            "repository": (run.get("repository") or {}).get("name"),
            "ended_at": run.get("ended_at"),
            "findings": (run.get("findings") or {}).get("count"),
        }
        path.write_text(json.dumps(record) + "\n")
    except OSError:
        pass


def last_run(environ: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    try:
        record = json.loads((state_home(environ) / "last-run.json").read_text())
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def duration_text(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"
    if seconds >= 60:
        return f"{seconds // 60} min {seconds % 60} s"
    return f"{seconds} s"


def _location(finding: OutputFinding) -> str:
    first = finding.location
    if first is None:
        return "(no location)"
    return f"{first.path}:{first.start_line}"


def short_location(location: str, width: int) -> str:
    """A location that fits ``width`` cells: whole leading folders give way to "…/" first, so the file and line stay."""
    if cells(location) <= width:
        return location
    parts = location.split("/")
    while len(parts) > 1:
        parts = parts[1:]
        candidate = "…/" + "/".join(parts)
        if cells(candidate) <= width:
            return candidate
    return "…" + location[-(width - 1) :]


def finding_rows(findings: list[OutputFinding], theme: Theme, width: int) -> list[Line]:
    """The rows of the findings by severity: the standard run first, then the further findings of a deeper run (tier 2)."""
    ordered = sorted(
        findings,
        key=lambda item: (item.tier == 2, SEVERITY_ORDER.index(item.severity) if item.severity in SEVERITY_ORDER else 9, item.rank),
    )
    shown = ordered[:MAX_ROWS]
    locations = [short_location(_location(item), LOCATION_CELLS) for item in shown]
    location_width = max((cells(location) for location in locations), default=0)
    rows: list[Line] = []
    labelled = False
    for finding, location in zip(shown, locations, strict=True):
        if finding.tier == 2 and not labelled:
            labelled = True
            rows.append([(f"  More findings ({PREVIEW_LABEL}):", theme.dim)])
        cwe = finding.cwe[0] if finding.cwe else "CWE-?"
        line: Line = [
            (f" {LABELS.get(finding.severity, 'INFO'):<4} ", theme.severity(finding.severity)),
            ("  ", PLAIN),
            (f"{cwe:<8} ", theme.dim),
            (location + " " * (location_width - cells(location)) + "  ", PLAIN),
            (finding.title, theme.bold),
        ]
        rows.append(clip(line, width))
    if len(ordered) > len(shown):
        rows.append([(f"  … and {len(ordered) - len(shown)} more in the report", theme.dim)])
    return rows


def summary_lines(
    findings: list[OutputFinding],
    run: dict[str, Any],
    files: Mapping[str, Path],
    *,
    theme: Theme,
    caps: Caps,
    agent_name: str,
    agent_color: str,
    width: int,
    shown_warnings: list[str] | None = None,
) -> list[Line]:
    """The final screen of a run."""
    sym = Symbols() if caps.unicode else ASCII
    usage = (run.get("usage") or {}).get("total") or {}
    repository = (run.get("repository") or {}).get("name") or "the repository"
    status = run.get("status")
    count = len(findings)
    if status == "complete" and count:
        issues = f"{count} issue{'s' if count != 1 else ''}"
        headline: Line = [(agent_name, theme.name), (" found ", PLAIN), (issues, theme.bold), (" in ", PLAIN), (repository, theme.bold)]
    elif status == "complete":
        headline = [(agent_name, theme.name), (" found no issue in ", PLAIN), (repository, theme.bold)]
    elif status == "interrupted":
        headline = [
            (agent_name, theme.name),
            (" stopped early: ", PLAIN),
            (f"{count} finding{'s' if count != 1 else ''} so far", theme.bold),
        ]
    else:
        headline = [(agent_name, theme.name), (" could not finish the audit of ", PLAIN), (repository, theme.bold)]
    facts = [duration_text(float(run.get("seconds") or 0)), f"{tokens_text(usage.get('total_tokens'))} tokens"]
    if isinstance(usage.get("cost_usd"), (int, float)):
        facts.append(money(usage["cost_usd"]))
    facts.append("funnel engine" if run.get("route") == "funnel" else "single-agent engine")
    header = [headline, [(f" {sym.dot} ".join(facts), theme.dim)]]
    result = run.get("result") if isinstance(run.get("result"), dict) else None
    if status not in ("complete", "interrupted") and run.get("failure"):
        header.append([(f"{sym.warning} ", theme.caution), (str(run["failure"])[:200], PLAIN)])
    # The spend, why the run stopped, the checked units and the depth: the sentences of each output (result.result_lines);
    # the header shows the failure.
    sentences = [line for line in result_lines(result) if not line.startswith(FAILURE_PREFIXES)] if result is not None else []
    left = art(agent_color, BADGE, caps.color)
    lines = beside(left, header, gap=3, top=max(0, (len(left) - len(header)) // 2)) if left else header
    lines.append([])
    for sentence in sentences:
        lines.append([("  " + sentence, theme.dim)])
    if sentences:
        lines.append([])
    if findings:
        lines += finding_rows(findings, theme, width - 2)
    elif status == "complete":
        lines.append([("  An empty result is not proof that the code is safe.", theme.dim)])
    lines.append([])
    if files:
        folder = next(iter(files.values())).parent
        names = " · ".join(path.name for path in files.values()) if caps.unicode else ", ".join(path.name for path in files.values())
        lines.append([("  Saved to ", theme.dim), (tilde(folder, from_cwd=True), theme.bold), (": " + names, theme.dim)])
    for warning in run.get("warnings") or []:
        if warning not in (shown_warnings or []):
            lines.append([(f"  {sym.warning} ", theme.caution), (str(warning), PLAIN)])
    if findings:
        lines.append([("  Each finding is a claim of a language model: confirm it in the code before you act on it.", theme.dim)])
    return lines


def report_file(files: Mapping[str, Path]) -> Path | None:
    """The report of a run for people: report.html, else report.md."""
    return files.get("html") or files.get("markdown")


def can_open(environ: Mapping[str, str] | None = None) -> bool:
    """Whether a file that this process opens shows on a screen of the person.

    Not in CI, not in an SSH session, and on Linux only with a graphical
    session (DISPLAY or WAYLAND_DISPLAY).
    """
    env = os.environ if environ is None else environ
    if env.get("CI") or env.get("SSH_CONNECTION") or env.get("SSH_TTY"):
        return False
    if sys.platform == "darwin":
        return True
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def open_file(path: Path) -> bool:
    """Open a file in the default application (macOS open, xdg-open): report.html opens in the browser.

    The opener comes from the absolute entries of PATH only (``programs.which``):
    the folder of this process can be the audited repository.
    """
    opener = which("open" if sys.platform == "darwin" else "xdg-open")
    if opener is None:
        return False
    try:
        subprocess.Popen([opener, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return False
    time.sleep(0.2)
    return True


def from_document(document: Any) -> list[OutputFinding]:
    """The findings of a ``findings.json`` document (for ``sentrytower last``)."""
    from ..findings import OutputLocation

    out: list[OutputFinding] = []
    for item in (document or {}).get("findings") or []:
        if not isinstance(item, dict):
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else None
        locations = (
            [OutputLocation(str(location.get("path")), int(location.get("start_line") or 1), int(location.get("end_line") or 1))]
            if location
            else []
        )
        given = item.get("verification")
        verification: dict[str, Any] = given if isinstance(given, dict) else {}
        finding = OutputFinding(
            rank=int(item.get("rank") or len(out) + 1),
            title=str(item.get("title") or ""),
            severity=str(item.get("severity") or "unknown"),
            cwe=[str(value) for value in item.get("cwe") or []],
            locations=locations,
            evidence=str(item.get("evidence") or ""),
            exploit_conditions=str(item.get("exploit_conditions") or ""),
            engine=str(item.get("engine") or ""),
            route=str(item.get("route") or ""),
            tier=2 if item.get("tier") == 2 else 1,
            verification_status=str(verification.get("status") or "none"),
            verification_reason=str(verification["reason"]) if verification.get("reason") else None,
        )
        out.append(finding)
    return out
