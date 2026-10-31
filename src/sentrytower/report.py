"""The findings of a run as a Markdown report (``report.md``) for people; ``html_report`` writes the web page.

The report gives the result of the run (the spend, why it stopped, the
checked units), the findings of the standard run, and after them the
further findings of a deeper run (tier 2) under the preview label.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .findings import OutputFinding, severity_counts
from .result import PREVIEW_LABEL, result_lines
from .ui.term import printable_text

ENGINE_NAMES = {
    "free-roaming": "funnel, free-roaming agent",
    "deep-check": "funnel, deep check",
    "single-agent": "single agent",
}


def _cell(text: str) -> str:
    return " ".join(text.replace("|", "\\|").split())


def _location_text(finding: OutputFinding) -> str:
    first = finding.location
    if first is None:
        return "(no location)"
    lines = f"{first.start_line}" if first.start_line == first.end_line else f"{first.start_line}-{first.end_line}"
    return f"`{first.path}:{lines}`"


def _number(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else "n/a"


def _findings_part(findings: list[OutputFinding]) -> list[str]:
    """A findings table and the details of each finding."""
    lines = ["| # | Severity | CWE | Location | Title | Engine |", "| --- | --- | --- | --- | --- | --- |"]
    for finding in findings:
        lines.append(
            f"| {finding.rank} | {finding.severity} | {', '.join(finding.cwe) or '-'} | {_location_text(finding)} | "
            f"{_cell(finding.title)} | {ENGINE_NAMES.get(finding.engine, finding.engine)} |"
        )
    lines.append("")
    for finding in findings:
        lines += [f"### {finding.id}: {finding.title}", ""]
        lines.append(f"- Severity: **{finding.severity}**" + (f"; CWE: {', '.join(finding.cwe)}" if finding.cwe else ""))
        lines.append(f"- Location: {_location_text(finding)}")
        for location in finding.locations[1:]:
            span = f"{location.start_line}" if location.start_line == location.end_line else f"{location.start_line}-{location.end_line}"
            note = f" ({_cell(location.note)})" if location.note else ""
            lines.append(f"- Related: `{location.path}:{span}`{note}")
        engine = ENGINE_NAMES.get(finding.engine, finding.engine)
        if finding.confidence is not None:
            engine += f"; verification score {finding.confidence:.2f}"
        lines.append(f"- Engine: {engine}")
        label = finding.verification_label()
        if label:
            lines.append(f"- Verification: {_cell(label)}")
        lines.append("")
        if finding.evidence.strip():
            lines += [finding.evidence.strip(), ""]
        if finding.exploit_conditions.strip():
            lines += [f"**Exploit conditions.** {finding.exploit_conditions.strip()}", ""]
    return lines


def markdown_report(findings: list[OutputFinding], run: dict[str, Any]) -> str:
    """The report: the run summary, a findings table and the details of each finding."""
    counts = severity_counts(findings)
    usage = (run.get("usage") or {}).get("total") or {}
    repository = run.get("repository") or {}
    lines = [
        "# SentryTower security audit",
        "",
        f"- Repository: `{repository.get('name') or 'repository'}` ({_number(repository.get('files_counted'))} files counted"
        f"{'' if repository.get('files_counted', 0) <= repository.get('counted_up_to', 0) - 1 else ' or more'})",
        f"- Route: **{run.get('route')}** ({'funnel engine' if run.get('route') == 'funnel' else 'single-agent engine'})",
        f"- Models: {', '.join(f'`{model}`' for model in sorted(set((run.get('models') or {}).values()))) or 'n/a'}",
        f"- Tokens: {_number(usage.get('total_tokens'))}"
        + (f"; cost: ${usage['cost_usd']:.4f} ({usage.get('cost_source')})" if isinstance(usage.get("cost_usd"), (int, float)) else ""),
        f"- Duration: {run.get('seconds', 0):.0f} s; stop: {run.get('stop') or 'n/a'}",
        f"- Findings: {len(findings)} ("
        + ", ".join(f"{counts[name]} {name}" for name in ("critical", "high", "medium", "low", "unknown") if counts[name])
        + (")" if findings else "none)"),
        "",
    ]
    if isinstance(run.get("result"), dict):
        # The spend, why the run stopped and the checked units: the sentences of each output (result.result_lines).
        lines += ["## Result", "", *(f"- {_cell(line)}" for line in result_lines(run["result"])), ""]
    if not findings:
        lines += [
            "SentryTower reported no vulnerability. This is not a proof that the code is safe: the engines read",
            "a part of the code within a budget, and a language model can miss a vulnerability.",
            "",
        ]
    else:
        first = [finding for finding in findings if finding.tier != 2]
        more = [finding for finding in findings if finding.tier == 2]
        lines += ["## Findings", ""]
        lines += _findings_part(first) if first else ["The standard run of the audit reported no vulnerability.", ""]
        if more:
            lines += [
                f"## More findings ({PREVIEW_LABEL})",
                "",
                "The deeper checks of this run found these findings after the findings of the standard run. They are "
                "verified, unless a finding says otherwise.",
                "",
                *_findings_part(more),
            ]
    lines += [
        "---",
        "",
        f"Generated by SentryTower {__version__}. Each finding is a claim of a language model: confirm it in the",
        "code before you act on it. The findings files are `findings.json` and `findings.sarif`.",
        "",
    ]
    # The findings are text of a model that read untrusted code: no control character of it reaches a terminal that shows the file.
    return printable_text("\n".join(lines))
