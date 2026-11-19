"""The findings of a run as a Markdown report (``report.md``) for people; ``html_report`` writes the web page.

The report gives the result of the run (the spend, why it stopped, the
checked units), the findings of the standard run, and after them the
further findings of a deeper run (tier 2) under the preview label.

The titles, explanations, paths and notes of the findings are text of a
model that read the audited repository, so an attacker can write them. The
report escapes each of them: a Markdown viewer (GitHub, an IDE preview, a CI
summary) shows them as text and renders no HTML, link text, image, heading,
list, quote or table cell of them. GitHub links a bare URL, which shows its
address, and draws text between two dollar signs as a formula also when the
dollar signs are escaped. Inline code and fenced code blocks of an
explanation stay code, with no language label.
"""

from __future__ import annotations

import re
from typing import Any

from . import __version__
from .agent.answer import CONDITIONS_LABEL
from .findings import OutputFinding, severity_counts
from .result import PREVIEW_LABEL, result_lines
from .ui.term import printable_text

ENGINE_NAMES = {
    "free-roaming": "funnel, free-roaming agent",
    "deep-check": "funnel, deep check",
    "single-agent": "single agent",
}


# Each character that can start inline Markdown or HTML: escapes, code, emphasis, strikethrough, links and
# images, HTML tags and autolinks, entities, table cells and math ("\$"; GitHub's formulas ignore the escape).
_INLINE_MARKUP = re.compile(r"([\\`*_~\[\]<>&|$])")
# What makes a line a heading, a list item, a setext underline or a thematic break ("*", "_" and ">" are inline markup).
_LINE_START = re.compile(r"^(?:([#+=-])|(\d{1,9})([.)]))")
_INLINE_CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_FENCE = re.compile(r"^```[^\n`]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)


def _escape(text: str) -> str:
    return _INLINE_MARKUP.sub(r"\\\1", text)


def _code(text: str, *, table: bool = False) -> str:
    """Untrusted text as one inline code span: the delimiter is longer than each run of backticks in the text."""
    text = " ".join(text.split())
    if table and ("|" in text or "\\" in text):
        # A table splits its cells at each pipe before it reads code spans, and a backslash can unescape a pipe.
        return _escape(text)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    delimiter = "`" * (longest + 1)
    padded = f" {text} " if text.startswith("`") or text.endswith("`") else text
    return delimiter + padded + delimiter


def markdown_text(text: str, *, table: bool = False) -> str:
    """Untrusted text as one line of literal Markdown text; its inline code stays code."""
    return _line(" ".join(text.split()), table=table)


def _line(text: str, *, table: bool = False) -> str:
    """One line of untrusted text, without white space at its ends, as literal Markdown text."""
    parts: list[str] = []
    position = 0
    for match in _INLINE_CODE.finditer(text):
        parts += [_escape(text[position : match.start()]), _code(match.group(1), table=table)]
        position = match.end()
    parts.append(_escape(text[position:]))
    return _LINE_START.sub(lambda match: f"\\{match[1]}" if match[1] else f"{match[2]}\\{match[3]}", "".join(parts))


def _cell(text: str) -> str:
    return markdown_text(text, table=True)


def _paragraphs(text: str) -> list[str]:
    """Untrusted text of several lines as Markdown blocks: escaped paragraphs and fenced code blocks.

    Each line of a paragraph ends with a hard line break, so the lines of the
    model stay lines. A code block has no language label: GitHub renders the
    labels ``mermaid``, ``geojson``, ``topojson``, ``stl`` and ``math`` as
    diagrams, maps, models and formulas.
    """
    blocks: list[str] = []

    def prose(part: str) -> None:
        for paragraph in re.split(r"\n[ \t]*\n", part):
            lines = [_line(line.strip()) for line in paragraph.split("\n") if line.strip()]
            if lines:
                blocks.append("  \n".join(lines))

    position = 0
    for match in _FENCE.finditer(text):
        prose(text[position : match.start()])
        code = match.group(1).rstrip()
        longest = max((len(run) for run in re.findall(r"`+", code)), default=0)
        fence = "`" * max(3, longest + 1)
        blocks.append(f"{fence}\n{code}\n{fence}")
        position = match.end()
    prose(text[position:])
    return blocks


def _location_text(finding: OutputFinding, *, table: bool = False) -> str:
    first = finding.location
    if first is None:
        return "(no location)"
    lines = f"{first.start_line}" if first.start_line == first.end_line else f"{first.start_line}-{first.end_line}"
    return _code(f"{first.path}:{lines}", table=table)


def _number(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else "n/a"


def _findings_part(findings: list[OutputFinding]) -> list[str]:
    """A findings table and the details of each finding."""
    lines = ["| # | Severity | CWE | Location | Title | Engine |", "| --- | --- | --- | --- | --- | --- |"]
    for finding in findings:
        lines.append(
            f"| {finding.rank} | {_cell(finding.severity)} | {_cell(', '.join(finding.cwe)) or '-'} | "
            f"{_location_text(finding, table=True)} | {_cell(finding.title)} | {_cell(ENGINE_NAMES.get(finding.engine, finding.engine))} |"
        )
    lines.append("")
    for finding in findings:
        lines += [f"### {markdown_text(finding.id)}: {markdown_text(finding.title)}", ""]
        lines.append(
            f"- Severity: **{markdown_text(finding.severity)}**"
            + (f"; CWE: {markdown_text(', '.join(finding.cwe))}" if finding.cwe else "")
        )
        lines.append(f"- Location: {_location_text(finding)}")
        for location in finding.locations[1:]:
            span = f"{location.start_line}" if location.start_line == location.end_line else f"{location.start_line}-{location.end_line}"
            note = f" ({markdown_text(location.note)})" if location.note else ""
            lines.append(f"- Related: {_code(f'{location.path}:{span}')}{note}")
        engine = markdown_text(ENGINE_NAMES.get(finding.engine, finding.engine))
        if finding.confidence is not None:
            engine += f"; model review score {finding.confidence:.2f}"
        lines.append(f"- Engine: {engine}")
        label = finding.verification_label()
        if label:
            lines.append(f"- Verification: {markdown_text(label)}")
        lines.append("")
        for block in _paragraphs(finding.evidence):
            lines += [block, ""]
        conditions = _paragraphs(finding.exploit_conditions)
        if conditions and not conditions[0].startswith("`"):
            conditions[0] = f"**{CONDITIONS_LABEL}.** {conditions[0]}"
        elif conditions:
            conditions.insert(0, f"**{CONDITIONS_LABEL}.**")
        for block in conditions:
            lines += [block, ""]
    return lines


#: How a finding is known. Each report states it under its headline.
CLAIM = "Each finding is a claim of a language model. Confirm it in the code before you act on it."
#: What an empty result covers.
EMPTY = (
    "This is not proof that the code is safe: the engines read a part of the code within a budget, "
    "and a language model can miss a vulnerability."
)


def markdown_report(findings: list[OutputFinding], run: dict[str, Any]) -> str:
    """The report: the run summary, a findings table and the details of each finding."""
    counts = severity_counts(findings)
    usage = (run.get("usage") or {}).get("total") or {}
    repository = run.get("repository") or {}
    lines = [
        "# SentryTower security audit",
        "",
        *([CLAIM, ""] if findings else [f"SentryTower reported no finding. {EMPTY}", ""]),
        f"- Repository: {_code(str(repository.get('name') or 'repository'))} ({_number(repository.get('files_counted'))} files counted"
        f"{'' if repository.get('files_counted', 0) <= repository.get('counted_up_to', 0) - 1 else ' or more'})",
        f"- Route: **{markdown_text(str(run.get('route')))}** ({'funnel engine' if run.get('route') == 'funnel' else 'single-agent engine'})",
        f"- Models: {', '.join(_code(str(model)) for model in sorted(set((run.get('models') or {}).values()))) or 'n/a'}",
        f"- Tokens: {_number(usage.get('total_tokens'))}"
        + (
            f"; cost: \\${usage['cost_usd']:.4f} ({markdown_text(str(usage.get('cost_source')))})"
            if isinstance(usage.get("cost_usd"), (int, float))
            else ""
        ),
        f"- Duration: {run.get('seconds', 0):.0f} s; stop: {markdown_text(str(run.get('stop') or 'n/a'))}",
        f"- Findings: {len(findings)} ("
        + ", ".join(f"{counts[name]} {name}" for name in ("critical", "high", "medium", "low", "unknown") if counts[name])
        + (")" if findings else "none)"),
        "",
    ]
    if isinstance(run.get("result"), dict):
        # The spend, why the run stopped and the checked units: the sentences of each output (result.result_lines).
        lines += ["## Result", "", *(f"- {markdown_text(line)}" for line in result_lines(run["result"])), ""]
    if findings:
        first = [finding for finding in findings if finding.tier != 2]
        more = [finding for finding in findings if finding.tier == 2]
        lines += ["## Findings", ""]
        lines += _findings_part(first) if first else ["The standard run of the audit reported no vulnerability.", ""]
        if more:
            lines += [
                f"## More findings ({PREVIEW_LABEL})",
                "",
                "The deeper checks of this run found these findings after the findings of the standard run. A second model "
                "call reviewed each one, unless a finding says otherwise.",
                "",
                *_findings_part(more),
            ]
    lines += [
        "---",
        "",
        f"Generated by SentryTower {__version__}. The findings files are `findings.json` and `findings.sarif`.",
        "",
    ]
    # The findings are text of a model that read untrusted code: no control character of it reaches a terminal that shows the file.
    return printable_text("\n".join(lines))
