"""The findings of a run as a web page (``report.html``) for people.

The page is one self-contained file: the styles are inline, it loads
nothing and runs no script (its Content-Security-Policy forbids both). It
reads on light and dark screens and prints on paper. All text from the run,
the model or the repository is escaped. The explanation of a finding keeps a
small, safe part of Markdown: code blocks, inline code, bold text, lists and
paragraphs.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any

from . import __version__
from .findings import SEVERITY_ORDER, OutputFinding, severity_counts
from .report import CLAIM, EMPTY, ENGINE_NAMES
from .result import PREVIEW_LABEL, result_lines
from .ui.mascot import BADGE, pixels
from .ui.theme import AGENT_COLORS, DEFAULT_AGENT_COLOR

SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "unknown": "Info"}
CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
_FENCE = re.compile(r"^```[^\n`]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")
_BULLET = re.compile(r"^\s*[-*]\s+")
_NUMBERED = re.compile(r"^\s*\d+[.)]\s+")
_CWE = re.compile(r"^CWE-(\d{1,6})$")

STYLE = """
:root {
  --bg: #f6f5f2; --panel: #ffffff; --text: #1d1d22; --muted: #5f5f6b; --line: #e3e1db; --code: #f0eee9;
  --critical: #c92a2a; --high: #d9480f; --medium: #b07d00; --low: #3b5bdb; --unknown: #6b6b76;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131317; --panel: #1c1c22; --text: #ececf1; --muted: #a3a3b0; --line: #2e2e37; --code: #24242c;
    --critical: #ff6b6b; --high: #ff8a5c; --medium: #f2c14e; --low: #8fb3ff; --unknown: #a8a8b3;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 48px; }
a { color: var(--accent-text); }
code, pre { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
code { background: var(--code); padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: var(--code); padding: 12px 14px; border-radius: 8px; overflow-x: auto; }
pre code { background: none; padding: 0; }
header.top { display: flex; gap: 20px; align-items: center; margin-bottom: 24px; }
header.top svg { width: 56px; height: 64px; flex: none; image-rendering: pixelated; }
.brand { color: var(--muted); font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }
h1 { font-size: 26px; line-height: 1.25; margin: 4px 0 0; }
.known { margin: 6px 0 0; }
h1 .agent { color: var(--accent-text); }
h2 { font-size: 18px; margin: 32px 0 12px; }
h2 small { color: var(--muted); font-weight: 600; font-size: 13px; }
.facts { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); margin: 0; background: var(--panel);
  border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.facts div { padding: 10px 14px; box-shadow: 1px 0 0 var(--line), 0 1px 0 var(--line); }
.facts dt { color: var(--muted); font-size: 12px; }
.facts dd { margin: 2px 0 0; font-weight: 600; overflow-wrap: anywhere; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 20px 0 0; padding: 0; list-style: none; }
.counts li { border: 1px solid var(--line); background: var(--panel); border-radius: 999px; padding: 4px 12px; font-size: 14px; }
.counts b { color: var(--sev); }
.note { border-left: 4px solid var(--accent); background: var(--panel); padding: 12px 16px; border-radius: 6px; margin: 20px 0 0; }
.note.bad { border-color: var(--critical); }
.note ul { margin: 6px 0 0; padding-left: 20px; }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  overflow: hidden; font-size: 14px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; }
tr:last-child td { border-bottom: none; }
td.where { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.sev { display: inline-block; min-width: 64px; text-align: center; font-size: 12px; font-weight: 700; color: #fff;
  background: var(--sev); border-radius: 999px; padding: 1px 8px; }
@media (prefers-color-scheme: dark) { .sev { color: #141418; } }
.critical { --sev: var(--critical); } .high { --sev: var(--high); } .medium { --sev: var(--medium); }
.low { --sev: var(--low); } .unknown { --sev: var(--unknown); }
article { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--sev); border-radius: 10px;
  padding: 16px 20px; margin: 0 0 16px; }
article h3 { margin: 0 0 8px; font-size: 17px; line-height: 1.35; }
article h3 small { color: var(--muted); font-weight: 600; margin-right: 6px; }
article .meta { display: flex; flex-wrap: wrap; gap: 6px 16px; color: var(--muted); font-size: 13px; margin-bottom: 8px; }
article ul.where { list-style: none; padding: 0; margin: 8px 0; }
article ul.where li { margin: 2px 0; }
article .label { font-weight: 700; }
footer { color: var(--muted); font-size: 13px; margin-top: 40px; border-top: 1px solid var(--line); padding-top: 16px; }
@media print {
  body { background: #fff; color: #000; } main { max-width: none; padding: 0; }
  article, table, .facts div, .counts li, .note { background: #fff; break-inside: avoid; }
}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _inline(text: str) -> str:
    """Escaped text with inline code and bold text."""
    escaped = _e(text)
    escaped = _INLINE_CODE.sub(lambda match: f"<code>{match.group(1)}</code>", escaped)
    return _BOLD.sub(lambda match: f"<strong>{match.group(1)}</strong>", escaped)


def _blocks(text: str) -> list[str]:
    """Paragraphs and lists of a text without code blocks."""
    out: list[str] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        # Model text splits on "\n" only: U+2028 and the other separators of str.splitlines stay in their line.
        lines = [line.rstrip("\r") for line in block.split("\n") if line.strip()]
        if not lines:
            continue
        for pattern, tag in ((_BULLET, "ul"), (_NUMBERED, "ol")):
            if all(pattern.match(line) for line in lines):
                items = "".join(f"<li>{_inline(pattern.sub('', line, count=1))}</li>" for line in lines)
                out.append(f"<{tag}>{items}</{tag}>")
                break
        else:
            out.append("<p>" + "<br>".join(_inline(line.strip()) for line in lines) + "</p>")
    return out


def rich_text(text: str) -> str:
    """A text of the model as safe HTML: code blocks, inline code, bold text, lists and paragraphs."""
    parts: list[str] = []
    position = 0
    for match in _FENCE.finditer(text):
        parts += _blocks(text[position : match.start()])
        parts.append(f"<pre><code>{_e(match.group(1).rstrip())}</code></pre>")
        position = match.end()
    parts += _blocks(text[position:])
    return "\n".join(parts)


def _span(start: int, end: int) -> str:
    return f"{start}" if start == end else f"{start}-{end}"


def _cwe_links(values: list[str]) -> str:
    links = []
    for value in values:
        match = _CWE.match(value)
        if match:
            url = f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
            links.append(f'<a href="{url}" rel="noopener noreferrer">{_e(value)}</a>')
        else:
            links.append(_e(value))
    return ", ".join(links)


def agent_svg(color: str) -> str:
    """The agent's pixel art as an inline SVG: one rectangle for each run of pixels of one colour."""
    grid = pixels(color, BADGE)
    rects = []
    for y, row in enumerate(grid):
        x = 0
        while x < len(row):
            pixel = row[x]
            run = 1
            while x + run < len(row) and row[x + run] == pixel:
                run += 1
            if pixel is not None:
                rects.append(f'<rect x="{x}" y="{y}" width="{run}" height="1" fill="#{pixel[0]:02x}{pixel[1]:02x}{pixel[2]:02x}"/>')
            x += run
    width, height = len(grid[0]) if grid else 0, len(grid)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" shape-rendering="crispEdges" '
        f'role="img" aria-label="the agent">{"".join(rects)}</svg>'
    )


def _when(text: Any) -> str:
    try:
        return datetime.fromisoformat(str(text)).strftime("%Y-%m-%d %H:%M %Z").strip()
    except ValueError:
        return "n/a"


def _duration(seconds: Any) -> str:
    value = int(seconds or 0)
    if value >= 3600:
        return f"{value // 3600} h {value % 3600 // 60} min"
    if value >= 60:
        return f"{value // 60} min {value % 60} s"
    return f"{value} s"


def _tokens(value: Any) -> str:
    if not isinstance(value, int):
        return "n/a"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    return f"{value / 1000:.0f}k" if value >= 1000 else str(value)


def _finding(finding: OutputFinding) -> str:
    severity = finding.severity if finding.severity in SEVERITY_LABELS else "unknown"
    meta = [f'<span class="sev">{SEVERITY_LABELS[severity]}</span>']
    if finding.cwe:
        meta.append(f"<span>{_cwe_links(finding.cwe)}</span>")
    engine = ENGINE_NAMES.get(finding.engine, finding.engine)
    meta.append(f"<span>{_e(engine)}</span>")
    if finding.confidence is not None:
        meta.append(f"<span>model review score {finding.confidence:.2f}</span>")
    label = finding.verification_label()
    if label:
        meta.append(f'<span class="label">{_e(label)}</span>')
    places = []
    for index, location in enumerate(finding.locations):
        label = "Location" if index == 0 else "Related"
        note = f" ({_e(location.note)})" if location.note else ""
        places.append(
            f'<li><span class="label">{label}:</span> <code>{_e(location.path)}:{_span(location.start_line, location.end_line)}</code>{note}</li>'
        )
    if not places:
        places.append('<li><span class="label">Location:</span> none given</li>')
    body = [
        f'<article id="{finding.id}" class="{severity}">',
        f"<h3><small>{finding.id}</small>{_e(finding.title)}</h3>",
        f'<div class="meta">{"".join(meta)}</div>',
        f'<ul class="where">{"".join(places)}</ul>',
    ]
    if finding.evidence.strip():
        body.append(rich_text(finding.evidence))
    if finding.exploit_conditions.strip():
        body.append('<p><span class="label">Exploit conditions.</span></p>')
        body.append(rich_text(finding.exploit_conditions))
    body.append("</article>")
    return "\n".join(body)


def _table(findings: list[OutputFinding]) -> list[str]:
    rows = []
    for finding in findings:
        severity = finding.severity if finding.severity in SEVERITY_LABELS else "unknown"
        first = finding.location
        where = f"{_e(first.path)}:{_span(first.start_line, first.end_line)}" if first else "none"
        rows.append(
            f'<tr class="{severity}"><td>{finding.id}</td><td><span class="sev">{SEVERITY_LABELS[severity]}</span></td>'
            f'<td>{_cwe_links(finding.cwe) or "-"}</td><td class="where">{where}</td>'
            f'<td><a href="#{finding.id}">{_e(finding.title)}</a></td></tr>'
        )
    return [
        "<table><thead><tr><th>ID</th><th>Severity</th><th>CWE</th><th>Location</th><th>Title</th></tr></thead>",
        "<tbody>" + "".join(rows) + "</tbody></table>",
    ]


def html_report(findings: list[OutputFinding], run: dict[str, Any]) -> str:
    """The report as one HTML page: the summary of the run, a table of the findings and each finding in full.

    The findings come by severity, then in their rank order, as on the results screen of the terminal: the
    findings of the standard run first, then the further findings of a deeper run (tier 2) under the preview label.
    """
    agent = ((run.get("configuration") or {}).get("agent")) or {}
    color = str(agent.get("color")) if agent.get("color") in AGENT_COLORS else DEFAULT_AGENT_COLOR
    name = str(agent.get("name") or "Juno")
    _, light, base, dark = AGENT_COLORS[color]
    repository = run.get("repository") or {}
    repo_name = str(repository.get("name") or "the repository")
    usage = (run.get("usage") or {}).get("total") or {}
    status = run.get("status")
    count = len(findings)
    findings = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, len(SEVERITY_ORDER)), item.rank))
    if status == "complete":
        headline = (
            f'<span class="agent">{_e(name)}</span> found {count} issue{"s" if count != 1 else ""} in {_e(repo_name)}'
            if count
            else f'<span class="agent">{_e(name)}</span> reported no finding in {_e(repo_name)}'
        )
    elif status == "interrupted":
        headline = f'<span class="agent">{_e(name)}</span> stopped early: {count} finding{"s" if count != 1 else ""} so far'
    else:
        headline = f'<span class="agent">{_e(name)}</span> could not finish the audit of {_e(repo_name)}'
    files = repository.get("files_counted")
    more = isinstance(files, int) and files >= (repository.get("counted_up_to") or 0) > 0
    cost = usage.get("cost_usd")
    facts = [
        ("Repository", repo_name),
        ("Files", f"{files:,}{'+' if more else ''}" if isinstance(files, int) else "n/a"),
        ("Engine", "funnel" if run.get("route") == "funnel" else "single agent"),
        ("Models", ", ".join(sorted(set((run.get("models") or {}).values()))) or "n/a"),
        ("Tokens", _tokens(usage.get("total_tokens"))),
        ("Cost", f"${cost:.2f}" if isinstance(cost, (int, float)) else "n/a"),
        ("Duration", _duration(run.get("seconds"))),
        ("Finished", _when(run.get("ended_at"))),
    ]
    # How the result is known, under the headline: what a finding is, or what an empty result covers.
    if findings:
        known = f'<p class="known">{CLAIM}</p>'
    elif status == "complete":
        known = f'<p class="known">{EMPTY}</p>'
    else:
        known = ""
    counts = severity_counts(findings)
    chips = "".join(
        f'<li class="{severity}"><b>{counts[severity]}</b> {SEVERITY_LABELS[severity].lower()}</li>'
        for severity in SEVERITY_LABELS
        if counts[severity]
    )
    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>SentryTower audit of {_e(repo_name)}</title>",
        f"<style>{STYLE}:root {{ --accent: rgb{base}; --accent-text: rgb{dark}; }}\n"
        f"@media (prefers-color-scheme: dark) {{ :root {{ --accent-text: rgb{light}; }} }}</style>",
        "</head>",
        "<body>",
        "<main>",
        '<header class="top">',
        agent_svg(color),
        f'<div><div class="brand">SentryTower security audit</div><h1>{headline}</h1>{known}</div>',
        "</header>",
        '<dl class="facts">' + "".join(f"<div><dt>{label}</dt><dd>{_e(value)}</dd></div>" for label, value in facts) + "</dl>",
    ]
    if chips:
        parts.append(f'<ul class="counts">{chips}</ul>')
    result = run.get("result")
    if isinstance(result, dict):
        # The spend, why the run stopped and the checked units: the sentences of each output (result.result_lines).
        bad = " bad" if status not in ("complete", "interrupted") else ""
        items = "".join(f"<li>{_e(line)}</li>" for line in result_lines(result))
        parts.append(f'<div class="note{bad}"><b>{"The audit did not finish." if bad else "Result"}</b><ul>{items}</ul></div>')
    elif status not in ("complete", "interrupted") and run.get("failure"):
        parts.append(f'<div class="note bad"><b>The audit did not finish.</b> {_e(run["failure"])}</div>')
    warnings = [str(item) for item in run.get("warnings") or []]
    if warnings:
        parts.append('<div class="note"><b>Warnings</b><ul>' + "".join(f"<li>{_e(item)}</li>" for item in warnings) + "</ul></div>")
    if findings:
        first = [finding for finding in findings if finding.tier != 2]
        more = [finding for finding in findings if finding.tier == 2]
        parts += ["<h2>Findings</h2>", *(_table(first) if first else ["<p>The standard run of the audit reported no vulnerability.</p>"])]
        if more:
            parts += [
                f"<h2>More findings <small>({_e(PREVIEW_LABEL)})</small></h2>",
                "<p>The deeper checks of this run found these findings after the findings of the standard run. A second model call reviewed "
                "each one, unless a finding says otherwise.</p>",
                *_table(more),
            ]
        parts += ["<h2>Details</h2>", *(_finding(finding) for finding in first)]
        if more:
            parts += [
                f"<h2>Details of the more findings <small>({_e(PREVIEW_LABEL)})</small></h2>",
                *(_finding(finding) for finding in more),
            ]
    outputs = [str(item) for item in (run.get("outputs") or {}).values() if str(item) != "report.html"]
    parts += [
        "<footer>",
        f"<p>Generated by SentryTower {_e(__version__)}.</p>",
        f"<p>Files of this run: {', '.join(f'<code>{_e(item)}</code>' for item in outputs)}.</p>" if outputs else "",
        "</footer>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(part for part in parts if part) + "\n"
