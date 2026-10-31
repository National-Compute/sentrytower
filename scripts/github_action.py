#!/usr/bin/env python3
"""The helper of the SentryTower GitHub Action (``action.yml``): the context of a run and the report of an audit.

    python3 scripts/github_action.py context
    python3 scripts/github_action.py report

``context`` finds the visibility of the repository and decides what the
Action shows. Anyone who can read a public repository can read its job
summaries, annotations and logs and download its workflow artifacts, so on
a public repository the Action shows counts only, unless the input
``public-findings`` is true. GitHub shows the code scanning alerts of a
pull request to each reader of the repository, but the alert list of the
repository only to people with write access; so ``upload-sarif: auto``
uploads on a public repository only for a run of the default branch. The
step writes the outputs ``visibility``, ``public``, ``details``,
``upload-sarif`` and ``artifact``.

``report`` reads ``run.json`` and ``findings.json`` of the audit, writes the
job summary and the outputs of the Action, and prints an error annotation
when the audit did not pass. Exit code 4 (a failed or incomplete run) gives
the reason of the run record, whatever ``fail-on`` says. The titles and
locations of the findings are text of a model that read untrusted code:
the summary escapes them, and it shows them only when ``details`` is true.

The Python of the runner runs this file (3.9 or later, the standard library
only). The inputs come from the environment of the step.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

# The events of a run that GitHub can show on a pull request (as annotations and check results).
PULL_REQUEST_EVENTS = frozenset(
    {"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment", "merge_group"}
)
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
EXIT_MEANING = {
    1: "a finding at or above fail-on",
    2: "a usage error",
    3: "an environment problem (the key, the endpoint or a tool)",
    4: "the run failed or is incomplete",
    130: "the run was interrupted",
}
PREVIEW = "preview: more checks; effect on findings not yet measured"
OUTPUT_FILES = (("findings", "findings.json"), ("sarif", "findings.sarif"), ("report", "report.md"), ("report-html", "report.html"))
MAX_ROWS = 50
MAX_TEXT = 160
# The characters that Markdown can read as markup; each one gets a backslash in front.
_MARKUP = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~])")


def _load(path: Path | None) -> dict[str, Any]:
    """The JSON object of a file, or an empty object when the file is missing or broken."""
    if path is None or not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _count(value: Any) -> int | None:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


def _escape_data(text: str) -> str:
    """The message of a workflow command: one line, with no command in it."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def annotate(kind: str, message: str, title: str = "SentryTower") -> None:
    """Print a workflow command (error, warning or notice) for the log and the annotations of the run."""
    print(f"::{kind} title={_escape_property(title)}::{_escape_data(message)}", flush=True)


def plain(value: Any, limit: int = MAX_TEXT) -> str:
    """Untrusted text as Markdown text: one line, printable, short, with each markup character escaped."""
    text = "".join(character for character in " ".join(str(value).split()) if character.isprintable())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return _MARKUP.sub(r"\\\1", text.replace("&", "&amp;"))


def write_outputs(values: dict[str, str]) -> None:
    """Append ``name=value`` lines to $GITHUB_OUTPUT; each value is one line."""
    target = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{name}={' '.join(value.split())}\n" for name, value in values.items())
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(lines)
    else:
        sys.stdout.write(lines)


def _choice(name: str, default: str, allowed: tuple[str, ...]) -> str | None:
    value = (os.environ.get(f"INPUT_{name.upper().replace('-', '_')}") or default).strip().lower()
    if value not in allowed:
        annotate("error", f"the input {name} must be {', '.join(allowed[:-1])} or {allowed[-1]}, not {value!r}")
        return None
    return value


def _api_repository(environ: dict[str, str]) -> dict[str, Any]:
    """The repository object of the GitHub REST API (the token of the job reads its metadata)."""
    url = f"{environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')}/repos/{environ.get('GITHUB_REPOSITORY', '')}"
    if not url.startswith(("https://", "http://")):
        raise ValueError("the API URL is not an HTTP URL")
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sentrytower-action"}
    )
    if environ.get("INPUT_TOKEN"):
        request.add_header("Authorization", f"Bearer {environ['INPUT_TOKEN']}")
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.loads(response.read().decode("utf-8"))
    return value if isinstance(value, dict) else {}


def repository_visibility(event: dict[str, Any], environ: dict[str, str]) -> tuple[str, str | None]:
    """``public``, ``private``, ``internal`` or ``unknown``, and the default branch when known.

    The event payload has the repository for most events; a scheduled run has
    none, so the step asks the API.
    """
    repository = _object(event.get("repository"))
    if not repository.get("visibility") and not isinstance(repository.get("private"), bool):
        try:
            repository = _api_repository(environ)
        except (OSError, ValueError) as error:
            annotate("warning", f"the visibility of the repository is unknown ({type(error).__name__}): the Action shows counts only")
            return "unknown", None
    visibility = repository.get("visibility")
    if visibility not in ("public", "private", "internal"):
        private = repository.get("private")
        visibility = "unknown" if not isinstance(private, bool) else ("private" if private else "public")
    branch = repository.get("default_branch")
    return str(visibility), branch if isinstance(branch, str) and branch else None


def context() -> int:
    environ = dict(os.environ)
    upload_sarif = _choice("upload-sarif", "auto", ("auto", "true", "false"))
    upload_artifact = _choice("upload-artifact", "true", ("true", "false"))
    public_findings = _choice("public-findings", "false", ("true", "false"))
    if upload_sarif is None or upload_artifact is None or public_findings is None:
        return 2
    event_path = environ.get("GITHUB_EVENT_PATH")
    event = _load(Path(event_path)) if event_path else {}
    visibility, default_branch = repository_visibility(event, environ)
    public = visibility not in ("private", "internal")
    details = not public or public_findings == "true"
    event_name = environ.get("GITHUB_EVENT_NAME", "")
    # A scheduled run always runs on the default branch; its event payload does not name the branch.
    on_default_branch = event_name == "schedule" or (
        default_branch is not None and environ.get("GITHUB_REF") == f"refs/heads/{default_branch}"
    )
    if upload_sarif == "auto":
        sarif = details or (event_name not in PULL_REQUEST_EVENTS and on_default_branch)
    else:
        sarif = upload_sarif == "true"
    artifact = "none" if upload_artifact == "false" else ("all" if details else "record")
    if public and not details:
        held = ", and the workflow artifact holds run.json only" if artifact == "record" else ""
        annotate(
            "notice",
            f"This repository is public, so the Action shows counts only in the job summary, the annotations and the log{held}. "
            'Set public-findings: "true" to show the findings to every reader.',
        )
    elif public:
        annotate(
            "warning",
            "public-findings is true: the job summary and the workflow artifact show the findings to every reader of this repository",
        )
    if upload_sarif == "auto" and not sarif:
        annotate(
            "notice",
            "upload-sarif is auto: no upload for this run. GitHub shows the code scanning alerts of a pull request to every reader "
            "of a public repository; the alert list of a run on the default branch needs write access.",
        )
    write_outputs(
        {
            "visibility": visibility,
            "public": str(public).lower(),
            "details": str(details).lower(),
            "upload-sarif": str(sarif).lower(),
            "artifact": artifact,
        }
    )
    return 0


def _severity_counts(findings_document: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, int]:
    recorded = _object(_object(findings_document.get("summary")).get("by_severity"))
    counts = {name: _count(recorded.get(name)) for name in SEVERITIES}
    if all(value is not None for value in counts.values()):
        return {name: int(value or 0) for name, value in counts.items()}
    computed = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        severity = finding.get("severity")
        computed[severity if severity in computed else "unknown"] += 1
    return computed


def _money(value: float) -> str:
    return "less than $0.01" if 0 < value < 0.005 else f"${value:,.2f}"


def _spend(run: dict[str, Any], result: dict[str, Any]) -> str:
    spent = (
        _number(result.get("spent_usd"))
        if "spent_usd" in result
        else _number(_object(_object(run.get("usage")).get("total")).get("cost_usd"))
    )
    cap = _number(result.get("cap_usd")) if "cap_usd" in result else _number(_object(run.get("budget")).get("max_cost_usd"))
    text = _money(spent) if spent is not None else "unknown"
    return f"{text} of the {_money(cap)} cap" if cap is not None else f"{text} (no cap)"


def _units(result: dict[str, Any]) -> str | None:
    units = _object(result.get("units"))
    checked, total, failed = _count(units.get("checked")), _count(units.get("total")), _count(units.get("failed"))
    if checked is None:
        return None
    kind = plain(units.get("kind") or "units", 40)
    text = f"{checked:,} of {total:,} {kind}" if total is not None else f"{checked:,} {kind}"
    return text + (f", {failed:,} failed" if failed else "")


def _calls(run: dict[str, Any], result: dict[str, Any]) -> str | None:
    calls = _object(result.get("calls"))
    total, failed, share = _count(calls.get("total")), _count(calls.get("failed")), _number(calls.get("failed_share"))
    if total is None:
        usage = _object(_object(run.get("usage")).get("total"))
        total, failed, share = _count(usage.get("calls")), _count(usage.get("failures")), None
    if total is None:
        return None
    if not failed:
        return f"{total:,}"
    return f"{total:,} ({failed:,} failed" + (f", {share:.1%})" if share is not None else ")")


def _location(finding: dict[str, Any]) -> str:
    location = _object(finding.get("location"))
    path, start, end = location.get("path"), _count(location.get("start_line")), _count(location.get("end_line"))
    if not isinstance(path, str) or not path:
        return "no location"
    lines = "" if start is None else (f":{start}" if end in (None, start) else f":{start}-{end}")
    return plain(f"{path}{lines}", 120)


def _note(finding: dict[str, Any]) -> str:
    """The labels of a finding: unverified, second tier."""
    notes = []
    verification = finding.get("verification")
    if isinstance(verification, dict):
        verification = verification.get("status")
    if isinstance(verification, str) and verification.strip().lower() not in ("", "verified", "none"):
        notes.append(verification)
    if finding.get("tier") == 2:
        notes.append("second tier")
    return plain("; ".join(notes), 80)


def summary(run: dict[str, Any], findings_document: dict[str, Any], code: int, *, details: bool, sarif: bool, fail_on: str) -> str:
    """The job summary of an audit: counts always, and the findings when ``details`` is true."""
    if not run:
        meaning = EXIT_MEANING.get(code, "docker run or sentrytower failed")
        return f"## SentryTower: no result\n\nThe audit wrote no run record (exit code {code}: {meaning}). The log of the audit step tells why.\n"
    result = _object(run.get("result"))
    findings = [item for item in findings_document.get("findings") or [] if isinstance(item, dict)]
    counts = _severity_counts(findings_document, findings)
    total = _count(_object(findings_document.get("summary")).get("findings"))
    total = total if total is not None else sum(counts.values())
    status = plain(result.get("status") or run.get("status") or "unknown", 40)
    rows = []
    failure = result.get("failure") if "failure" in result else run.get("failure")
    if failure:
        rows.append(("Why it is not complete", plain(failure, 300)))
    stop = result.get("stop_text") or run.get("stop")
    if stop:
        rows.append(("Why the run stopped", plain(stop, 300)))
    rows.append(("Spend", _spend(run, result)))
    units = _units(result)
    if units:
        rows.append(("Checked", units))
    calls = _calls(run, result)
    if calls:
        rows.append(("Model calls", calls))
    route = run.get("route")
    files = _count(_object(run.get("repository")).get("files_counted"))
    if route:
        rows.append(("Route", plain(route, 20) + (f", {files:,} files counted" if files is not None else "")))
    rows.append(("Findings", f"{total:,}: " + ", ".join(f"{counts[name]} {name}" for name in SEVERITIES)))
    if result.get("preview") is True:
        rows.append(("Depth", plain(PREVIEW)))
    if code != 0:
        meaning = (
            f"{EXIT_MEANING[1]} ({plain(fail_on, 20)})"
            if code == 1 and fail_on
            else EXIT_MEANING.get(code, "docker run or sentrytower failed")
        )
        rows.append(("Exit code", f"{code}: {meaning}"))
    lines = [f"## SentryTower: {status}", "", "| Run | |", "| --- | --- |"]
    lines += [f"| {name} | {value} |" for name, value in rows]
    lines.append("")
    if details and findings:
        lines += ["### Findings", "", "| Severity | Finding | Location | Note |", "| --- | --- | --- | --- |"]
        for finding in findings[:MAX_ROWS]:
            severity = finding.get("severity") if finding.get("severity") in SEVERITIES else "unknown"
            lines.append(f"| {severity} | {plain(finding.get('title') or 'untitled')} | {_location(finding)} | {_note(finding)} |")
        if len(findings) > MAX_ROWS:
            lines.append(f"\n{len(findings) - MAX_ROWS} more findings are in report.md and findings.json.")
        lines += ["", "Each finding is a claim of a language model: confirm it in the code before you act on it.", ""]
    elif findings:
        where = (
            "The findings go to code scanning, which shows the alert list to people with write access only."
            if sarif
            else "This run uploads no SARIF file: a run of the default branch (for example on a schedule) puts the findings "
            "in code scanning, which shows the alert list to people with write access only."
        )
        lines += [
            "This repository is public, so this summary shows counts only: every reader of the repository can read it. "
            f'{where} Set the input public-findings to "true" to show the findings here.',
            "",
        ]
    return "\n".join(lines)


def _error(run: dict[str, Any], findings_document: dict[str, Any], code: int, fail_on: str) -> str | None:
    """The message of the error annotation of an exit code other than 0 (counts and run reasons only)."""
    if code == 0:
        return None
    result = _object(run.get("result"))
    reasons = [str(text) for text in (result.get("stop_text"), result.get("failure") or run.get("failure")) if text]
    if code == 1:
        findings = [item for item in findings_document.get("findings") or [] if isinstance(item, dict)]
        counts = _severity_counts(findings_document, findings)
        listed = ", ".join(f"{counts[name]} {name}" for name in SEVERITIES if counts[name])
        return f"findings at or above {fail_on or 'the fail-on severity'} ({listed or 'see the summary'}): exit code 1"
    meaning = EXIT_MEANING.get(code, "docker run or sentrytower failed")
    if not run:
        return f"exit code {code} ({meaning}); the audit wrote no run record, the log of the audit step tells why"
    return f"exit code {code} ({meaning}): " + (" ".join(reasons) if reasons else "the log of the audit step tells why")


def report() -> int:
    out = Path(os.environ.get("AUDIT_OUT") or ".")
    try:
        code = int(os.environ.get("AUDIT_EXIT_CODE") or "4")
    except ValueError:
        code = 4
    details = os.environ.get("AUDIT_DETAILS") == "true"
    sarif = os.environ.get("AUDIT_UPLOAD_SARIF") == "true"
    fail_on = os.environ.get("AUDIT_FAIL_ON") or ""
    run = _load(out / "run.json")
    findings_document = _load(out / "findings.json")
    outputs = {name: str(out / file) for name, file in OUTPUT_FILES if (out / file).is_file()}
    result = _object(run.get("result"))
    outputs["status"] = str(result.get("status") or run.get("status") or ("" if not run else "unknown"))
    outputs["route"] = str(run.get("route") or _object(findings_document.get("run")).get("route") or "")
    if findings_document:
        findings = [item for item in findings_document.get("findings") or [] if isinstance(item, dict)]
        total = _count(_object(findings_document.get("summary")).get("findings"))
        outputs["count"] = str(total if total is not None else len(findings))
    write_outputs(outputs)
    try:
        # Only a complete run uploads its SARIF file (action.yml): code scanning would close the alerts that it does not hold.
        complete = outputs["status"] == "complete"
        text = summary(run, findings_document, code, details=details, sarif=sarif and complete, fail_on=fail_on)
        if sarif and not complete:
            text += "\nThe run is not complete, so it uploads no SARIF file: code scanning keeps the alerts of the last complete run.\n"
    except Exception as error:  # noqa: BLE001 - the exit code of the audit decides the step, not the summary
        annotate("warning", f"the job summary was not written ({type(error).__name__})")
        text = ""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target and text:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    message = _error(run, findings_document, code, fail_on)
    if message:
        annotate("error", message)
    elif findings_document:
        annotate("notice", f"{outputs.get('status') or 'done'}: {outputs.get('count', '0')} finding(s)")
    return 0


def main(argv: list[str]) -> int:
    commands = {"context": context, "report": report}
    if len(argv) != 2 or argv[1] not in commands:
        print(f"usage: {Path(argv[0]).name} context|report", file=sys.stderr)
        return 2
    return commands[argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
