"""The result of a run: its status, why it stopped, the spend, the checked units and the model calls.

``audit.run_audit`` builds one result for each run (``run.json`` ``result``,
and the run part of ``findings.json``). Each output states it with the same
plain sentences (``result_lines``): report.md, report.html, the result screen
of a terminal and the last lines of the plain log.

The statuses:

- ``complete``: the engine ended its work, or the budget or the wall clock
  ended it, and the outputs hold what it found;
- ``incomplete``: the engine crashed or gave no answer, more than
  ``FAILED_SHARE_LIMIT`` of the model calls failed, or the funnel did not
  do its work (``phase0_failure``, ``units_failure``, ``sessions_failure``);
- ``failed``: the provider refused the key, the account or the route (HTTP
  401, 402, 403 or 404), or the output of the engine cannot be read;
- ``interrupted``: SIGINT or SIGTERM stopped the run.

The share of failed calls is a share of the calls that reached the provider
(the budget refusals of the gateway and the calls after a provider refusal
do not count). The rule applies from ``FAILED_SHARE_MIN_CALLS`` such calls
on, so that one failure in a small run does not make it incomplete; a run
whose calls all failed is incomplete from one call on.

Standard library only.
"""

from __future__ import annotations

from typing import Any, Mapping

STATUS_COMPLETE = "complete"
STATUS_INCOMPLETE = "incomplete"
STATUS_FAILED = "failed"
STATUS_INTERRUPTED = "interrupted"
STOP_DONE = "done"
STOP_BUDGET = "budget"
STOP_TOKENS = "token-ceiling"
STOP_WALL_CLOCK = "wall-clock"
STOP_PROVIDER = "provider-error"
STOP_ENGINE = "engine-error"
STOP_INTERRUPTED = "interrupted"
# More than this share of failed model calls makes a run incomplete, from this count of calls on.
FAILED_SHARE_LIMIT = 0.20
FAILED_SHARE_MIN_CALLS = 10
# The same share of failed unit checks makes a funnel run incomplete, from this count of tried unit checks on.
FAILED_SHARE_MIN_UNITS = 10
# The statuses of phase 0 of the funnel (the inventory) that count as done: a partial inventory stopped at its time
# or size limit and holds the units that it found.
PHASE0_DONE = ("complete", "partial")
# The kinds of units of a run.
UNITS_FUNNEL = "code units"
UNITS_AGENT = "agent sessions"
# The label of a depth above the standard run, and of the second tier of findings.
PREVIEW_LABEL = "preview: more checks; effect on findings not yet measured"
# The first words of the sentence of a failure (``result_lines``).
FAILURE_PREFIXES = ("The run failed.", "The run is incomplete.")


def money_text(value: float) -> str:
    """US dollars for a sentence: two decimals, four below one cent."""
    return f"${value:.2f}" if value >= 0.01 or value == 0 else f"${value:.4f}"


def provider_failure(status: int, model: str, key_variable: str | None) -> str:
    """The plain failure of a run that the provider refused (``gateway.FATAL_STATUSES``)."""
    key = "the key in the system keychain" if key_variable == "keychain" else (key_variable or "SENTRYTOWER_API_KEY")
    if status == 401:
        return f"The provider refused the key (HTTP 401): check {key}."
    if status == 402:
        return "The provider account has no credit (HTTP 402): add credit, then run again."
    if status == 403:
        return f"The provider refused the account or the request (HTTP 403): check {key} and the limits of the account."
    # A wrong base URL or model, or (on OpenRouter) a route that no provider serves under its data policy.
    return (
        f"The endpoint answered HTTP {status} for {model}: check the model and --base-url; on OpenRouter, "
        "no provider of the route may serve the model under its data policy."
    )


def calls_record(total: Mapping[str, Any]) -> dict[str, Any]:
    """The model calls of a run for the result: the calls that reached the provider and the failed ones."""
    calls = int(total.get("upstream_calls") or 0)
    failed = int(total.get("failures") or 0)
    return {"total": calls, "failed": failed, "failed_share": round(failed / calls, 4) if calls else 0.0}


def failed_calls_failure(calls: Mapping[str, Any], failed_by: Mapping[str, int]) -> str | None:
    """The failure of a run with too many failed calls (more than the limit, or each call from one call on), else None."""
    total, failed = int(calls.get("total") or 0), int(calls.get("failed") or 0)
    every = total > 0 and failed >= total
    if not every and (total < FAILED_SHARE_MIN_CALLS or failed / total <= FAILED_SHARE_LIMIT):
        return None
    main = sorted(failed_by.items(), key=lambda pair: (-pair[1], pair[0]))[:3]
    kinds = ", ".join(f"{label} ({count:,})" for label, count in main)
    end = f": {kinds}." if kinds else "."
    if total < FAILED_SHARE_MIN_CALLS:
        return f"{failed:,} of {total:,} model call{'s' if total != 1 else ''} failed{end}"
    return f"{failed:,} of {total:,} model calls failed ({failed / total:.0%}, more than {FAILED_SHARE_LIMIT:.0%}){end}"


def phase0_failure(phase0: Mapping[str, Any]) -> str | None:
    """The failure of a funnel run whose inventory (phase 0) did not succeed, else None.

    ``phase0`` is the phase 0 record of the funnel: its ``status`` and the
    ``error`` code (for example ``deadline`` or ``exit 1``). A run without
    the record (the engine stopped before phase 0 ended) gets None.
    """
    status = phase0.get("status")
    if status is None or status in PHASE0_DONE:
        return None
    error = f" ({phase0['error']})" if phase0.get("error") else ""
    return f"Phase 0, the inventory of the code units, failed{error}."


def units_failure(units: Mapping[str, Any]) -> str | None:
    """The failure of a funnel run whose unit checks did not do their work, else None.

    The run had code units to check (``total``) and checked none, or it
    tried at least ``FAILED_SHARE_MIN_UNITS`` unit checks (checked and
    failed) and more than ``FAILED_SHARE_LIMIT`` of them failed. A unit that
    the budget refused is neither checked nor failed.
    """
    checked, failed, total = int(units.get("checked") or 0), int(units.get("failed") or 0), units.get("total")
    tried = checked + failed
    if isinstance(total, int) and total > 0 and checked == 0:
        if failed:
            return f"No code unit was checked: {failed:,} of {tried:,} unit check{'s' if tried != 1 else ''} failed."
        return f"No code unit was checked: the run had {total:,} code unit{'s' if total != 1 else ''} to check."
    if tried >= FAILED_SHARE_MIN_UNITS and failed / tried > FAILED_SHARE_LIMIT:
        return f"{failed:,} of {tried:,} unit checks failed ({failed / tried:.0%}, more than {FAILED_SHARE_LIMIT:.0%})."
    return None


def sessions_failure(sessions: Mapping[str, Any]) -> str | None:
    """The failure of a run in which more than half of the agent sessions ended without an answer, else None.

    The caller leaves out a run that the wall clock or an interrupt stopped:
    such a stop ends the running sessions.
    """
    answered, failed = int(sessions.get("answered") or 0), int(sessions.get("failed") or 0)
    ran = answered + failed
    if not ran or 2 * failed <= ran:
        return None
    return f"{failed:,} of {ran:,} agent session{'s' if ran != 1 else ''} ended without an answer."


def stop_text(
    reason: str,
    *,
    route: str,
    detail: str | None,
    cap_usd: float | None,
    tokens: int | None,
    wall_clock_seconds: int | None,
    provider_status: int | None = None,
    incomplete: bool = False,
) -> str:
    """One plain sentence: why the run stopped.

    ``detail`` is the stop of the engine (for example ``queue-empty`` or
    ``unit-check-cap`` of the funnel, ``budget-stop`` of the 85% rule).
    ``incomplete``: the status of the run is incomplete, so an engine that
    ended on its own did not finish its work.
    """
    if reason == STOP_DONE:
        if incomplete:
            return "The engine ended, but its work is incomplete."
        if route == "funnel" and detail == "unit-check-cap":
            return "The run finished its work: it made each unit check that its depth allows, and no other work was left."
        if route == "funnel":
            return "The run finished its work: no code unit, lead or finding was left to check."
        if detail == "done":
            # The deep engine of the agent route: the whole-repository session and the slices.
            return "The run finished its work: the whole-repository session and each slice session ended."
        return "The agent finished its audit and gave its answer."
    if reason == STOP_BUDGET:
        cap = f"the {money_text(cap_usd)} cost cap" if cap_usd else "the cost cap"
        if detail in ("budget-stop", "budget"):
            return f"The run spent 85% of {cap}, so no new work started; the running work finished."
        if detail == "budget-left":
            return f"The money left before 85% of {cap} could not buy the next task, so no new work started."
        return f"The model gateway refused new calls at {cap}."
    if reason == STOP_TOKENS:
        size = f" of {tokens:,} tokens" if tokens else ""
        return f"The run used its token budget{size}."
    if reason == STOP_WALL_CLOCK:
        clock = f" ({_duration(wall_clock_seconds)})" if wall_clock_seconds else ""
        return f"The wall clock of the run{clock} ended."
    if reason == STOP_PROVIDER:
        status = f" (HTTP {provider_status})" if provider_status else ""
        return f"The provider refused a model call{status}, so the run made no more calls."
    if reason == STOP_INTERRUPTED:
        return "The run was interrupted (Ctrl-C or SIGTERM)."
    return "The engine stopped with an error."


def _duration(seconds: int | None) -> str:
    value = int(seconds or 0)
    if value % 3600 == 0:
        return f"{value // 3600} h"
    if value >= 3600:
        return f"{value // 3600} h {value % 3600 // 60} min"
    return f"{value // 60} min" if value % 60 == 0 else f"{value} s"


def spend_sentence(result: Mapping[str, Any]) -> str:
    spent, cap = result.get("spent_usd"), result.get("cap_usd")
    if isinstance(spent, (int, float)):
        return (
            f"Spent {money_text(float(spent))} of the {money_text(float(cap))} cost cap."
            if cap
            else f"Spent {money_text(float(spent))}; the run had no cost cap."
        )
    if cap:
        return f"The provider reported no cost and the prices are not known; the cost cap was {money_text(float(cap))}."
    return "The provider reported no cost and the prices are not known; the run had no cost cap."


def units_sentence(result: Mapping[str, Any]) -> str:
    units = result.get("units") or {}
    kind = str(units.get("kind") or UNITS_FUNNEL)
    checked, failed, total = int(units.get("checked") or 0), int(units.get("failed") or 0), units.get("total")
    if kind == UNITS_AGENT:
        planned = int(total) if isinstance(total, int) else checked + failed
        text = f"{checked:,} of {planned:,} agent session{'s' if planned != 1 else ''} gave an answer"
        if failed:
            text += f"; {failed:,} ended without one"
        files = units.get("files_read")
        if isinstance(files, int):
            text += f"; the agents read {files:,} file{'s' if files != 1 else ''}"
        return text + "."
    text = f"Checked {checked:,} of {total:,} {kind}" if isinstance(total, int) else f"Checked {checked:,} {kind}"
    if failed:
        text += f"; {failed:,} could not be checked"
    sessions = result.get("sessions") or {}
    if int(sessions.get("failed") or 0):
        count = int(sessions["failed"])
        text += f"; {count:,} agent session{'s' if count != 1 else ''} ended without an answer"
    return text + "."


def result_lines(result: Mapping[str, Any]) -> list[str]:
    """The plain sentences of a result: the spend, why the run stopped, the checked units, the depth and the failure."""
    lines = [spend_sentence(result), str(result.get("stop_text") or "The run stopped."), units_sentence(result)]
    if result.get("preview"):
        lines.append(f"Depth {float(result.get('depth_factor') or 1):.2g} times the standard run ({PREVIEW_LABEL}).")
    failure = str(result.get("failure") or "").strip()
    if failure and result.get("status") in (STATUS_FAILED, STATUS_INCOMPLETE):
        prefix = FAILURE_PREFIXES[0] if result.get("status") == STATUS_FAILED else FAILURE_PREFIXES[1]
        lines.append(f"{prefix} {failure[:1].upper()}{failure[1:]}" + ("" if failure.endswith(".") else "."))
    return lines
