"""The files that one funnel run writes: findings, summary, call ledger and inventory.

- Each JSON file is written to a temporary file and then renamed, so a
  reader (or a run that a signal stops) never sees a partial file.
- The call ledger has one row for each model call and each agent session.
  A row holds numbers and short codes only: never prompt text, response
  text or code. ``Ledger.append`` keeps only the known keys and refuses
  long text.
- The inventory file has a size cap: the run record needs the units and
  their scores, not every feature of every unit.
- The hit file has one row for each search hit that changed the queue: the
  session, the tool, the repository path, the line, the rank, the unit and
  the bonus. It holds no code.
- The lead file lists the leads of the unit checks: the place, the CWE, the
  confidence, the queue score and the status of the deep check. It holds
  no code and no reason.

Standard library only.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

FINDINGS_FILE = "findings.json"
SUMMARY_FILE = "summary.json"
LEDGER_FILE = "ledger.jsonl"
INVENTORY_FILE = "inventory.json"
RECORD_FILE = "funnel-run.json"
WORKERS_FILE = "workers.jsonl"
HITS_FILE = "hits.jsonl"
LEADS_FILE = "leads.json"
FINDINGS_SCHEMA = "funnel-findings-v1"
SUMMARY_SCHEMA = "funnel-summary-v1"
LEDGER_SCHEMA = 1
# The keys of a ledger row, with their types. A string value has at most
# LEDGER_TEXT_LIMIT characters: a row holds codes, never content.
LEDGER_KEYS: dict[str, type | tuple[type, ...]] = {
    "schema": int,
    "t": (int, float),
    "phase": str,
    "task": str,
    "unit_id": str,
    "lead_id": str,
    "status": str,
    "error": str,
    "tokens": int,
    "input_tokens": int,
    "output_tokens": int,
    "latency_s": (int, float),
    "attempts": int,
    "http_status": int,
    "finish_reason": str,
    "verdict": str,
    "candidates": int,
    "findings": int,
    "leads": int,
    "operations": int,
    "rated": int,
    "keep_score": (int, float),
    "exit": int,
    "stopped": str,
    "seconds": (int, float),
    "token_budget": int,
    "finding_id": str,
}
LEDGER_TEXT_LIMIT = 80


def atomic_write_json(path: Path, value: Any) -> None:
    """Write ``value`` as JSON to ``path`` in one rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    staging.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(staging, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class Ledger:
    """One JSON line for each model call or Pi session; no content."""

    def __init__(self, path: Path, started: float | None = None) -> None:
        self.path = path
        self.started = time.monotonic() if started is None else started
        self.rows = 0
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def clean(row: dict[str, Any]) -> dict[str, Any]:
        """The row with the known keys only; a text value is cut to a code."""
        kept: dict[str, Any] = {}
        for key, value in row.items():
            expected = LEDGER_KEYS.get(key)
            if expected is None or value is None or isinstance(value, bool) and expected is not bool:
                continue
            if not isinstance(value, expected):
                continue
            if isinstance(value, str):
                value = value[:LEDGER_TEXT_LIMIT]
            kept[key] = value
        return kept

    def append(self, row: dict[str, Any]) -> dict[str, Any]:
        entry = self.clean({"schema": LEDGER_SCHEMA, "t": round(time.monotonic() - self.started, 1), **row})
        line = json.dumps(entry, sort_keys=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            self.rows += 1
        return entry


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")


def _size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":")).encode())


def cap_inventory(inventory: dict[str, Any], limit_bytes: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """A copy of the inventory that has at most ``limit_bytes`` of JSON, and what the cap removed.

    The steps stop as soon as the copy fits: remove the features of each
    unit, cut each signal text to 120 characters, keep at most 20,000 files,
    and then keep the units in score order until the limit.
    """
    capped = dict(inventory)
    record: dict[str, Any] = {"limit_bytes": limit_bytes, "bytes_before": _size(inventory), "steps": []}
    units = [dict(unit) for unit in inventory.get("units") or [] if isinstance(unit, dict)]
    capped["units"] = units
    if _size(capped) > limit_bytes:
        for unit in units:
            unit.pop("features", None)
        record["steps"].append("unit-features")
    if _size(capped) > limit_bytes:
        for unit in units:
            unit["signals"] = [
                {**signal, "text": str(signal.get("text") or "")[:120]} if isinstance(signal, dict) else signal
                for signal in unit.get("signals") or []
            ]
        record["steps"].append("signal-text")
    files = list(inventory.get("files") or [])
    if _size(capped) > limit_bytes and len(files) > 20_000:
        capped["files"] = files[:20_000]
        record["steps"].append("files")
        record["files_removed"] = len(files) - 20_000
    if _size(capped) > limit_bytes:
        kept: list[dict[str, Any]] = []
        budget = limit_bytes - _size({**capped, "units": []}) - 2
        for unit in units:
            size = _size(unit) + 1
            if size > budget:
                break
            kept.append(unit)
            budget -= size
        record["units_removed"] = len(units) - len(kept)
        capped["units"] = kept
        record["steps"].append("units")
    record["bytes_after"] = _size(capped)
    capped["capped"] = record if record["steps"] else None
    return capped, record
