"""``python -m sentrytower.funnel --spec SPEC.json``: one run of the funnel engine."""

from __future__ import annotations

from .orchestrator import exit_now, main

if __name__ == "__main__":
    exit_now(main())
