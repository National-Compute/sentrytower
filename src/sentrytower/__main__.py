"""``python -m sentrytower``: the command-line interface."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
