"""The class of a repository path for the queue, the leads and the output of the funnel.

The language and the path tags come from the functions of the phase-0
inventory (``inventory.path_tags`` and ``inventory._language``), so the
orchestrator and the inventory classify each path in one way. A file that
the inventory lists keeps the language and the tags of its record.

- A file with one of ``EXCLUDED_TAGS`` (test, docs, example, fixtures,
  generated, declarations) or a non-code language (markdown, JSON, YAML,
  lock files, text, data, images and similar) gets no search-hit bonus, no
  window, no unit check, no lead, and no deep-check finding in the output (a
  security fix changes production code). A workflow file of GitHub Actions
  is code: the inventory scans it.
- A vendor file gets the bonus of a search hit, but no window.

Standard library only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Iterable

EXCLUDED_TAGS = frozenset({"test", "docs", "example", "fixtures", "generated", "declarations"})
VENDOR_TAG = "vendor"
NON_CODE_LANGUAGES = frozenset(
    {
        "markdown",
        "rst",
        "asciidoc",
        "text",
        "json",
        "yaml",
        "toml",
        "xml",
        "ini",
        "conf",
        "properties",
        "lock",
        "data",
        "binary",
        "svg",
        "css",
        "sourcemap",
    }
)
WORKFLOW_FOLDER = ".github/workflows/"


class PathClasses:
    """The language and the tags of the paths of one repository, with the inventory functions."""

    def __init__(self, root: Path, files: Iterable[Any] = ()) -> None:
        self.root = root
        self.records: dict[str, tuple[str | None, frozenset[str]]] = {}
        for item in files:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                tags = found if isinstance(found := item.get("tags"), list) else []
                language = given if isinstance(given := item.get("language"), str) else None
                self.records[item["path"]] = (language, frozenset(str(tag) for tag in tags))
        self.cache: dict[str, tuple[str | None, frozenset[str]]] = {}
        self.path_tags: Callable[[str], Any] | None = None
        self.language_of: Callable[[str, str, str, int], str] | None = None
        try:
            from . import inventory  # type: ignore[attr-defined]

            self.path_tags = inventory.path_tags
            self.language_of = inventory._language
        except Exception:  # noqa: BLE001 - without the inventory module the run has no path classes
            self.path_tags = None
            self.language_of = None

    @property
    def available(self) -> bool:
        return self.path_tags is not None and self.language_of is not None

    def classes(self, path: str) -> tuple[str | None, frozenset[str]]:
        """The language and the tags of a repository path."""
        if path in self.records:
            return self.records[path]
        if path in self.cache:
            return self.cache[path]
        language: str | None = None
        tags: frozenset[str] = frozenset()
        if self.path_tags is not None and self.language_of is not None:
            full = os.path.join(self.root, path)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            try:
                tags = frozenset(self.path_tags(path))
                language = self.language_of(path, path.rsplit("/", 1)[-1], full, size)
            except Exception:  # noqa: BLE001 - one odd path must not stop the run
                language, tags = None, frozenset()
        self.cache[path] = (language, tags)
        return language, tags

    def excluded(self, path: str) -> str | None:
        """The class that keeps a path out of the queue, the leads and the output, or None."""
        language, tags = self.classes(path)
        hit = sorted(tags & EXCLUDED_TAGS)
        if hit:
            return f"tag-{hit[0]}"
        if language in NON_CODE_LANGUAGES and "/" + WORKFLOW_FOLDER not in "/" + path:
            return f"language-{language}"
        return None

    def vendor(self, path: str) -> bool:
        return VENDOR_TAG in self.classes(path)[1]
