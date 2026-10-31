"""The search hits of the agent sessions of a funnel run: the outputs of grep and find.

An agent session writes each tool call of the model to its session file: the
call (its ID, name and arguments) in an assistant message, and the output in
a ``toolResult`` message with the same call ID. The orchestrator reads the
new lines of each session file while the session runs (``SessionTokens`` of
``workers.py``) and gives each grep and find output to ``search_hits``:

- The grep tool prints one line ``<path>:<line>: <text>`` for each match and
  ``<path>-<line>- <text>`` for each context line. The path is relative to
  the search path when the search path is a folder, and it is the base name
  of the file when the search path is a file.
- The find tool prints one path for each file, relative to the search path.
- The agent resolves a relative search path from the working folder of the
  session (the repository root). An absolute search path must be in the
  repository.

A hit is never an instruction to open a file: the orchestrator adds a score
to the queue entry of the unit around the hit, and the queue decides.

Standard library only.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any, Callable

from .slices import split_lines

SEARCH_TOOLS = ("grep", "find")
PATH_ARGUMENTS = ("path", "file_path")
_GREP_MATCH = re.compile(r"^(?P<path>.+?):(?P<line>\d+):(?: |$)")


@dataclass(frozen=True)
class SearchHit:
    """One grep match (a path and a line) or one found file (no line), with its rank in its output."""

    tool: str
    path: str
    line: int | None
    rank: int


def _search_folder(arguments: Any, root: str) -> str | None:
    """The search path of a call relative to the repository root ("" for the root), or None outside it."""
    value = None
    if isinstance(arguments, dict):
        for name in PATH_ARGUMENTS:
            if isinstance(arguments.get(name), str) and arguments[name].strip():
                value = arguments[name].strip()
                break
    if value is None or value in (".", "./"):
        return ""
    if value.startswith("@"):
        value = value[1:]
    root = posixpath.normpath(root)
    if posixpath.isabs(value):
        normal = posixpath.normpath(value)
        if normal == root:
            return ""
        if not normal.startswith(root + "/"):
            return None
        relative = normal[len(root) + 1 :]
    else:
        relative = posixpath.normpath(value)
    if relative in ("", "."):
        return ""
    if relative == ".." or relative.startswith("../") or posixpath.isabs(relative):
        return None
    return relative


def _join(folder: str, path: str) -> str | None:
    joined = posixpath.normpath(posixpath.join(folder, path)) if folder else posixpath.normpath(path)
    if joined in ("", ".") or joined == ".." or joined.startswith("../") or posixpath.isabs(joined):
        return None
    return joined


def search_hits(tool: str, arguments: Any, output: str, *, root: str, is_file: Callable[[str], bool], limit: int) -> list[SearchHit]:
    """The hits of one grep or find output, at most ``limit``, as repository paths.

    ``root`` is the working folder of the session (the repository root);
    ``is_file`` tells if a repository path is a file. A path that leaves the
    repository gives no hit.
    """
    if tool not in SEARCH_TOOLS or not isinstance(output, str) or limit < 1:
        return []
    folder = _search_folder(arguments, root)
    if folder is None:
        return []
    hits: list[SearchHit] = []
    seen: set[tuple[str, int | None]] = set()
    single_file = bool(folder) and is_file(folder)
    for raw in split_lines(output):
        if len(hits) >= limit:
            break
        line_text = raw.rstrip("\r")
        if not line_text.strip() or line_text.startswith("["):
            continue
        if tool == "grep":
            match = _GREP_MATCH.match(line_text)
            if match is None:
                continue
            path = folder if single_file else _join(folder, match.group("path"))
            line: int | None = int(match.group("line"))
        else:
            if " limit reached" in line_text or line_text.endswith("/"):
                continue
            path = _join(folder, line_text.strip())
            line = None
        if path is None or (path, line) in seen:
            continue
        seen.add((path, line))
        hits.append(SearchHit(tool, path, line, len(hits) + 1))
    return hits
