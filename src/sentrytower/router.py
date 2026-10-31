"""The size rule of the hybrid: one count of the repository files picks the engine of a run.

At the start of a run, before any model call, the router counts the regular
files of the repository (``count_files``): links are not followed, and the
count stops at ``threshold + 1``. The count leaves out each folder that holds
no code of the project, at any depth below the root (``skipped_folder``):

- a folder that the census of the funnel inventory does not enter
  (``inventory.SKIP_DIRS``): version control such as .git, installed
  dependencies such as node_modules, bower_components, jspm_packages, .venv
  and site-packages, and caches and tool folders such as __pycache__, .tox,
  .gradle, .next, .nuxt, .svelte-kit, Pods and Carthage;
- a folder that the path tags of the inventory mark as vendored, generated or
  build output (``inventory.path_tags``): vendor, third_party, dist, build,
  target, out, coverage and similar. A build folder below a source folder
  (src, lib, app, packages and similar) is source code for the inventory; the
  router counts it as build output only when a build file (package.json,
  build.gradle, pom.xml, Cargo.toml and similar) is next to it, as in
  app/build of an Android app or packages/ui/dist of a monorepo;
- the version-control folders that the inventory does not name
  (``EXTRA_SKIPPED``) and each Python virtual environment: venv, and each
  folder with a pyvenv.cfg file.

``run.json`` records the skipped folders, their names and their files (also
counted up to ``threshold + 1``).

- 1,000 files or fewer: the funnel engine.
- More than 1,000 files: the single-agent engine.

The threshold is the funnel parameter ``large_repo_files``; it was fixed
before the measured runs and not tuned. A run has one route: the count happens
one time. The large-repository rule of the funnel uses the same count.
"""

from __future__ import annotations

import os
import time
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .funnel.inventory import SKIP_DIRS, TAG_DIRS, path_tags

LARGE_REPO_FILES = 1000
RULE = "size-route-v2"
ROUTE_FUNNEL = "funnel"
ROUTE_AGENT = "agent"
VCS_FOLDERS = (".git", ".hg", ".svn", ".bzr", "_darcs", "CVS", ".jj", ".pijul", ".sl")
# The folders that the router leaves out besides the folders of the inventory rules: the
# version-control folders that SKIP_DIRS does not name, and the usual name of a virtual environment.
EXTRA_SKIPPED = frozenset({*VCS_FOLDERS, "venv"}) - SKIP_DIRS
# The path tags of the inventory whose folders hold no code of the project.
SKIPPED_TAGS = frozenset({"vendor", "generated", "build"})
BUILD_FOLDERS = frozenset(name for name in TAG_DIRS["build"] if "/" not in name)
# A build file next to a build folder below a source folder makes that folder build output.
BUILD_FILES = frozenset(
    {"package.json", "build.gradle", "build.gradle.kts", "pom.xml", "Cargo.toml", "build.sbt", "setup.py", "pyproject.toml"}
)
BUILD_FILE_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
# A folder with this file is a Python virtual environment.
VENV_MARKER = "pyvenv.cfg"
# The record keeps at most this many names of skipped folders.
MAX_SKIPPED_NAMES = 50


def route_of(files: int, threshold: int = LARGE_REPO_FILES) -> str:
    """The route of a count: more than ``threshold`` files is the single agent."""
    return ROUTE_AGENT if files > threshold else ROUTE_FUNNEL


def skipped_folder(name: str, relative: str, beside: Collection[str] = ()) -> bool:
    """Whether the folder ``relative`` (its path below the root, with "/") holds no code of the project.

    ``name`` is the last part of ``relative``; ``beside`` holds the names of
    the files and folders next to it.
    """
    if name in SKIP_DIRS or name in EXTRA_SKIPPED:
        return True
    if SKIPPED_TAGS & path_tags(relative + "/_"):
        return True
    return name.lower() in BUILD_FOLDERS and any(item in BUILD_FILES or item.endswith(BUILD_FILE_SUFFIXES) for item in beside)


@dataclass(frozen=True)
class FileCount:
    """The count of a repository: the counted files, and the skipped folders with their files."""

    files: int
    skipped_folders: int = 0
    skipped_files: int = 0
    skipped_names: tuple[str, ...] = ()


def _is_file(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_file(follow_symlinks=False)
    except OSError:
        return False


def _files_below(folders: list[str], limit: int) -> int:
    """The regular files in ``folders`` and below them (links not followed), counted up to ``limit``."""
    count = 0
    stack = list(folders)
    # The folders that one count reads: a tree of empty folders cannot make the count slow.
    visits = 10 * limit
    while stack and count < limit and visits > 0:
        visits -= 1
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    count += 1
            except OSError:
                continue
    return min(count, limit)


def count_files(root: Path, limit: int) -> FileCount:
    """The regular files of ``root`` outside the skipped folders (``skipped_folder``), counted up to ``limit``.

    Links are not followed and do not count, and a folder that cannot be
    read does not count. The root always counts. The skipped folders are
    the folders that the count saw before it stopped; their files are
    counted up to ``limit`` too.
    """
    count = 0
    skipped: list[str] = []
    names: set[str] = set()
    stack: list[tuple[str, str]] = [(str(root), "")]
    while stack and count < limit:
        folder, relative = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        beside = {entry.name for entry in entries}
        if relative and VENV_MARKER in beside and _is_file(next(entry for entry in entries if entry.name == VENV_MARKER)):
            skipped.append(folder)
            names.add(relative.rsplit("/", 1)[-1])
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    path = f"{relative}/{entry.name}" if relative else entry.name
                    if skipped_folder(entry.name, path, beside):
                        skipped.append(entry.path)
                        names.add(entry.name)
                    else:
                        stack.append((entry.path, path))
                elif entry.is_file(follow_symlinks=False):
                    count += 1
            except OSError:
                continue
            if count >= limit:
                break
    return FileCount(count, len(skipped), _files_below(skipped, limit), tuple(sorted(names)[:MAX_SKIPPED_NAMES]))


@dataclass(frozen=True)
class RouteDecision:
    route: str
    files_counted: int
    counted_up_to: int
    threshold: int
    seconds: float
    skipped_folders: int = 0
    skipped_files: int = 0
    skipped_names: tuple[str, ...] = ()

    def record(self) -> dict[str, Any]:
        return {
            "rule": RULE,
            "route": self.route,
            "files_counted": self.files_counted,
            "counted_up_to": self.counted_up_to,
            "large_repo_files": self.threshold,
            # The folders without code of the project that the count left out, and their files (up to counted_up_to).
            "skipped": {"folders": self.skipped_folders, "files": self.skipped_files, "names": list(self.skipped_names)},
            "seconds": round(self.seconds, 4),
        }


def decide(repository: Path, threshold: int = LARGE_REPO_FILES) -> RouteDecision:
    """Count the files of ``repository`` (up to ``threshold + 1``) and select the route."""
    if threshold < 1:
        raise ValueError("the threshold of the router must be positive")
    started = time.monotonic()
    found = count_files(repository, threshold + 1)
    return RouteDecision(
        route_of(found.files, threshold),
        found.files,
        threshold + 1,
        threshold,
        time.monotonic() - started,
        skipped_folders=found.skipped_folders,
        skipped_files=found.skipped_files,
        skipped_names=found.skipped_names,
    )
