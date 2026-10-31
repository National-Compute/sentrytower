"""The search path of the programs that SentryTower and its engines start: absolute folders only.

The engines and the agent sessions run in the audited repository. An entry
of PATH that is not absolute (an empty entry, ".", or a name such as
``node_modules/.bin``) names a folder below the working folder, so a program
of the audited repository could run in place of node, rg or fd. The parent
often runs in the repository too (``sentrytower audit .``).

Thus each environment of an engine, an agent session, Pi and its tools keeps
only the absolute entries of PATH (``search_path``, ``program_environment``),
and each lookup of a program (``which``) reads only those entries. The parent
also leaves out of the environment of the engines each entry that is in the
audited repository.

Other variables make a program load code or settings from a path: an empty
or relative entry of PYTHONPATH names the working folder, so Python imports
a module of the repository; NODE_OPTIONS can require a file; a relative
RIPGREP_CONFIG_PATH makes the grep tool read a configuration (and run a
``--pre`` program) of the repository. The search paths among them
(``SEARCH_PATH_VARIABLES``) keep the same entries as PATH, and the others
(``DROPPED_VARIABLES``), which no engine needs, are left out.

Standard library only: the funnel and the agent runner run in their own
processes and import this module.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Mapping
from pathlib import Path

# The search paths of code: each one keeps its absolute entries outside the audited repository, as PATH does.
SEARCH_PATH_VARIABLES = (
    "PYTHONPATH",
    "NODE_PATH",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
)
# The variables that load a library, a module or a configuration file, or that start code: no engine needs one.
DROPPED_VARIABLES = ("NODE_OPTIONS", "RIPGREP_CONFIG_PATH", "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES")


def _absolute_entries(value: str | None, folders: list[str]) -> list[str]:
    """The absolute entries of a search path ``value`` outside the resolved ``folders``, in their order."""
    kept: list[str] = []
    for entry in (value or "").split(os.pathsep):
        if not entry or not Path(entry).is_absolute():
            continue
        if folders:
            real = os.path.realpath(entry)
            if any(real == folder or real.startswith(folder.rstrip(os.sep) + os.sep) for folder in folders):
                continue
        kept.append(entry)
    return kept


def search_path(value: str | None, *, outside: Iterable[str | os.PathLike[str]] = ()) -> str:
    """The absolute entries of the PATH ``value``, in their order.

    An empty entry, "." and each other relative entry are left out, and so
    is each entry in one of the folders ``outside`` (after links). When no
    entry stays, the result is the default search path of the system
    (``os.defpath``): an empty PATH makes a program search start in the
    working folder.
    """
    return os.pathsep.join(_absolute_entries(value, [os.path.realpath(folder) for folder in outside])) or os.defpath


def program_environment(environment: Mapping[str, str], *, outside: Iterable[str | os.PathLike[str]] = ()) -> dict[str, str]:
    """A copy of ``environment`` with the PATH of ``search_path``; an environment without PATH keeps none.

    Each of ``SEARCH_PATH_VARIABLES`` keeps the same entries as PATH, and is
    left out when none stays; ``DROPPED_VARIABLES`` are left out.
    """
    folders = [os.path.realpath(folder) for folder in outside]
    result = {name: value for name, value in environment.items() if name not in DROPPED_VARIABLES}
    if "PATH" in result:
        result["PATH"] = search_path(result["PATH"], outside=folders)
    for name in SEARCH_PATH_VARIABLES:
        if name in result:
            kept = _absolute_entries(result[name], folders)
            if kept:
                result[name] = os.pathsep.join(kept)
            else:
                del result[name]
    return result


def which(name: str, path: str | None = None) -> str | None:
    """The absolute path of the program ``name`` on the absolute entries of ``path`` (default: PATH), or None.

    ``name`` is the name of a program, not a path: a name with a folder gives None.
    """
    if os.sep in name:
        return None
    return shutil.which(name, path=search_path(os.environ.get("PATH") if path is None else path))
