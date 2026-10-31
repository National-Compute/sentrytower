"""The provider key in the keychain of the system: the macOS Keychain or the Secret Service of Linux.

Only the setup writes the key, and only when the person asks for it. The
key goes to the keychain tool on stdin, never as an argument (an argument
is visible to the other processes of the computer). A run reads the key
from the keychain only when the configuration says so
(``provider.keychain = true``) and the environment holds no key.

Each keychain tool runs from its absolute path on the absolute entries of
PATH (``programs.which``): a run can start in the audited repository, and a
program of the repository must never get the key.
"""

from __future__ import annotations

import subprocess
import sys

from ..programs import which

SERVICE = "sentrytower"
ACCOUNT = "provider-key"
TOOLS = {"macos": "security", "secret-service": "secret-tool"}


def backend() -> str | None:
    """macos, secret-service, or None when this computer has no supported keychain."""
    if sys.platform == "darwin" and which(TOOLS["macos"]):
        return "macos"
    if sys.platform.startswith("linux") and which(TOOLS["secret-service"]):
        return "secret-service"
    return None


def _tool(kind: str) -> str:
    """The absolute path of the tool of a keychain; OSError when it is gone."""
    path = which(TOOLS[kind])
    if path is None:
        raise OSError(f"{TOOLS[kind]} is not on PATH")
    return path


def label() -> str:
    return {"macos": "the macOS Keychain", "secret-service": "the system keyring"}.get(backend() or "", "a keychain")


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def store(key: str) -> None:
    """Save the key; raises OSError when the keychain refuses it."""
    kind = backend()
    if kind == "macos":
        # security -i reads its commands from stdin, so the key is never an argument.
        command = (
            f"add-generic-password -U -a {_quote(ACCOUNT)} -s {_quote(SERVICE)} -l {_quote('SentryTower provider key')} -w {_quote(key)}\n"
        )
        completed = subprocess.run([_tool(kind), "-i"], input=command, capture_output=True, text=True, timeout=30, check=False)
    elif kind == "secret-service":
        completed = subprocess.run(
            [_tool(kind), "store", "--label=SentryTower provider key", "service", SERVICE, "account", ACCOUNT],
            input=key,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    else:
        raise OSError("this computer has no supported keychain")
    if completed.returncode != 0:
        raise OSError(f"the keychain refused the key (exit {completed.returncode})")


def read() -> str | None:
    """The saved key, or None."""
    kind = backend()
    if kind == "macos":
        argv = ["find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"]
    elif kind == "secret-service":
        argv = ["lookup", "service", SERVICE, "account", ACCOUNT]
    else:
        return None
    try:
        completed = subprocess.run([_tool(kind), *argv], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip() if completed.returncode == 0 else ""
    return value or None
