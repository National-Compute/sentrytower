"""``sentrytower doctor``: check the environment of a run before the first audit.

The checks: Python, Node.js, the Pi CLI and its version, ripgrep, fd, the
provider key (present or missing; the value is never printed), and one tiny
request to the endpoint (skipped with ``--offline``).
"""

from __future__ import annotations

import http.client
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

from . import __version__
from .agent import pi
from .config import Config
from .gateway import http_transport, proxy_problem, read_response
from .policies import canonical_json
from .programs import which

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
PYTHON_MINIMUM = (3, 11)
NODE_MINIMUM = (22, 19, 0)
PINNED_TOOLS = {"rg": "15.2.0", "fd": "10.5.0"}
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass
class Check:
    name: str
    status: str
    detail: str
    hint: str | None = None

    def record(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail, "hint": self.hint}


def _version(text: str) -> tuple[int, ...] | None:
    match = _VERSION.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def _command_version(argv: list[str]) -> str | None:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr).strip()
    return text.splitlines()[0] if text else None


def check_python() -> Check:
    found = sys.version_info[:3]
    text = ".".join(str(part) for part in found)
    if found[:2] < PYTHON_MINIMUM:
        return Check("python", FAIL, f"Python {text}", "SentryTower needs Python 3.11 or later")
    return Check("python", OK, f"Python {text}")


def check_node() -> Check:
    # The absolute entries of PATH only: doctor often runs in a repository (programs.which).
    node = which("node")
    if node is None:
        return Check("node", FAIL, "node is not on PATH", "install Node.js 22.19 or later (the Pi CLI runs on Node.js)")
    text = _command_version([node, "--version"]) or ""
    found = _version(text)
    if found is None or found < NODE_MINIMUM:
        return Check("node", FAIL, f"Node.js {text or 'unknown'}", "the Pi CLI needs Node.js 22.19 or later")
    return Check("node", OK, f"Node.js {text.lstrip('v')}")


def check_pi(config: Config) -> Check:
    cli = pi.find_pi(config.tools.pi)
    install = f"npm install -g {pi.PI_PACKAGE}@{pi.PI_VERSION}"
    if cli is None:
        return Check("pi", FAIL, "the Pi CLI is not installed", f"run `{install}` or set SENTRYTOWER_PI")
    try:
        pi.pi_package_directory(cli)
    except (OSError, ValueError):
        return Check("pi", FAIL, f"{cli} is not the {pi.PI_PACKAGE} CLI", f"run `{install}`")
    version = pi.pi_version(cli)
    if version != pi.PI_VERSION:
        hint = f"the pinned version is {pi.PI_VERSION}, and another version can change the model requests: run `{install}`"
        return Check("pi", WARN, f"Pi {version} at {cli}", hint)
    return Check("pi", OK, f"Pi {version} at {cli}")


def check_tool(name: str, config: Config) -> Check:
    path = pi.find_tool(name, getattr(config.tools, name))
    label = "ripgrep" if name == "rg" else "fd"
    if path is None:
        return Check(name, FAIL, f"{label} is not on PATH", f"install {label} {PINNED_TOOLS[name]} (the agent search tools run it)")
    text = _command_version([str(path), "--version"]) or ""
    found = _version(text)
    wanted = _version(PINNED_TOOLS[name])
    if found != wanted:
        detail = f"{label} {'.'.join(map(str, found or ())) or 'unknown'} at {path}"
        return Check(name, WARN, detail, f"the pinned version is {PINNED_TOOLS[name]}")
    return Check(name, OK, f"{label} {PINNED_TOOLS[name]} at {path}")


def check_key(config: Config) -> Check:
    key, variable = config.api_key()
    names = " or ".join(config.provider.api_key_env)
    if key is None:
        if not config.provider.require_api_key:
            return Check("api key", OK, f"not set ({names}); the endpoint needs no key")
        return Check("api key", FAIL, f"not set ({names})", f"export {config.provider.api_key_env[0]}=<your key>")
    return Check("api key", OK, f"set in {variable} ({len(key)} characters; the value is not shown)")


def check_endpoint(config: Config) -> Check:
    key, _ = config.api_key()
    if key is None and config.provider.require_api_key:
        return Check("endpoint", SKIP, "no key", None)
    model = config.default_model
    policy = config.policies([model])[model]
    payload, _ = policy.rewrite({"model": model, "messages": [{"role": "user", "content": "Reply with the word OK."}]})
    payload[policy.token_field] = 256
    if "reasoning" in payload:
        payload["reasoning"] = {"effort": "low"}
    headers = {"content-type": "application/json", **dict(config.provider.headers)}
    if key:
        headers["authorization"] = f"Bearer {key}"
    url = config.provider.base_url.rstrip("/") + "/chat/completions"
    problem = proxy_problem(config.provider.base_url)
    if problem:
        return Check("endpoint", FAIL, problem, "set HTTPS_PROXY to an http:// proxy URL")
    started = time.monotonic()
    try:
        status, content_type, body = http_transport(url, canonical_json(payload), headers, 60.0)
    except (OSError, TimeoutError, ValueError, http.client.HTTPException) as error:
        return Check("endpoint", FAIL, f"{config.provider.base_url}: {type(error).__name__}", "check the base URL and the network")
    seconds = time.monotonic() - started
    if status in (401, 403):
        return Check("endpoint", FAIL, f"HTTP {status}: the endpoint refused the key", "check the key and its credit")
    if status != 200:
        return Check("endpoint", FAIL, f"HTTP {status} for {model}", "check the model ID, the policy and the endpoint")
    usage, failed, _ = read_response(body, content_type)
    if failed:
        return Check("endpoint", FAIL, f"the provider reported an error for {model}", None)
    tokens = (usage or {}).get("total_tokens")
    return Check("endpoint", OK, f"{model} answered in {seconds:.1f} s ({tokens or 'unknown'} tokens)")


def run_checks(config: Config, *, offline: bool = False) -> list[Check]:
    checks = [check_python(), check_node(), check_pi(config), check_tool("rg", config), check_tool("fd", config), check_key(config)]
    checks.append(Check("endpoint", SKIP, "offline") if offline else check_endpoint(config))
    return checks


def render(checks: list[Check], *, as_json: bool = False) -> str:
    if as_json:
        return json.dumps({"version": __version__, "checks": [check.record() for check in checks]}, indent=2)
    marks = {OK: "ok  ", WARN: "warn", FAIL: "FAIL", SKIP: "skip"}
    lines = [f"SentryTower {__version__} doctor"]
    for check in checks:
        lines.append(f"  [{marks[check.status]}] {check.name:<9} {check.detail}")
        if check.hint and check.status in (WARN, FAIL):
            lines.append(f"         {'':<9} -> {check.hint}")
    failed = sum(1 for check in checks if check.status == FAIL)
    lines.append("All checks passed." if not failed else f"{failed} check(s) failed.")
    return "\n".join(lines)
