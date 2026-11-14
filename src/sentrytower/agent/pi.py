"""The configuration and the command of the agent: the Pi coding agent in print mode.

The agent gets the Pi built-in tools read, grep, find and ls, and nothing
else: Pi loads no skill, prompt template, theme, context file, project
file of the audited repository or other extension, only two extensions of
SentryTower. ``--no-extensions`` also keeps out the extensions that Pi
builds in (codemode, tool search, MCP and llama.cpp): Pi loads one of them
only when ``--extension builtin:NAME`` names it. ``--no-approve`` makes
Pi ignore the ``.pi`` folder of the repository, its settings and its
``mcp.json`` included. It does not stop the migration that Pi 1.5.0 runs at
its start, before it reads any settings: a folder ``.pi/commands`` of the
repository becomes ``.pi/prompts`` when no ``.pi/prompts`` exists
(SECURITY.md). The two extensions:

- numbered-read: a ``tool_result`` hook that puts the line number in front
  of each line of a text read result (``{n:>5}│``);
- repository-guard: a ``tool_call`` hook that refuses a call whose path is
  outside the audited repository and the Pi package, after symbolic links
  (for example ``/proc/1/environ`` or a link in the repository that points
  out of it).

Neither changes a tool, a schema or the system prompt.

The agent folder (``PI_CODING_AGENT_DIR``) holds:

- ``settings.json``: the default provider and model, the thinking level of
  the model policy, a long idle timeout and no retry in the agent (the
  gateway retries);
- ``models.json``: the model catalog of the provider ``openrouter`` with
  the URL of the local gateway, a reference to the variable that holds the
  credential of the run, and one entry for each model of the run, with
  temperature 1.0 as a sampling parameter;
- ``bin/rg`` and ``bin/fd``: links to ripgrep and fd (the grep and find
  tools of Pi run them; ``PI_OFFLINE=1`` stops a download);
- ``pi-ext/numbered-read.ts`` and ``pi-ext/repository-guard.ts``: the extensions;
- ``pi-package``: a link to the Pi package, so that the documentation path
  that Pi shows in its system prompt is a neutral path.

These files are the files of the measured runs, byte for byte, with three
exceptions. The credential reference: the measured runs gave Pi a literal
placeholder key, and the gateway of a release run checks a random
credential of the run. The repository guard: the measured runs ran each
agent in a sandbox that held nothing else to read, and a release run can
hold the provider key and other files next to the repository. The
numbered-read extension: its comments and type annotations name Pi
1.5.0; without them its code is the measured code.

The measured runs ran Pi 0.84.1 with the same command and files. Pi 1.5.0
sends another system prompt and leaves ``"strict": false`` out of each
tool definition; the task prompt, the tool descriptions and parameters and
the tool results are the same.
"""

from __future__ import annotations

import json
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from ..limits import CREDENTIAL_VARIABLE
from ..policies import ModelPolicy
from ..programs import which
from .runner import AGENT_TOOLS, LIMIT_FRACTION, RESERVE_FRACTION

PI_PACKAGE = "@earendil-works/pi-coding-agent"
PI_VERSION = "1.5.0"
PROVIDER = "openrouter"
EXTENSION_NAME = "numbered-read"
EXTENSION_SOURCE = "numbered_read.ts"
GUARD_NAME = "repository-guard"
GUARD_SOURCE = "repository_guard.ts"
EXTENSION_DIRECTORY = "pi-ext"
PACKAGE_LINK = "pi-package"
NATIVE_TOOLS = ("rg", "fd")
# One explicit temperature for every endpoint. Pi merges it into each request.
SAMPLING = {"temperature": 1.0}
PROMPT_PACKAGE = "sentrytower.prompts"
AUDIT_PROMPT_FILES = ("agent-audit.txt", "agent-output.txt", "agent-findings.schema.json")
FINAL_MESSAGE_FILE = "agent-final.txt"
# The places of the Pi CLI (the ``bin`` of its package) in the container image and in a global npm install.
PI_CANDIDATES = ("/opt/pi/dist/bundle/cli.js", "/usr/local/bin/pi")


def _prompt(name: str) -> str:
    return resources.files(PROMPT_PACKAGE).joinpath(name).read_text(encoding="utf-8")


def audit_prompt() -> str:
    """The task prompt of the agent: the audit request, the output contract and the findings schema."""
    return "\n\n".join(_prompt(name).strip() for name in AUDIT_PROMPT_FILES) + "\n"


def final_message() -> str:
    """The message of the final turn."""
    return _prompt(FINAL_MESSAGE_FILE).strip()


def find_pi(configured: str | None = None) -> Path | None:
    """The Pi CLI: the configured path, ``SENTRYTOWER_PI``, ``pi`` on PATH, or the image path.

    The result is an absolute path, and the PATH lookup reads the absolute
    entries only (``programs.which``): the engines run in the audited
    repository, where a relative path names another program.
    """
    for candidate in (configured, os.environ.get("SENTRYTOWER_PI"), which("pi"), *PI_CANDIDATES):
        if candidate and Path(candidate).is_file():
            return Path(candidate).absolute()
    return None


def pi_package_directory(cli: Path) -> Path:
    """The package folder of the Pi CLI: the nearest folder above the script, after links, with a ``package.json``.

    The ``bin`` of the package is ``dist/bundle/cli.js``; ``dist/cli.js``
    also runs Pi. Either finds the package.
    """
    script = cli.resolve()
    package = next((folder for folder in script.parents if (folder / "package.json").is_file()), None)
    if package is None:
        raise ValueError(f"{cli} is not the {PI_PACKAGE} command")
    manifest = json.loads((package / "package.json").read_text())
    if manifest.get("name") != PI_PACKAGE:
        raise ValueError(f"{cli} is not the {PI_PACKAGE} command")
    return package


def pi_version(cli: Path) -> str | None:
    try:
        return str(json.loads((pi_package_directory(cli) / "package.json").read_text()).get("version"))
    except (OSError, ValueError):
        return None


def find_tool(name: str, configured: str | None = None) -> Path | None:
    """A native tool of the agent: ripgrep (``rg``) or fd (``fd``, ``fdfind`` on Debian).

    As ``find_pi``: an absolute path, from the absolute entries of PATH only.
    """
    names = (name, "fdfind") if name == "fd" else (name,)
    for candidate in (configured, *(which(item) for item in names)):
        if candidate and Path(candidate).is_file():
            return Path(candidate).absolute()
    return None


def write_agent_config(agent_directory: Path, gateway_url: str, policies: Iterable[ModelPolicy]) -> None:
    """Write the agent ``settings.json`` and ``models.json``: the first policy is the default model."""
    ordered = list(policies)
    if not ordered:
        raise ValueError("the agent needs at least one model")
    models: list[dict[str, object]] = []
    for policy in ordered:
        definition = policy.pi_definition()
        definition["samplingParams"] = dict(SAMPLING)
        models.append(definition)
    agent_directory.mkdir(parents=True, exist_ok=True)
    settings: dict[str, Any] = {
        "defaultProvider": PROVIDER,
        "defaultModel": ordered[0].model_id,
        "defaultThinkingLevel": ordered[0].thinking_level(),
        "httpIdleTimeoutMs": 1_200_000,
        "retry": {
            "provider": {
                "timeoutMs": 1_200_000,
                "maxRetries": 0,
                "maxRetryDelayMs": 60_000,
            }
        },
    }
    (agent_directory / "settings.json").write_text(json.dumps(settings, indent=2) + "\n")
    # The entry overrides the built-in provider: the gateway URL and a reference
    # ("$NAME") to the variable that holds the credential of the run. The
    # credential goes in the authorization header only; the request bodies are
    # the bodies of the measured runs.
    provider = {"baseUrl": gateway_url, "apiKey": f"${CREDENTIAL_VARIABLE}", "models": models}
    (agent_directory / "models.json").write_text(json.dumps({"providers": {PROVIDER: provider}}, indent=2) + "\n")


def prepare_agent_directory(agent_directory: Path, *, pi_cli: Path, tools: dict[str, Path]) -> Path:
    """Link the native tools and a neutral Pi package path into the agent folder; copy the extension.

    Returns the package link, the value of ``PI_PACKAGE_DIR``.
    """
    binaries = agent_directory / "bin"
    binaries.mkdir(parents=True, exist_ok=True)
    for name in NATIVE_TOOLS:
        if name in tools:
            target = binaries / name
            if target.is_symlink() or target.exists():
                target.unlink()
            target.symlink_to(tools[name].resolve())
    for path, source in ((extension_path(agent_directory), EXTENSION_SOURCE), (guard_path(agent_directory), GUARD_SOURCE)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(resources.files("sentrytower.agent").joinpath(source).read_bytes())
        path.chmod(0o644)
    package = agent_directory / PACKAGE_LINK
    if package.is_symlink() or package.exists():
        package.unlink()
    package.symlink_to(pi_package_directory(pi_cli))
    return package


def extension_path(agent_directory: Path) -> Path:
    return agent_directory / EXTENSION_DIRECTORY / f"{EXTENSION_NAME}.ts"


def guard_path(agent_directory: Path) -> Path:
    return agent_directory / EXTENSION_DIRECTORY / f"{GUARD_NAME}.ts"


def agent_command(
    *,
    pi_cli: Path,
    session_directory: Path,
    agent_directory: Path,
    model: str,
    prompt: str,
    final: str,
    token_budget: int,
    wall_clock_seconds: int,
    python: str = sys.executable,
    budget_url: str | None = None,
) -> list[str]:
    """The agent runner around Pi in print mode: the runner part, ``--``, the Pi command, the prompt last.

    ``budget_url`` (the model gateway of a run with a cost cap) lets the
    runner end the first turn when the money says that new work must stop.
    """
    if not model or not prompt.strip() or not final.strip():
        raise ValueError("the agent needs a model, a prompt and a final message")
    if token_budget < 1 or wall_clock_seconds < 1:
        raise ValueError("the agent needs a positive token budget and wall clock")
    # -P: the working folder of the runner is the audited repository; Python must not import a module from it.
    runner = [python, "-P", "-m", "sentrytower.agent.runner", "--session-dir", str(session_directory), "--final-message", final]
    runner += ["--token-budget", str(token_budget), "--wall-clock-seconds", str(wall_clock_seconds)]
    runner += ["--reserve-fraction", str(RESERVE_FRACTION), "--limit-fraction", str(LIMIT_FRACTION)]
    if budget_url:
        runner += ["--budget-url", budget_url]
    agent = [str(pi_cli), "--provider", PROVIDER, "--model", model, "--print", "--session-dir", str(session_directory)]
    agent += ["--no-extensions", "--extension", str(extension_path(agent_directory)), "--extension", str(guard_path(agent_directory))]
    agent += ["--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve"]
    agent += ["--tools", ",".join(AGENT_TOOLS)]
    return [*runner, "--", *agent, prompt]


def agent_environment(agent_directory: Path, package_link: Path, credential: str) -> dict[str, str]:
    """The variables of each agent session: the agent folder, the package link, offline mode and the credential."""
    return {
        "PI_CODING_AGENT_DIR": str(agent_directory),
        "PI_PACKAGE_DIR": str(package_link),
        "PI_OFFLINE": "1",
        CREDENTIAL_VARIABLE: credential,
    }
