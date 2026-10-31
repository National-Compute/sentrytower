"""The configuration of a run: a TOML file, then environment variables, then command-line options.

The TOML file is ``--config FILE`` or ``SENTRYTOWER_CONFIG``; else the file of
a profile (``--profile NAME``: ``~/.config/sentrytower/profiles/NAME.toml``);
else the user's file that ``sentrytower setup`` writes
(``~/.config/sentrytower/config.toml``), when it exists.

Single-LLM (the default): one model for every role. Multi-LLM:
``[models]`` can give another model to each role of the funnel and to the
single agent.

The budget: a cost cap (``max_cost_usd``) in US dollars, $2 when no source
gives one and each model of the route has prices (``Config.cost_cap``). The
cap sets the depth and the token plan of a run, from the prices of its
models (``budget.plan_tokens``); ``max_tokens`` is an upper limit. A cap of
0 means no cap: the ceiling is then ``max_tokens``, else 20,000,000. A cap
that the person gives for a route with a model without prices is an error
(``Config.check_cost_cap``): the cap could not stop the run.

Roles:

| Role | Engine | Work |
| --- | --- | --- |
| ``rating`` | funnel | rates unit cards when the queue is larger than the unit-check budget |
| ``unit_check`` | funnel | one plain question for each code unit |
| ``triage`` | funnel | one blind verification of each lead |
| ``verify`` | funnel | one blind verification of each deep-check finding |
| ``deep_check`` | funnel | one agent session for each unit with a triaged lead |
| ``free_roaming`` | funnel | one agent session on the whole repository |
| ``agent`` | single agent | the agent session of a repository with more than 1,000 files |

The provider key is never part of the configuration: it comes from the
environment only (``SENTRYTOWER_API_KEY``, else ``OPENROUTER_API_KEY``, or
the variables that ``provider.api_key_env`` names). SentryTower never reads
a configuration file from the audited repository: give the file with
``--config`` or ``SENTRYTOWER_CONFIG``.
"""

from __future__ import annotations

import math
import os
import re
import tomllib
import urllib.parse
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from .budget import STANDARD_COST_USD, TokenPlan, plan_tokens, unpriced_models, worst_call
from .funnel.pacing import Parameters
from .policies import BUILTIN_POLICIES, DEFAULT_MODEL, ModelPolicy, policy_from_table, resolve_policies
from .router import LARGE_REPO_FILES

FUNNEL_ROLES = ("rating", "unit_check", "triage", "verify", "deep_check", "free_roaming")
AGENT_ROLE = "agent"
ROLES = (*FUNNEL_ROLES, AGENT_ROLE)
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_KEY_VARIABLES = ("SENTRYTOWER_API_KEY", "OPENROUTER_API_KEY")
DEFAULT_WALL_CLOCK_SECONDS = 14_400
DEFAULT_PARALLEL_REQUESTS = 8
PROJECT_URL = "https://github.com/National-Compute/sentrytower"
DEFAULT_HEADERS = {"X-Title": "SentryTower", "HTTP-Referer": PROJECT_URL}
CONFIG_VARIABLE = "SENTRYTOWER_CONFIG"
PROFILE_VARIABLE = "SENTRYTOWER_PROFILE"
TOP_LEVEL_KEYS = frozenset({"models", "provider", "budget", "router", "tools", "policies", "funnel", "run", "ui"})
# The roles of the two-model setup (--fast-model and --agent-model): the short calls, and the agent sessions.
FAST_ROLES = ("rating", "unit_check", "triage", "verify")
AGENT_ROLES = ("deep_check", "free_roaming", "agent")
SEVERITY_NAMES = ("critical", "high", "medium", "low")
AGENT_COLOR_NAMES = ("cobalt", "moss", "coral", "plum", "sand")
_AGENT_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,24}$")
_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
SECRET_KEYS = frozenset(
    {"api_key", "apikey", "api-key", "key", "token", "access_token", "secret", "client_secret", "password", "authorization", "bearer"}
)
# Header names that carry a credential: the gateway sets the authorization header from the environment only.
_SECRET_HEADER = re.compile(r"(?i)^(authorization|proxy-authorization|cookie)$|api[-_]?key|token|secret|auth|passw|credential|session")
_VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ConfigError(ValueError):
    """The configuration is not valid. The message names the field, never a secret value."""


@dataclass(frozen=True)
class ProviderConfig:
    base_url: str = DEFAULT_BASE_URL
    api_key_env: tuple[str, ...] = DEFAULT_KEY_VARIABLES
    require_api_key: bool = True
    max_parallel_requests: int = DEFAULT_PARALLEL_REQUESTS
    headers: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_HEADERS))
    # Read the key from the system keychain when the environment holds none (setup saves it there on request).
    keychain: bool = False


@dataclass(frozen=True)
class UiConfig:
    """The agent of the interactive screens: its name and colour, and the terminal theme (auto, dark or light)."""

    agent_name: str = "Juno"
    agent_color: str = "sand"
    theme: str = "auto"


@dataclass(frozen=True)
class BudgetConfig:
    # The token ceiling; None: the tokens that the cost cap buys, else DEFAULT_MAX_TOKENS (``Config.token_plan``).
    max_tokens: int | None = None
    wall_clock_seconds: int = DEFAULT_WALL_CLOCK_SECONDS
    # The cost cap in US dollars: None when no source gives one (the default cap applies, ``Config.cost_cap``),
    # 0 for no cap.
    max_cost_usd: float | None = None


@dataclass(frozen=True)
class ToolsConfig:
    pi: str | None = None
    rg: str | None = None
    fd: str | None = None


@dataclass(frozen=True)
class Config:
    """The resolved configuration of a run."""

    default_model: str = DEFAULT_MODEL
    role_overrides: Mapping[str, str] = field(default_factory=dict)
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    large_repo_files: int = LARGE_REPO_FILES
    funnel_parameters: Mapping[str, Any] = field(default_factory=dict)
    policy_tables: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    state_dir: str | None = None
    # The output folder and the severity of --fail-on when the command line gives none.
    out_dir: str | None = None
    fail_on: str | None = None
    # Open report.html when an audit in a terminal ends.
    open_report: bool = True
    ui: UiConfig = field(default_factory=UiConfig)
    sources: tuple[str, ...] = ()

    def model_for(self, role: str) -> str:
        if role not in ROLES:
            raise ConfigError(f"unknown role {role!r}; the roles are {', '.join(ROLES)}")
        return self.role_overrides.get(role) or self.default_model

    @property
    def models(self) -> dict[str, str]:
        """The model of each role."""
        return {role: self.model_for(role) for role in ROLES}

    @property
    def single_model(self) -> bool:
        return len(set(self.models.values())) == 1

    def models_of(self, route: str) -> dict[str, str]:
        """The roles that a route uses and their models."""
        roles = FUNNEL_ROLES if route == "funnel" else (AGENT_ROLE,)
        return {role: self.model_for(role) for role in roles}

    def policies(self, models: list[str] | None = None) -> dict[str, ModelPolicy]:
        """The request policy of each model (all models of the configuration by default)."""
        try:
            return resolve_policies(list(models or self.models.values()), self.policy_tables)
        except ValueError as error:
            raise ConfigError(str(error)) from None

    def parameters(self) -> Parameters:
        """The funnel parameters: the defaults, changed by ``[funnel]`` and the threshold."""
        values = {**Parameters().record(), **dict(self.funnel_parameters), "large_repo_files": self.large_repo_files}
        try:
            return Parameters.from_record(values)
        except ValueError as error:
            raise ConfigError(f"[funnel]: {error}") from None

    def cost_cap(self, route: str) -> float | None:
        """The cost cap of a run on ``route`` in US dollars, or None for no cap.

        The cap of the settings; when none gives one, $2 (the standard run)
        if each model of the route has prices, else no cap. A cap of 0 is no
        cap.
        """
        if self.budget.max_cost_usd is not None:
            return self.budget.max_cost_usd or None
        if unpriced_models(self.policies(list(self.models_of(route).values())).values(), route):
            return None
        return STANDARD_COST_USD

    def check_cost_cap(self, route: str) -> None:
        """The checks of the cost cap of a run on ``route`` before the run; ConfigError names the problem and the fix.

        A cap that the person gave needs the prices of each model of the
        route. A cap (also the default cap) must pay for one model call at
        its worst case (``budget.worst_call``), else the gateway refuses each
        call of the run.
        """
        policies = list(self.policies(list(self.models_of(route).values())).values())
        if self.budget.max_cost_usd:
            missing = unpriced_models(policies, route)
            if missing:
                raise ConfigError(
                    f"the cost cap of ${self.budget.max_cost_usd:.2f} needs the prices of {missing[0]}: add input_cost_per_million and "
                    f'output_cost_per_million to its [policies."{missing[0]}"] table, or remove the cap (--max-cost-usd 0)'
                )
        cap, worst = self.cost_cap(route), worst_call(policies)
        if cap is None or worst is None or cap > worst[1]:
            return
        policy, cost = worst
        # The next whole cent above the worst case.
        needed = math.floor(cost * 100) / 100 + 0.01
        raise ConfigError(
            f"the {'default ' if self.budget.max_cost_usd is None else ''}cost cap of ${cap:.2f} cannot pay for one model call: "
            f"a call of {policy.model_id} can cost up to ${cost:.4f} ({policy.max_completion_tokens:,} completion tokens at "
            f"${policy.output_cost_per_million or 0:.2f} for one million); give a cap of at least ${needed:.2f} (--max-cost-usd)"
        )

    def unpriced_note(self, route: str) -> str | None:
        """The warning of a run without a cap because a model of the route has no prices, else None."""
        if self.budget.max_cost_usd is not None:
            return None
        missing = unpriced_models(self.policies(list(self.models_of(route).values())).values(), route)
        if not missing:
            return None
        return (
            f"the prices of {missing[0]} are not known, so the run has no cost cap and the standard ceiling of "
            f"{self.token_plan(route).tokens:,} tokens; add its prices to its [policies] table for the ${STANDARD_COST_USD:.0f} cap"
        )

    def token_plan(self, route: str) -> TokenPlan:
        """The token plan of a run on ``route``: from the cost cap and the prices of the models of the route."""
        models = list(self.models_of(route).values())
        return plan_tokens(self.budget.max_tokens, self.cost_cap(route), self.policies(models).values(), route)

    def record(self) -> dict[str, Any]:
        """The configuration for run.json: no secret, only the names of the key variables."""
        policies = self.policies()
        return {
            "models": self.models,
            "single_model": self.single_model,
            "provider": {
                "base_url": self.provider.base_url,
                "api_key_env": list(self.provider.api_key_env),
                "max_parallel_requests": self.provider.max_parallel_requests,
            },
            "budget": {
                "max_tokens": self.budget.max_tokens,
                "wall_clock_seconds": self.budget.wall_clock_seconds,
                "max_cost_usd": self.budget.max_cost_usd,
            },
            "router": {"large_repo_files": self.large_repo_files},
            "agent": {"name": self.ui.agent_name, "color": self.ui.agent_color},
            "funnel_parameters": dict(self.funnel_parameters),
            "policies": {model: policy.record() for model, policy in policies.items()},
            "sources": list(self.sources),
        }

    def api_key(self, environment: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
        """The provider key and its source: an environment variable, else the system keychain when
        ``provider.keychain`` is on. The key is never part of a file of the configuration."""
        env = os.environ if environment is None else environment
        for name in self.provider.api_key_env:
            value = env.get(name)
            if value and value.strip():
                return value.strip(), name
        if self.provider.keychain:
            from .ui import keychain

            stored = keychain.read()
            if stored:
                return stored, "keychain"
        return None, None


def _int(value: Any, name: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        digits = value.strip().replace("_", "") if isinstance(value, str) else ""
        if digits.isascii() and digits.isdigit() and len(digits) <= 15:
            value = int(digits)
        else:
            raise ConfigError(f"{name} must be an integer")
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _cost(value: Any, name: str) -> float | None:
    """A cost cap in US dollars; 0 is no cap; None (or an empty text) is no value, so the default cap applies."""
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number of US dollars (0 for no cap)") from None
    if isinstance(value, bool) or not math.isfinite(number) or number < 0:
        raise ConfigError(f"{name} must be a positive number of US dollars (0 for no cap)")
    return number


def _model(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(character.isspace() for character in value.strip()):
        raise ConfigError(f"{name} must be a model ID without spaces")
    return value.strip()


def _check_secrets(table: Mapping[str, Any], where: str) -> None:
    for key, value in table.items():
        if key.lower() in SECRET_KEYS:
            raise ConfigError(f"{where}.{key}: a configuration file must not hold a key; set SENTRYTOWER_API_KEY in the environment")
        if isinstance(value, Mapping):
            _check_secrets(value, f"{where}.{key}")


def load_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except OSError as error:
        raise ConfigError(f"the configuration file {path} cannot be read: {type(error).__name__}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"the configuration file {path} is not UTF-8 text") from None
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"the configuration file {path} is not valid TOML: {error}") from None
    unknown = sorted(set(document) - TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"unknown tables in {path.name}: {', '.join(unknown)}")
    _check_secrets(document, "config")
    return document


def apply_document(config: Config, document: Mapping[str, Any], source: str) -> Config:
    """The configuration with the values of one TOML document."""
    changes: dict[str, Any] = {}
    models = document.get("models") or {}
    if not isinstance(models, Mapping):
        raise ConfigError("[models] must be a table")
    unknown = sorted(set(models) - {"default", *ROLES})
    if unknown:
        raise ConfigError(f"unknown roles in [models]: {', '.join(unknown)}; the roles are {', '.join(ROLES)}")
    if "default" in models:
        changes["default_model"] = _model(models["default"], "models.default")
    overrides = dict(config.role_overrides)
    for role in ROLES:
        if role in models:
            overrides[role] = _model(models[role], f"models.{role}")
    changes["role_overrides"] = overrides

    provider = document.get("provider") or {}
    if not isinstance(provider, Mapping):
        raise ConfigError("[provider] must be a table")
    unknown = sorted(set(provider) - {"base_url", "api_key_env", "require_api_key", "max_parallel_requests", "headers", "keychain"})
    if unknown:
        raise ConfigError(f"unknown keys in [provider]: {', '.join(unknown)}")
    provider_changes: dict[str, Any] = {}
    if "keychain" in provider:
        if not isinstance(provider["keychain"], bool):
            raise ConfigError("provider.keychain must be true or false")
        provider_changes["keychain"] = provider["keychain"]
    if "base_url" in provider:
        provider_changes["base_url"] = _base_url(provider["base_url"], "provider.base_url")
    if "api_key_env" in provider:
        names = provider["api_key_env"]
        names = [names] if isinstance(names, str) else names
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(name, str) and _VARIABLE_NAME.match(name.strip()) for name in names)
        ):
            raise ConfigError("provider.api_key_env must name one or more environment variables")
        provider_changes["api_key_env"] = tuple(name.strip() for name in names)
    if "require_api_key" in provider:
        if not isinstance(provider["require_api_key"], bool):
            raise ConfigError("provider.require_api_key must be true or false")
        provider_changes["require_api_key"] = provider["require_api_key"]
    if "max_parallel_requests" in provider:
        provider_changes["max_parallel_requests"] = _int(provider["max_parallel_requests"], "provider.max_parallel_requests")
    if "headers" in provider:
        headers = provider["headers"]
        if not isinstance(headers, Mapping) or not all(isinstance(value, str) for value in headers.values()):
            raise ConfigError("provider.headers must be a table of strings")
        for name in headers:
            if _SECRET_HEADER.search(str(name)):
                raise ConfigError(
                    f"provider.headers.{name}: a configuration file must not hold a credential; the gateway sends the key "
                    "of the environment as the authorization header"
                )
        provider_changes["headers"] = {str(name): value for name, value in headers.items()}
    changes["provider"] = replace(config.provider, **provider_changes)

    budget = document.get("budget") or {}
    if not isinstance(budget, Mapping):
        raise ConfigError("[budget] must be a table")
    unknown = sorted(set(budget) - {"max_tokens", "wall_clock_seconds", "max_cost_usd"})
    if unknown:
        raise ConfigError(f"unknown keys in [budget]: {', '.join(unknown)}")
    budget_changes: dict[str, Any] = {}
    if "max_tokens" in budget:
        budget_changes["max_tokens"] = _int(budget["max_tokens"], "budget.max_tokens", minimum=1000)
    if "wall_clock_seconds" in budget:
        budget_changes["wall_clock_seconds"] = _int(budget["wall_clock_seconds"], "budget.wall_clock_seconds", minimum=60)
    if "max_cost_usd" in budget:
        budget_changes["max_cost_usd"] = _cost(budget["max_cost_usd"], "budget.max_cost_usd")
    changes["budget"] = replace(config.budget, **budget_changes)

    router = document.get("router") or {}
    if not isinstance(router, Mapping) or sorted(set(router) - {"large_repo_files"}):
        raise ConfigError("[router] has one key: large_repo_files")
    if "large_repo_files" in router:
        changes["large_repo_files"] = _int(router["large_repo_files"], "router.large_repo_files")

    tools = document.get("tools") or {}
    if not isinstance(tools, Mapping) or sorted(set(tools) - {"pi", "rg", "fd"}):
        raise ConfigError("[tools] has the keys pi, rg and fd")
    if not all(isinstance(value, str) and value.strip() for value in tools.values()):
        raise ConfigError("[tools] values must be paths")
    changes["tools"] = replace(config.tools, **{key: str(value) for key, value in tools.items()})

    policies = document.get("policies") or {}
    if not isinstance(policies, Mapping) or not all(isinstance(value, Mapping) for value in policies.values()):
        raise ConfigError('[policies] must hold one table for each model, for example [policies."vendor/model"]')
    changes["policy_tables"] = {**dict(config.policy_tables), **{str(key): dict(value) for key, value in policies.items()}}

    funnel = document.get("funnel") or {}
    if not isinstance(funnel, Mapping):
        raise ConfigError("[funnel] must be a table")
    known = set(Parameters().record())
    unknown = sorted(set(funnel) - known)
    if unknown:
        raise ConfigError(f"unknown funnel parameters: {', '.join(unknown)}")
    if "large_repo_files" in funnel:
        raise ConfigError("set the threshold with [router] large_repo_files")
    changes["funnel_parameters"] = {**dict(config.funnel_parameters), **dict(funnel)}

    run = document.get("run") or {}
    if not isinstance(run, Mapping) or sorted(set(run) - {"state_dir", "out_dir", "fail_on", "open_report"}):
        raise ConfigError("[run] has the keys state_dir, out_dir, fail_on and open_report")
    if "state_dir" in run:
        changes["state_dir"] = str(run["state_dir"])
    if "out_dir" in run:
        if not isinstance(run["out_dir"], str) or not run["out_dir"].strip():
            raise ConfigError("run.out_dir must be a folder")
        changes["out_dir"] = run["out_dir"].strip()
    if "fail_on" in run:
        value = run["fail_on"]
        if value in ("", "off", "none", False, None):
            changes["fail_on"] = None
        elif value in SEVERITY_NAMES:
            changes["fail_on"] = value
        else:
            raise ConfigError("run.fail_on must be critical, high, medium, low or off")
    if "open_report" in run:
        if not isinstance(run["open_report"], bool):
            raise ConfigError("run.open_report must be true or false")
        changes["open_report"] = run["open_report"]

    ui = document.get("ui") or {}
    if not isinstance(ui, Mapping) or sorted(set(ui) - {"agent_name", "agent_color", "theme"}):
        raise ConfigError("[ui] has the keys agent_name, agent_color and theme")
    ui_changes: dict[str, Any] = {}
    if "agent_name" in ui:
        name = ui["agent_name"].strip() if isinstance(ui["agent_name"], str) else ""
        if not _AGENT_NAME.match(name):
            raise ConfigError("ui.agent_name must be 1 to 24 printable characters")
        ui_changes["agent_name"] = name
    if "agent_color" in ui:
        if ui["agent_color"] not in AGENT_COLOR_NAMES:
            raise ConfigError(f"ui.agent_color must be one of {', '.join(AGENT_COLOR_NAMES)}")
        ui_changes["agent_color"] = ui["agent_color"]
    if "theme" in ui:
        if ui["theme"] not in ("auto", "dark", "light"):
            raise ConfigError("ui.theme must be auto, dark or light")
        ui_changes["theme"] = ui["theme"]
    changes["ui"] = replace(config.ui, **ui_changes)
    updated = replace(config, **changes, sources=(*config.sources, source))
    # Each policy table must be valid, also the table of a model that no role uses.
    for model, table in updated.policy_tables.items():
        try:
            policy_from_table(model, table, BUILTIN_POLICIES.get(model))
        except ValueError as error:
            raise ConfigError(f"[policies.{model!r}]: {error}") from None
    updated.parameters()
    return updated


def _base_url(value: Any, name: str) -> str:
    text = value.strip().rstrip("/") if isinstance(value, str) else ""
    try:
        parsed = urllib.parse.urlsplit(text)
        parsed.port  # noqa: B018 - a port that is not a number raises ValueError
    except ValueError:
        raise ConfigError(f"{name} must be an http or https URL") from None
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(character.isspace() for character in text):
        raise ConfigError(f"{name} must be an http or https URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError(f"{name} must not hold a user or a password; set the key in the environment")
    return text


ENVIRONMENT = {
    "SENTRYTOWER_MODEL": "the default model",
    **{f"SENTRYTOWER_MODEL_{role.upper()}": f"the model of the role {role}" for role in ROLES},
    "SENTRYTOWER_BASE_URL": "the provider base URL",
    "SENTRYTOWER_MAX_TOKENS": "the token ceiling of a run",
    "SENTRYTOWER_WALL_CLOCK": "the wall clock of a run, in seconds",
    "SENTRYTOWER_MAX_COST_USD": "the cost cap of a run, in US dollars (0: no cap)",
    "SENTRYTOWER_PI": "the Pi CLI",
    "SENTRYTOWER_RG": "ripgrep",
    "SENTRYTOWER_FD": "fd",
    "SENTRYTOWER_STATE_DIR": "the folder of the run state",
}


def apply_environment(config: Config, environment: Mapping[str, str]) -> Config:
    """The configuration with the ``SENTRYTOWER_*`` variables of the environment."""
    used = [name for name in ENVIRONMENT if environment.get(name)]
    if not used:
        return config
    changes: dict[str, Any] = {}
    if environment.get("SENTRYTOWER_MODEL"):
        changes["default_model"] = _model(environment["SENTRYTOWER_MODEL"], "SENTRYTOWER_MODEL")
    overrides = dict(config.role_overrides)
    for role in ROLES:
        value = environment.get(f"SENTRYTOWER_MODEL_{role.upper()}")
        if value:
            overrides[role] = _model(value, f"SENTRYTOWER_MODEL_{role.upper()}")
    changes["role_overrides"] = overrides
    if environment.get("SENTRYTOWER_BASE_URL"):
        changes["provider"] = replace(config.provider, base_url=_base_url(environment["SENTRYTOWER_BASE_URL"], "SENTRYTOWER_BASE_URL"))
    budget = config.budget
    if environment.get("SENTRYTOWER_MAX_TOKENS"):
        budget = replace(budget, max_tokens=_int(environment["SENTRYTOWER_MAX_TOKENS"], "SENTRYTOWER_MAX_TOKENS", minimum=1000))
    if environment.get("SENTRYTOWER_WALL_CLOCK"):
        budget = replace(budget, wall_clock_seconds=_int(environment["SENTRYTOWER_WALL_CLOCK"], "SENTRYTOWER_WALL_CLOCK", minimum=60))
    if environment.get("SENTRYTOWER_MAX_COST_USD"):
        budget = replace(budget, max_cost_usd=_cost(environment["SENTRYTOWER_MAX_COST_USD"], "SENTRYTOWER_MAX_COST_USD"))
    changes["budget"] = budget
    tools = {key: environment[f"SENTRYTOWER_{key.upper()}"] for key in ("pi", "rg", "fd") if environment.get(f"SENTRYTOWER_{key.upper()}")}
    if tools:
        changes["tools"] = replace(config.tools, **tools)
    if environment.get("SENTRYTOWER_STATE_DIR"):
        changes["state_dir"] = environment["SENTRYTOWER_STATE_DIR"]
    return replace(config, **changes, sources=(*config.sources, "environment: " + ", ".join(used)))


def config_home(environment: Mapping[str, str] | None = None) -> Path:
    """The folder of the user's settings: ``$XDG_CONFIG_HOME/sentrytower``, else ``~/.config/sentrytower``."""
    env = os.environ if environment is None else environment
    base = env.get("XDG_CONFIG_HOME") or str(Path(env.get("HOME") or Path.home()) / ".config")
    return Path(base) / "sentrytower"


def user_config_path(profile: str | None = None, environment: Mapping[str, str] | None = None) -> Path:
    """The settings file of the user, or of a profile."""
    if profile is None:
        return config_home(environment) / "config.toml"
    if not _PROFILE_NAME.match(profile):
        raise ConfigError("a profile name has letters, digits, '.', '_' and '-' (at most 40)")
    return config_home(environment) / "profiles" / f"{profile}.toml"


def config_file(path: Path | None, profile: str | None, environment: Mapping[str, str]) -> Path | None:
    """The settings file of a run: --config, SENTRYTOWER_CONFIG, the profile, or the user's file when it exists."""
    if path is not None:
        return path
    if environment.get(CONFIG_VARIABLE):
        return Path(environment[CONFIG_VARIABLE])
    name = profile or environment.get(PROFILE_VARIABLE) or None
    if name:
        file = user_config_path(name, environment)
        if not file.is_file():
            raise ConfigError(f"there is no profile {name!r}: run `sentrytower setup --profile {name}`")
        return file
    default = user_config_path(None, environment)
    return default if default.is_file() else None


def load_config(
    path: Path | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    profile: str | None = None,
    model: str | None = None,
    fast_model: str | None = None,
    agent_model: str | None = None,
    max_tokens: int | None = None,
    wall_clock_seconds: int | None = None,
    max_cost_usd: float | None = None,
    base_url: str | None = None,
) -> Config:
    """The configuration of a run: the defaults, the file (``config_file``), the ``SENTRYTOWER_*``
    variables, then the command-line values (each one when it is not None).

    ``model`` sets the default model and clears the role overrides of the
    file and the environment: ``--model`` runs one model everywhere.
    ``fast_model`` gives the short calls of the funnel their model, and
    ``agent_model`` the agent sessions (``FAST_ROLES``, ``AGENT_ROLES``).
    """
    env = os.environ if environment is None else environment
    config = Config(sources=("defaults",))
    file = config_file(path, profile, env)
    if file is not None:
        config = apply_document(config, load_file(file), f"file: {file}")
    config = apply_environment(config, env)
    changes: dict[str, Any] = {}
    flags: list[str] = []
    if model is not None:
        changes.update(default_model=_model(model, "--model"), role_overrides={})
        flags.append("--model")
    for value, roles, flag in ((fast_model, FAST_ROLES, "--fast-model"), (agent_model, AGENT_ROLES, "--agent-model")):
        if value is not None:
            overrides = dict(changes.get("role_overrides", config.role_overrides))
            overrides.update({role: _model(value, flag) for role in roles})
            changes["role_overrides"] = overrides
            flags.append(flag)
    budget = config.budget
    if max_tokens is not None:
        budget = replace(budget, max_tokens=_int(max_tokens, "--max-tokens", minimum=1000))
        flags.append("--max-tokens")
    if wall_clock_seconds is not None:
        budget = replace(budget, wall_clock_seconds=_int(wall_clock_seconds, "--wall-clock", minimum=60))
        flags.append("--wall-clock")
    if max_cost_usd is not None:
        budget = replace(budget, max_cost_usd=_cost(max_cost_usd, "--max-cost-usd"))
        flags.append("--max-cost-usd")
    changes["budget"] = budget
    if base_url is not None:
        changes["provider"] = replace(config.provider, base_url=_base_url(base_url, "--base-url"))
        flags.append("--base-url")
    if flags:
        changes["sources"] = (*config.sources, "options: " + ", ".join(flags))
    config = replace(config, **changes)
    config.policies()
    config.parameters()
    return config


def _toml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else '"' + key.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return f"{value:_}" if abs(value) >= 10_000 else str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
        return f'"{escaped}"'
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise ConfigError(f"a value of type {type(value).__name__} cannot be written to TOML")


def dump_toml(document: Mapping[str, Any], header: str = "") -> str:
    """A TOML text of a document of tables (one level of sub-tables, as ``[policies."vendor/model"]``)."""
    _check_secrets(document, "config")
    lines = [f"# {line}" if line else "#" for line in header.splitlines()]
    for table, values in document.items():
        if not isinstance(values, Mapping) or not values:
            continue
        scalars = {key: value for key, value in values.items() if not isinstance(value, Mapping)}
        subtables = {key: value for key, value in values.items() if isinstance(value, Mapping)}
        if scalars:
            lines += ["", f"[{_toml_key(table)}]"]
            lines += [f"{_toml_key(key)} = {_toml_value(value)}" for key, value in scalars.items() if value is not None]
        for key, value in subtables.items():
            lines += ["", f"[{_toml_key(table)}.{_toml_key(key)}]"]
            lines += [f"{_toml_key(name)} = {_toml_value(item)}" for name, item in value.items() if item is not None]
    return "\n".join(lines).lstrip("\n") + "\n"


def write_config(path: Path, document: Mapping[str, Any], header: str = "") -> Path:
    """Write a settings file (mode 0600) after a check that SentryTower reads it back as a valid configuration."""
    text = dump_toml(document, header)
    parsed = tomllib.loads(text)
    unknown = sorted(set(parsed) - TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"unknown tables: {', '.join(unknown)}")
    apply_document(Config(sources=("defaults",)), parsed, "check")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".toml.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.replace(temporary, path)
    return path
