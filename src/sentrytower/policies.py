"""Model request policies: the settings that the model gateway adds to each request, as data.

Each model of a run has one policy. The gateway rewrites each request of the
engines with the policy of its model before it sends the request upstream:

1. it removes the keys that choose another route or another reasoning
   knob (``STRIPPED_REQUEST_KEYS``), and each tool that is not a function
   tool (a server-side tool could reach the network);
2. it sets the completion ceiling (``max_completion_tokens``, or
   ``max_tokens`` for an endpoint that knows only that key). The ceiling of
   a policy is the ceiling of each call at every depth;
3. it sets the reasoning effort (``reasoning: {"effort": ...}``), or removes
   the key when the policy has no effort;
4. it sets the provider route of OpenRouter (``provider``), or removes the
   key when the policy has none.

The built-in table holds the policies of ``deepseek/deepseek-v4.1-flash-1017``
(the default model) and ``z-ai/glm-5.3-flash``. Their provider route is an
allowlist of endpoints with ``data_collection: "deny"``. A configuration file
can add a policy or change one (``[policies."<model>"]``,
docs/configuration.md); a provider table of the file replaces the whole
route. A model without a policy gets ``generic_policy``.

Standard library only.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

DEFAULT_MODEL = "deepseek/deepseek-v4.1-flash-1017"
# Routing and provider-specific reasoning knobs are removed so that each call
# takes the route and the parameter shape of its policy. The OpenRouter model
# fallback list (models), the route, the search options and a preset are
# removed too: the policy is the only route.
STRIPPED_REQUEST_KEYS = (
    "routes",
    "plugins",
    "transforms",
    "reasoning_effort",
    "thinking",
    "enable_thinking",
    "thinking_token_budget",
    "models",
    "route",
    "web_search_options",
    "preset",
)
# The forwarded tools are function tools only.
FORWARDED_TOOL_TYPES = ("function",)
TOKEN_FIELDS = ("max_completion_tokens", "max_tokens")
REASONING_EFFORTS = ("minimal", "low", "medium", "high", "xhigh")
# Pi thinking levels for the agent settings file (``off`` when the policy has no effort).
PI_THINKING_LEVELS = ("off", "minimal", "low", "medium", "high", "xhigh")
# The limits of a policy: an attempt waits at most an hour for a byte, and a call has at most 10 retries.
MAX_ATTEMPT_SECONDS = 3600.0
MAX_RETRIES = 10
# The data policy of the provider object of OpenRouter in each built-in route: "deny" uses only the
# providers that do not collect user data (OpenRouter provider routing, data_collection).
DENY_DATA_COLLECTION = {"data_collection": "deny"}


def canonical_json(value: Any) -> bytes:
    """The bytes that the gateway sends upstream: sorted keys, no spaces, UTF-8.

    A string with a lone UTF-16 surrogate (a valid JSON escape that has no
    UTF-8 form, for example half of an emoji that a truncation cut) keeps
    its JSON escapes: the body is then ASCII with ``\\u`` escapes.
    """
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        return text.encode()
    except UnicodeEncodeError:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True)
class ModelPolicy:
    """The request settings, limits and prices of one model.

    ``provider`` is the OpenRouter provider object of each request (None:
    no provider key). ``max_completion_tokens`` is the completion ceiling of
    each call at every depth; ``max_output_tokens`` is the largest output of
    the model on its route (None: the same), for the record only: it does
    not change the ceiling. ``attempt_timeout_seconds`` is the longest time
    without a byte from the endpoint in one attempt (a streamed answer can
    take longer as a whole); ``max_retries`` is the count of new attempts
    after a transient failure. The prices (US dollars for each million tokens) give a cost
    estimate when the provider reports no cost.
    """

    model_id: str
    name: str
    reasoning_effort: str | None = "medium"
    max_completion_tokens: int = 131_072
    max_output_tokens: int | None = None
    context_window: int = 131_072
    token_field: str = "max_completion_tokens"
    provider: Mapping[str, Any] | None = None
    input_cost_per_million: float | None = None
    output_cost_per_million: float | None = None
    cache_read_cost_per_million: float | None = None
    attempt_timeout_seconds: float = 660.0
    max_retries: int = 2
    input_modalities: tuple[str, ...] = ("text",)
    notes: tuple[str, ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if not self.model_id or not self.model_id.strip():
            raise ValueError("a model policy needs a model ID")
        if self.reasoning_effort is not None and self.reasoning_effort not in REASONING_EFFORTS:
            raise ValueError(f"reasoning_effort of {self.model_id} must be one of {', '.join(REASONING_EFFORTS)} or empty")
        if self.token_field not in TOKEN_FIELDS:
            raise ValueError(f"token_field of {self.model_id} must be one of {', '.join(TOKEN_FIELDS)}")
        if self.max_completion_tokens < 1 or self.context_window < 1:
            raise ValueError(f"the token limits of {self.model_id} must be positive")
        if self.max_output_tokens is not None and self.max_output_tokens < self.max_completion_tokens:
            raise ValueError(f"max_output_tokens of {self.model_id} must be at least its max_completion_tokens")
        if not (math.isfinite(self.attempt_timeout_seconds) and 0 < self.attempt_timeout_seconds <= MAX_ATTEMPT_SECONDS):
            raise ValueError(f"attempt_timeout_seconds of {self.model_id} must be more than 0 and at most {MAX_ATTEMPT_SECONDS:.0f}")
        if not 0 <= self.max_retries <= MAX_RETRIES:
            raise ValueError(f"max_retries of {self.model_id} must be 0 to {MAX_RETRIES}")
        for name in ("input_cost_per_million", "output_cost_per_million", "cache_read_cost_per_million"):
            price = getattr(self, name)
            if price is not None and not (math.isfinite(price) and price >= 0):
                raise ValueError(f"{name} of {self.model_id} must be a number of at least 0")
        if self.provider is not None and not isinstance(self.provider, Mapping):
            raise ValueError(f"provider of {self.model_id} must be a table")

    def rewrite(self, payload: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
        """The body that the gateway forwards for one request of this model, and each change.

        The changes come in a fixed order: each stripped key, the tools that
        are not function tools, the completion ceiling, the reasoning effort
        and the provider route. A change records the key, the action and
        the rule, never a value. ``payload`` does not change.
        """
        forwarded = dict(payload)
        changes: list[dict[str, str]] = []

        def assign(key: str, value: object, rule: str) -> None:
            if key not in forwarded:
                changes.append({"key": key, "action": "set", "rule": rule})
            elif canonical_json(forwarded[key]) != canonical_json(value):
                changes.append({"key": key, "action": "replaced", "rule": rule})
            forwarded[key] = value

        def remove(key: str, rule: str) -> None:
            if key in forwarded:
                forwarded.pop(key)
                changes.append({"key": key, "action": "removed", "rule": rule})

        for key in STRIPPED_REQUEST_KEYS:
            remove(key, "policy.stripped_request_keys")
        tools = forwarded.get("tools")
        if isinstance(tools, list):
            kept = [tool for tool in tools if isinstance(tool, Mapping) and tool.get("type") in FORWARDED_TOOL_TYPES]
            if len(kept) != len(tools):
                changes.append({"key": "tools", "action": "filtered", "rule": "policy.function_tools_only"})
                if kept:
                    forwarded["tools"] = kept
                else:
                    forwarded.pop("tools")
        choice = forwarded.get("tool_choice")
        if isinstance(choice, Mapping) and choice.get("type") not in FORWARDED_TOOL_TYPES:
            forwarded.pop("tool_choice")
            changes.append({"key": "tool_choice", "action": "removed", "rule": "policy.function_tools_only"})
        other = "max_tokens" if self.token_field == "max_completion_tokens" else "max_completion_tokens"
        remove(other, "policy.completion_ceiling")
        if self.reasoning_effort is None:
            remove("reasoning", "policy.reasoning_effort")
        else:
            assign("reasoning", {"effort": self.reasoning_effort}, "policy.reasoning_effort")
        assign(self.token_field, self.max_completion_tokens, "policy.completion_ceiling")
        if self.provider is None:
            remove("provider", "policy.provider_route")
        else:
            assign("provider", json.loads(json.dumps(dict(self.provider))), "policy.provider_route")
        return forwarded, changes

    def pi_definition(self) -> dict[str, object]:
        """The model entry of the agent model catalog (Pi ``models.json``)."""
        definition: dict[str, object] = {
            "id": self.model_id,
            "name": self.name,
            "reasoning": True,
            "input": list(self.input_modalities),
            "contextWindow": self.context_window,
            "maxTokens": self.max_completion_tokens,
        }
        if (
            self.input_cost_per_million is not None
            and self.output_cost_per_million is not None
            and self.cache_read_cost_per_million is not None
        ):
            definition["cost"] = {
                "input": self.input_cost_per_million,
                "output": self.output_cost_per_million,
                "cacheRead": self.cache_read_cost_per_million,
                "cacheWrite": 0,
            }
        return definition

    def thinking_level(self) -> str:
        """The thinking level of the agent settings file."""
        return self.reasoning_effort if self.reasoning_effort in PI_THINKING_LEVELS else "off"

    @property
    def priced(self) -> bool:
        return self.input_cost_per_million is not None and self.output_cost_per_million is not None

    def cost_estimate(self, input_tokens: int, output_tokens: int, cache_read_tokens: int = 0) -> float | None:
        """The cost of a call at the prices of the policy, or None without prices."""
        if not self.priced:
            return None
        assert self.input_cost_per_million is not None and self.output_cost_per_million is not None
        cache_price = self.cache_read_cost_per_million
        cached = min(max(0, cache_read_tokens), max(0, input_tokens)) if cache_price is not None else 0
        fresh = max(0, input_tokens) - cached
        return (
            fresh * self.input_cost_per_million + cached * (cache_price or 0.0) + max(0, output_tokens) * self.output_cost_per_million
        ) / 1_000_000

    def record(self) -> dict[str, Any]:
        """The policy as data (for run.json and the documentation)."""
        return {
            "model": self.model_id,
            "reasoning_effort": self.reasoning_effort,
            "max_completion_tokens": self.max_completion_tokens,
            "max_output_tokens": self.max_output_tokens,
            "token_field": self.token_field,
            "context_window": self.context_window,
            "provider": dict(self.provider) if self.provider is not None else None,
            "attempt_timeout_seconds": self.attempt_timeout_seconds,
            "max_retries": self.max_retries,
            "prices_per_million": {
                "input": self.input_cost_per_million,
                "output": self.output_cost_per_million,
                "cache_read": self.cache_read_cost_per_million,
            },
        }


# The default model. The provider route is an allowlist of the DeepSeek
# endpoint and fp8 endpoints that OpenRouter balances across and falls back
# within. Some calls of this model reason without end. The completion ceiling
# is 65,536 tokens at every depth: such a call stops with "length" after
# about 400 s, and no complete answer of the measured runs had more than
# 48,607 tokens. 384,000 tokens is the largest output that each endpoint of
# the route takes (StreamLake). The prices are the OpenRouter list prices of
# 2026-10-30. Each built-in route sets ``data_collection: "deny"``
# (``DENY_DATA_COLLECTION``): a request holds the code of the audited
# repository, and OpenRouter then uses only the endpoints of the allowlist
# that do not collect user data.
DEEPSEEK_V41_FLASH = ModelPolicy(
    model_id=DEFAULT_MODEL,
    name="DeepSeek V4.1 Flash 1017",
    reasoning_effort="medium",
    max_completion_tokens=65_536,
    max_output_tokens=384_000,
    context_window=1_024_000,
    provider={
        "only": ["deepseek", "streamlake/fp8", "novita/fp8", "atlas-cloud/fp8", "gmicloud/fp8"],
        "allow_fallbacks": True,
        **DENY_DATA_COLLECTION,
    },
    input_cost_per_million=0.15,
    output_cost_per_million=0.6,
    cache_read_cost_per_million=0.003,
    attempt_timeout_seconds=300.0,
    max_retries=2,
    input_modalities=("text", "image"),
)

# The default model of SentryTower 1.0 and 1.1. The provider route is an
# allowlist of fp8 endpoints. The prices are the OpenRouter list prices of
# 2026-10-30.
GLM_53_FLASH = ModelPolicy(
    model_id="z-ai/glm-5.3-flash",
    name="Z.ai GLM 5.3 Flash",
    reasoning_effort="medium",
    max_completion_tokens=131_072,
    context_window=1_310_720,
    provider={
        "only": ["z-ai/fp8", "atlas-cloud/fp8", "streamlake/fp8", "novita/fp8", "gmicloud/fp8"],
        "allow_fallbacks": True,
        **DENY_DATA_COLLECTION,
    },
    input_cost_per_million=0.018,
    output_cost_per_million=0.14,
    cache_read_cost_per_million=0.018,
    attempt_timeout_seconds=240.0,
    max_retries=2,
)

# The default model comes first: the setup lists the built-in models in this order.
BUILTIN_POLICIES: dict[str, ModelPolicy] = {policy.model_id: policy for policy in (DEEPSEEK_V41_FLASH, GLM_53_FLASH)}

# The keys of a policy table in a configuration file.
POLICY_KEYS = frozenset(
    {
        "name",
        "reasoning_effort",
        "max_completion_tokens",
        "max_output_tokens",
        "context_window",
        "token_field",
        "provider",
        "input_cost_per_million",
        "output_cost_per_million",
        "cache_read_cost_per_million",
        "attempt_timeout_seconds",
        "max_retries",
        "input_modalities",
    }
)


def generic_policy(model_id: str) -> ModelPolicy:
    """The policy of a model that the table does not name: no reasoning effort, no provider route."""
    return ModelPolicy(
        model_id=model_id,
        name=model_id,
        reasoning_effort=None,
        max_completion_tokens=32_768,
        context_window=131_072,
        provider=None,
        attempt_timeout_seconds=660.0,
        max_retries=2,
        notes=("generic policy: add a [policies] table to set the limits and the prices of this model",),
    )


def policy_from_table(model_id: str, table: Mapping[str, Any], base: ModelPolicy | None = None) -> ModelPolicy:
    """A policy from a configuration table: the keys of the table over ``base`` (or the generic policy)."""
    unknown = sorted(set(table) - POLICY_KEYS)
    if unknown:
        raise ValueError(f"unknown keys in the policy of {model_id}: {', '.join(unknown)}")
    start = base or generic_policy(model_id)
    values: dict[str, Any] = {}
    for key, value in table.items():
        if key == "reasoning_effort":
            values[key] = None if value in (None, "", "none", "off") else str(value)
        elif key == "provider":
            if value is not None and not isinstance(value, Mapping):
                raise ValueError(f"provider of {model_id} must be a table")
            values[key] = dict(value) if isinstance(value, Mapping) and value else None
        elif key == "input_modalities":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"input_modalities of {model_id} must be a list of strings")
            values[key] = tuple(value)
        elif key == "max_output_tokens":
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError(f"{key} of {model_id} must be an integer")
            values[key] = value
        elif key in ("max_completion_tokens", "context_window", "max_retries"):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} of {model_id} must be an integer")
            values[key] = value
        elif key in ("attempt_timeout_seconds", "input_cost_per_million", "output_cost_per_million", "cache_read_cost_per_million"):
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
                raise ValueError(f"{key} of {model_id} must be a number")
            values[key] = None if value is None else float(value)
        else:
            if not isinstance(value, str):
                raise ValueError(f"{key} of {model_id} must be a string")
            values[key] = value
    return replace(start, notes=(), **values)


def resolve_policies(models: list[str], tables: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, ModelPolicy]:
    """The policy of each model: the built-in table, changed or extended by ``tables``."""
    tables = tables or {}
    policies: dict[str, ModelPolicy] = {}
    for model in dict.fromkeys(models):
        base = BUILTIN_POLICIES.get(model)
        if model in tables:
            policies[model] = policy_from_table(model, tables[model], base)
        else:
            policies[model] = base or generic_policy(model)
    return policies
