"""The budget of a run: the cost cap, the depth factor and the token plan of the engines.

A run with a cost cap spends dollars, and the dollars end the run. The
engines still plan their work in tokens: the funnel splits its token
ceiling into pools, and the agent runner stops a session at shares of its
token budget. ``plan_tokens`` gives that plan from the cap and the prices
of the models of the route (``price_per_million``).

The standard run is the measured run: 20,000,000 tokens (``STANDARD_TOKENS``)
with the measured parameters, at a cost cap of $2 (``STANDARD_COST_USD``,
the standard depth and the default cap). The depth factor m is the count of
standard runs that a cap buys::

    m = max(1, min(cap / $2, the tokens that the cap buys / 20,000,000))

So a cap of $2 or less never adds depth, whatever the model, and an
expensive model gets depth only when the cap buys its tokens. A max_tokens
setting is an upper limit of the tokens. Then:

- m = 1, and the cap buys at least 20M tokens: the standard run, with the
  20M ceiling (or max_tokens, when it is smaller); the gateway applies the
  ceiling;
- m = 1, and the cap buys fewer than 20M tokens: the engines plan with the
  tokens that the cap buys; the gateway applies no token ceiling (only
  max_tokens, when it is set), and the funnel plans more work when the cap
  still has money and its tokens are spent;
- m > 1: the engines plan with m standard runs (m x 20M tokens), and each
  limit that is a count or a size grows with m, up to what the computer or
  the repository gives (``funnel_parameters``, ``parallel_sessions``). The
  gateway applies no token ceiling (only max_tokens, when it is set):
  dollars end the run.

The completion ceiling of a call is the ceiling of its policy at every
depth. No measured call reached it, and a larger ceiling made each call of
a deeper run reserve more of the cap and run past the timeouts of the
clients.

When dollars end the run (``TokenPlan.money_ends``), no new work starts at
``SOFT_STOP_FRACTION`` (85%) of the cap, and the running sessions finish in
the last 15% (the gateway answers ``GET /budget``, which the engines read
before they start work). On the agent route the soft stop applies whenever
the run has a cap: the agent then writes its answer before the cap refuses
its calls. On the funnel route, a run that its token ceiling ends has no
soft stop: the standard run keeps the measured pacing of the funnel (no new
work at 90% of the 20M ceiling), and its cap is an upper limit only.
Without a cap, the ceiling is max_tokens or 20,000,000 tokens, and m is the
count of standard runs that it holds.

The price of a token blends the prices of a policy with the token mix of the
engine, as measured with DeepSeek V4.1 Flash 1017:

| Route | Output share of all tokens | Cached share of the input tokens |
| --- | --- | --- |
| funnel | 9.5% | 83% |
| agent | 0.4% | 93% |

``TOKEN_MIX`` rounds both values toward a higher price; the estimate can
still be below the charged price when a provider charges peak-hour prices.
A route with more than one model takes the highest price.

Standard library only.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .funnel.pacing import Parameters
from .policies import ModelPolicy

DEFAULT_MAX_TOKENS = 20_000_000
# The token ceiling of a run of the standard budget: the measured parameters.
STANDARD_TOKENS = DEFAULT_MAX_TOKENS
# The cost cap of the standard run: the standard depth, and the cap of a run without a cap of its own.
STANDARD_COST_USD = 2.0
# The depths of an audit and their cost caps in US dollars (setup, --depth). Standard is the measured run; quick is a
# smaller one; deep and max buy more of each step (a preview: the effect on the findings is not yet measured).
DEPTHS = {"quick": 0.5, "standard": STANDARD_COST_USD, "deep": 10.0, "max": 50.0}
# The blind verifications of each finding in a run of more than one standard run.
VERIFY_VOTES = 3
# Agent sessions at the same time in a standard run (the deep checks of the funnel, the slices of the agent route).
STANDARD_SESSIONS = 4
# At this share of the cost cap no new work starts; the running sessions finish in the rest.
SOFT_STOP_FRACTION = 0.85
# For each route: the output share of all tokens, and the cached share of the input tokens.
TOKEN_MIX = {"funnel": (0.10, 0.80), "agent": (0.01, 0.90)}
# Below this ceiling an audit reads little of a repository.
SHALLOW_TOKENS = 2_000_000
# The lowest ceiling (the minimum of max_tokens).
MIN_TOKENS = 1_000

SOURCE_COST_CAP = "cost cap"
SOURCE_STANDARD = "standard run"
SOURCE_SETTING = "max_tokens"
SOURCE_DEFAULT = "default"


@dataclass(frozen=True)
class TokenPlan:
    """The token plan of a run: the token ceiling of the engines, the depth factor and the ceiling of the gateway.

    ``source`` is ``standard run`` (m = 1, the 20M ceiling), ``cost cap``
    (the tokens that the cap buys, or m standard runs), ``max_tokens`` (the
    setting) or ``default`` (no cap). ``price_per_million`` is the blended
    price of the route, in US dollars for one million tokens; ``cap_tokens``
    is what the cap buys at that price. ``gateway_tokens`` is the token
    ceiling that the gateway applies (None: dollars only). ``note`` explains
    a ceiling that the person may not expect.
    """

    tokens: int
    source: str
    price_per_million: float | None = None
    cap_tokens: int | None = None
    note: str | None = None
    depth: float = 1.0
    gateway_tokens: int | None = None

    @property
    def money_ends(self) -> bool:
        """Dollars end the run: a cap, no standard run, and room above the plan (no gateway ceiling, or max_tokens above it).

        The engines then plan more work while the cap has money, up to ``gateway_tokens``.
        """
        return (
            self.cap_tokens is not None
            and self.source != SOURCE_STANDARD
            and (self.gateway_tokens is None or self.gateway_tokens > self.tokens)
        )

    def record(self) -> dict[str, Any]:
        return {
            "token_ceiling_source": self.source,
            "price_per_million_estimate": round(self.price_per_million, 6) if self.price_per_million is not None else None,
            "cost_cap_tokens": self.cap_tokens,
            "gateway_token_ceiling": self.gateway_tokens,
        }


def price_per_million(policy: ModelPolicy, route: str) -> float | None:
    """The blended price of one million tokens of a model on a route, or None without prices."""
    if policy.input_cost_per_million is None or policy.output_cost_per_million is None:
        return None
    output, cached = TOKEN_MIX[route]
    cache_price = policy.cache_read_cost_per_million
    if cache_price is None:
        cache_price = policy.input_cost_per_million
    input_price = (1 - cached) * policy.input_cost_per_million + cached * cache_price
    return (1 - output) * input_price + output * policy.output_cost_per_million


def unpriced_models(policies: Iterable[ModelPolicy], route: str) -> list[str]:
    """The models of a route without the prices that a cost cap needs."""
    return [policy.model_id for policy in policies if price_per_million(policy, route) is None]


def worst_call(policies: Iterable[ModelPolicy]) -> tuple[ModelPolicy, float] | None:
    """The policy whose one call can cost the most, and that cost; None when no policy has prices.

    It is the reservation of the gateway for a small request: the completion
    ceiling of the call at the output price (DeepSeek V4.1 Flash: 65,536
    tokens at $0.60 for one million, about $0.04). A cap must be above it,
    else the gateway refuses each call.
    """
    costs = ((policy, policy.cost_estimate(0, policy.max_completion_tokens)) for policy in policies)
    return max(((policy, cost) for policy, cost in costs if cost is not None), key=lambda pair: pair[1], default=None)


def plan_tokens(max_tokens: int | None, max_cost_usd: float | None, policies: Iterable[ModelPolicy], route: str) -> TokenPlan:
    """The token plan of a run on ``route`` with the policies of the models of the route (see the module text)."""
    fallback = max_tokens if max_tokens is not None else DEFAULT_MAX_TOKENS
    fallback_source = SOURCE_SETTING if max_tokens is not None else SOURCE_DEFAULT
    if not max_cost_usd:
        return TokenPlan(fallback, fallback_source, depth=depth_factor(fallback), gateway_tokens=fallback)
    policies = list(policies)
    missing = unpriced_models(policies, route)
    if missing:
        # The configuration refuses an explicit cap without prices before the run (Config.check_cost_cap).
        unpriced = (
            f"the price of {missing[0]} is not known, so the cost cap cannot size the token budget: "
            f"the token ceiling is {fallback:,}; add the prices to its [policies] table"
        )
        return TokenPlan(fallback, fallback_source, note=unpriced, depth=depth_factor(fallback), gateway_tokens=fallback)
    price = max((price_per_million(policy, route) or 0.0 for policy in policies), default=0.0)
    if price <= 0:
        return TokenPlan(fallback, fallback_source, price_per_million=price, depth=depth_factor(fallback), gateway_tokens=fallback)
    cap_tokens = max(MIN_TOKENS, int(max_cost_usd / price * 1_000_000))
    limit = max_tokens if max_tokens is not None else cap_tokens
    factor = max(1.0, min(max_cost_usd / STANDARD_COST_USD, cap_tokens / STANDARD_TOKENS, limit / STANDARD_TOKENS))
    note: str | None = None
    if factor > 1:
        tokens = min(limit, round(STANDARD_TOKENS * factor))
        source = SOURCE_SETTING if max_tokens is not None and tokens == max_tokens else SOURCE_COST_CAP
        return TokenPlan(tokens, source, price, cap_tokens, note, depth=depth_factor(tokens), gateway_tokens=max_tokens)
    tokens = min(STANDARD_TOKENS, cap_tokens, limit)
    if cap_tokens >= STANDARD_TOKENS:
        # The standard run: the measured parameters and ceiling; the gateway applies the ceiling.
        source = SOURCE_SETTING if tokens == max_tokens and tokens < STANDARD_TOKENS else SOURCE_STANDARD
        return TokenPlan(tokens, source, price, cap_tokens, note, gateway_tokens=tokens)
    if cap_tokens < SHALLOW_TOKENS and (max_tokens is None or max_tokens > cap_tokens):
        note = f"the cost cap of ${max_cost_usd:.2f} buys about {cap_tokens:,} tokens: the audit reads only a small part of the repository"
    source = SOURCE_SETTING if tokens == max_tokens else SOURCE_COST_CAP
    return TokenPlan(tokens, source, price, cap_tokens, note, gateway_tokens=max_tokens)


def depth_factor(tokens: int) -> float:
    """The count of standard runs that a token ceiling holds; at least 1 (a smaller run keeps the standard limits)."""
    return max(1.0, tokens / STANDARD_TOKENS)


def machine_sessions() -> int:
    """The agent sessions that this computer runs at the same time: one for each CPU, at least the standard count."""
    return max(STANDARD_SESSIONS, os.cpu_count() or STANDARD_SESSIONS)


def parallel_sessions(tokens: int) -> int:
    """Agent sessions at the same time: the standard count times the depth factor, within the CPUs of the computer."""
    return min(math.ceil(STANDARD_SESSIONS * depth_factor(tokens)), machine_sessions())


def funnel_parameters(tokens: int, settings: Mapping[str, Any]) -> dict[str, Any]:
    """The funnel parameters that a budget of more than one standard run changes; the [funnel] settings keep theirs.

    The counts grow with the depth factor m, the size and the time of one
    deep check with its square root (the deep checks get more of both: more
    of them and deeper ones). The run gets the passes after the queues, three
    verifications of each finding, and extra output slots for the findings
    that the verifications call exploitable.
    """
    factor = depth_factor(tokens)
    if factor <= 1:
        return {}
    base = Parameters()
    root = math.sqrt(factor)
    workers = max(base.max_workers, parallel_sessions(tokens))
    scaled: dict[str, Any] = {
        "max_unit_checks": math.ceil(base.max_unit_checks * factor),
        "max_units": math.ceil(base.max_units * factor),
        "max_workers": workers,
        "max_concurrency": max(math.ceil(base.max_concurrency * factor), workers + 2),
        "worker_tokens": int(base.worker_tokens * root),
        "worker_seconds": int(base.worker_seconds * root),
        "verify_max_findings": math.ceil(base.verify_max_findings * factor),
        "extra_findings_total": math.ceil(base.max_findings_total * factor) - base.max_findings_total,
        "extra_findings_per_file": math.ceil(base.max_findings_per_file * root) - base.max_findings_per_file,
        "verify_votes": VERIFY_VOTES,
        "depth_passes": True,
        "focus_tokens": int(STANDARD_TOKENS * base.free_token_fraction),
    }
    return {name: value for name, value in scaled.items() if name not in settings}
