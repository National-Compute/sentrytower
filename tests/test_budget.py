"""The budget of a run: the depth factor and the token plan of a cost cap at the prices of the models, and max_tokens."""

from __future__ import annotations

import pytest

from sentrytower.budget import (
    DEFAULT_MAX_TOKENS,
    SHALLOW_TOKENS,
    SOFT_STOP_FRACTION,
    STANDARD_COST_USD,
    STANDARD_TOKENS,
    plan_tokens,
    price_per_million,
)
from sentrytower.policies import DEEPSEEK_V41_FLASH, GLM_53_FLASH, generic_policy, policy_from_table


def test_the_price_of_a_token_blends_the_prices_with_the_token_mix_of_the_route() -> None:
    # The funnel: 10% output, 80% of the input from the cache. The agent: 1% output, 90% cached.
    funnel = 0.9 * (0.2 * 0.15 + 0.8 * 0.003) + 0.1 * 0.6
    agent = 0.99 * (0.1 * 0.15 + 0.9 * 0.003) + 0.01 * 0.6
    assert price_per_million(DEEPSEEK_V41_FLASH, "funnel") == pytest.approx(funnel)
    assert price_per_million(DEEPSEEK_V41_FLASH, "agent") == pytest.approx(agent)
    # The measured price of the funnel runs was $0.0952 for a million tokens; the estimate is within 10% of it.
    assert 0.0952 * 0.9 < funnel < 0.0952 * 1.1
    # Without a cache price, a cached token costs as much as an input token.
    no_cache = policy_from_table("m/x", {"input_cost_per_million": 1.0, "output_cost_per_million": 2.0})
    assert price_per_million(no_cache, "funnel") == pytest.approx(0.9 * 1.0 + 0.1 * 2.0)
    assert price_per_million(generic_policy("m/y"), "funnel") is None


def test_without_a_cost_cap_the_ceiling_is_max_tokens_or_the_default() -> None:
    plan = plan_tokens(None, None, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.tokens == plan.gateway_tokens == DEFAULT_MAX_TOKENS and plan.depth == 1.0 and not plan.money_ends
    plan = plan_tokens(5_000_000, None, [DEEPSEEK_V41_FLASH], "agent")
    assert plan.tokens == 5_000_000 and plan.source == "max_tokens" and plan.price_per_million is None
    # Without a cap, a larger ceiling still buys depth in tokens.
    assert plan_tokens(60_000_000, None, [DEEPSEEK_V41_FLASH], "funnel").depth == 3.0


@pytest.mark.parametrize("route", ["funnel", "agent"])
def test_two_dollars_is_the_measured_standard_run_on_both_routes(route: str) -> None:
    plan = plan_tokens(None, STANDARD_COST_USD, [DEEPSEEK_V41_FLASH], route)
    # Depth factor exactly 1, the 20M ceiling, and the gateway applies it: the measured run.
    assert plan.depth == 1.0 and plan.tokens == STANDARD_TOKENS and plan.source == "standard run"
    assert plan.gateway_tokens == STANDARD_TOKENS and not plan.money_ends
    assert plan.cap_tokens is not None and plan.cap_tokens >= STANDARD_TOKENS


def test_the_depth_factor_is_the_count_of_standard_runs_that_the_cap_buys() -> None:
    # The default model: the cap in units of $2, on both routes.
    for cap, factor in ((5.0, 2.5), (10.0, 5.0), (50.0, 25.0)):
        for route in ("funnel", "agent"):
            plan = plan_tokens(None, cap, [DEEPSEEK_V41_FLASH], route)
            assert plan.depth == pytest.approx(factor) and plan.tokens == round(STANDARD_TOKENS * factor)
            # Dollars end the run: no token ceiling at the gateway.
            assert plan.gateway_tokens is None and plan.money_ends and plan.source == "cost cap"
    # A cap of $2 or less never adds depth, whatever the model.
    cheap = policy_from_table("m/cheap", {"input_cost_per_million": 0.001, "output_cost_per_million": 0.002})
    for cap in (0.1, 1.0, 2.0):
        assert plan_tokens(None, cap, [cheap], "funnel").depth == 1.0
    # An expensive model gets depth only when the cap buys its tokens.
    dear = policy_from_table("m/dear", {"input_cost_per_million": 1.0, "output_cost_per_million": 4.0})
    price = price_per_million(dear, "funnel") or 0.0
    assert plan_tokens(None, 10.0, [dear], "funnel").depth == 1.0
    plan = plan_tokens(None, 100.0, [dear], "funnel")
    assert plan.depth == pytest.approx(100.0 / price * 1_000_000 / STANDARD_TOKENS, rel=1e-6) and plan.depth < 50


def test_a_cap_that_buys_less_than_the_standard_run_plans_what_it_buys() -> None:
    price = price_per_million(DEEPSEEK_V41_FLASH, "funnel") or 0.0
    plan = plan_tokens(None, 0.5, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.source == "cost cap" and plan.tokens == int(0.5 / price * 1_000_000) < STANDARD_TOKENS
    # The money ends the run: the gateway applies no token ceiling, and the funnel plans more work while money is left.
    assert plan.depth == 1.0 and plan.gateway_tokens is None and plan.money_ends
    # At 85% of the cap no new work starts.
    assert SOFT_STOP_FRACTION == 0.85


def test_max_tokens_is_an_upper_limit_of_the_tokens() -> None:
    plan = plan_tokens(10_000_000, 20.0, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.tokens == plan.gateway_tokens == 10_000_000 and plan.source == "max_tokens" and plan.depth == 1.0
    plan = plan_tokens(50_000_000, 20.0, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.tokens == plan.gateway_tokens == 50_000_000 and plan.depth == 2.5 and not plan.money_ends
    plan = plan_tokens(50_000_000, 1.0, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.source == "cost cap" and plan.tokens < 50_000_000 and plan.gateway_tokens == 50_000_000 and plan.money_ends


def test_a_route_with_more_than_one_model_takes_the_highest_price() -> None:
    both = plan_tokens(None, 1.0, [GLM_53_FLASH, DEEPSEEK_V41_FLASH], "funnel")
    assert both.tokens == plan_tokens(None, 1.0, [DEEPSEEK_V41_FLASH], "funnel").tokens
    assert both.tokens < plan_tokens(None, 1.0, [GLM_53_FLASH], "funnel").tokens


def test_a_model_without_a_price_keeps_the_ceiling_and_says_why() -> None:
    plan = plan_tokens(None, 2.0, [DEEPSEEK_V41_FLASH, generic_policy("local/qwen")], "funnel")
    assert plan.tokens == DEFAULT_MAX_TOKENS and plan.source == "default" and plan.gateway_tokens == DEFAULT_MAX_TOKENS
    assert plan.note and "local/qwen" in plan.note and "[policies]" in plan.note
    free = policy_from_table("local/free", {"input_cost_per_million": 0, "output_cost_per_million": 0})
    assert plan_tokens(None, 2.0, [free], "agent").tokens == DEFAULT_MAX_TOKENS


def test_a_small_cap_gives_a_shallow_audit_and_a_warning() -> None:
    plan = plan_tokens(None, 0.1, [DEEPSEEK_V41_FLASH], "funnel")
    assert plan.tokens < SHALLOW_TOKENS and plan.note and "small part" in plan.note
    assert plan.record() == {
        "token_ceiling_source": "cost cap",
        "price_per_million_estimate": round(plan.price_per_million or 0, 6),
        "cost_cap_tokens": plan.tokens,
        "gateway_token_ceiling": None,
    }
