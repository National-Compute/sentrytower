"""The example configuration files load, and they say what they claim."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentrytower.config import load_config

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_the_single_llm_example_is_the_default_configuration() -> None:
    config = load_config(EXAMPLES / "single-llm.toml", environment={})
    default = load_config(environment={})
    assert config.models == default.models and config.budget == default.budget
    assert config.large_repo_files == default.large_repo_files and config.provider.base_url == default.provider.base_url


def test_the_multi_llm_example_gives_each_role_its_model() -> None:
    config = load_config(EXAMPLES / "multi-llm.toml", environment={})
    assert config.model_for("unit_check") == "vendor/small-model" and config.model_for("agent") == "vendor/agentic-model"
    assert config.model_for("rating") == "deepseek/deepseek-v4.1-flash-1017" and not config.single_model
    assert config.policies()["vendor/small-model"].reasoning_effort == "low"


def test_the_local_endpoint_example_needs_no_key_and_sends_max_tokens() -> None:
    config = load_config(EXAMPLES / "local-endpoint.toml", environment={})
    policy = config.policies()[config.default_model]
    assert not config.provider.require_api_key and config.provider.base_url == "http://127.0.0.1:8000/v1"
    assert policy.reasoning_effort is None and policy.token_field == "max_tokens" and policy.provider is None
    forwarded, _ = policy.rewrite({"model": config.default_model, "messages": [], "reasoning": {"effort": "medium"}})
    assert "reasoning" not in forwarded and forwarded["max_tokens"] == 16_384


@pytest.mark.parametrize("name", ["github-workflow.yml", "gitlab-ci.yml"])
def test_the_ci_examples_take_the_key_from_a_secret(name: str) -> None:
    text = (EXAMPLES / name).read_text()
    assert "OPENROUTER_API_KEY" in text and "sk-" not in text
