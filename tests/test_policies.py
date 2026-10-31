"""Model request policies: the built-in rewrites (DeepSeek V4.1 Flash, GLM 5.3 Flash), the generic policy and policy tables."""

from __future__ import annotations

import json

from sentrytower.policies import (
    BUILTIN_POLICIES,
    DEEPSEEK_V41_FLASH,
    DEFAULT_MODEL,
    GLM_53_FLASH,
    STRIPPED_REQUEST_KEYS,
    canonical_json,
    generic_policy,
    policy_from_table,
)

FUNNEL_REQUEST = {
    "model": "z-ai/glm-5.3-flash",
    "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u ✓"}],
    "stream": True,
    "stream_options": {"include_usage": True},
    "temperature": 1.0,
}


def test_the_rewrite_of_a_funnel_request() -> None:
    forwarded, changes = GLM_53_FLASH.rewrite(FUNNEL_REQUEST)
    assert forwarded == {
        **FUNNEL_REQUEST,
        "reasoning": {"effort": "medium"},
        "max_completion_tokens": 131072,
        "provider": {
            "only": ["z-ai/fp8", "atlas-cloud/fp8", "streamlake/fp8", "novita/fp8", "gmicloud/fp8"],
            "allow_fallbacks": True,
            "data_collection": "deny",
        },
    }
    assert [(change["key"], change["action"]) for change in changes] == [
        ("reasoning", "set"),
        ("max_completion_tokens", "set"),
        ("provider", "set"),
    ]
    # The canonical form: sorted keys, no spaces, UTF-8 (not escaped).
    data = canonical_json(forwarded)
    assert data.startswith(b'{"max_completion_tokens":131072,"messages":[')
    assert "u ✓".encode() in data and b": " not in data
    assert json.loads(data) == forwarded
    assert FUNNEL_REQUEST.get("reasoning") is None  # the input does not change


def test_the_rewrite_of_an_agent_request_strips_routes_and_server_tools() -> None:
    request = {
        "model": DEFAULT_MODEL,
        "messages": [{"role": "user", "content": "x"}],
        "tools": [
            {"type": "function", "function": {"name": "read", "parameters": {}}},
            {"type": "openrouter:web_search"},
        ],
        "tool_choice": {"type": "openrouter:web_search"},
        "max_tokens": 4096,
        "reasoning": {"effort": "high", "exclude": True},
        "provider": {"sort": "price"},
        **{key: "x" for key in STRIPPED_REQUEST_KEYS},
    }
    forwarded, changes = GLM_53_FLASH.rewrite(request)
    assert [tool["type"] for tool in forwarded["tools"]] == ["function"]
    assert "tool_choice" not in forwarded and "max_tokens" not in forwarded
    assert not any(key in forwarded for key in STRIPPED_REQUEST_KEYS)
    assert forwarded["reasoning"] == {"effort": "medium"} and forwarded["max_completion_tokens"] == 131072
    assert forwarded["provider"]["only"][0] == "z-ai/fp8"
    actions = {(change["key"], change["action"]) for change in changes}
    assert ("tools", "filtered") in actions and ("reasoning", "replaced") in actions and ("provider", "replaced") in actions
    assert all("value" not in change and "x" not in change.values() for change in changes)


def test_an_equal_value_is_no_change() -> None:
    request = {
        **FUNNEL_REQUEST,
        "reasoning": {"effort": "medium"},
        "max_completion_tokens": 131072,
        "provider": dict(GLM_53_FLASH.provider or {}),
    }
    forwarded, changes = GLM_53_FLASH.rewrite(request)
    assert changes == [] and forwarded == request


def test_the_generic_policy_sends_no_reasoning_and_no_route() -> None:
    policy = generic_policy("local/model")
    request = {**FUNNEL_REQUEST, "model": "local/model", "reasoning": {"effort": "medium"}, "provider": {"only": ["x"]}}
    forwarded, _ = policy.rewrite(request)
    assert "reasoning" not in forwarded and "provider" not in forwarded
    assert forwarded["max_completion_tokens"] == 32_768
    assert policy.thinking_level() == "off" and policy.cost_estimate(1000, 1000) is None


def test_a_policy_with_max_tokens_for_an_older_endpoint() -> None:
    policy = policy_from_table("local/model", {"token_field": "max_tokens", "max_completion_tokens": 2048})
    forwarded, _ = policy.rewrite({"model": "local/model", "messages": [], "max_completion_tokens": 9})
    assert forwarded["max_tokens"] == 2048 and "max_completion_tokens" not in forwarded


def test_the_agent_catalog_entry_and_the_prices() -> None:
    assert GLM_53_FLASH.pi_definition() == {
        "id": "z-ai/glm-5.3-flash",
        "name": "Z.ai GLM 5.3 Flash",
        "reasoning": True,
        "input": ["text"],
        "contextWindow": 1_310_720,
        "maxTokens": 131_072,
        "cost": {"input": 0.018, "output": 0.14, "cacheRead": 0.018, "cacheWrite": 0},
    }
    # 1M fresh input tokens and 1M output tokens; cached input at the cache price.
    assert round(GLM_53_FLASH.cost_estimate(1_000_000, 1_000_000) or 0, 6) == 0.158
    assert round(DEEPSEEK_V41_FLASH.cost_estimate(1_000_000, 0, cache_read_tokens=500_000) or 0, 6) == round(0.075 + 0.0015, 6)
    record = GLM_53_FLASH.record()
    assert "benchmarked" not in record and record["attempt_timeout_seconds"] == 240.0 and record["max_retries"] == 2


def test_the_default_model_is_deepseek_v41_flash_with_its_route_and_ceiling() -> None:
    assert DEFAULT_MODEL == DEEPSEEK_V41_FLASH.model_id == "deepseek/deepseek-v4.1-flash-1017"
    assert next(iter(BUILTIN_POLICIES)) == DEFAULT_MODEL
    forwarded, _ = DEEPSEEK_V41_FLASH.rewrite(FUNNEL_REQUEST)
    assert forwarded["model"] == FUNNEL_REQUEST["model"] and forwarded["max_completion_tokens"] == 65_536
    assert forwarded["reasoning"] == {"effort": "medium"}
    assert forwarded["provider"] == {
        "only": ["deepseek", "streamlake/fp8", "novita/fp8", "atlas-cloud/fp8", "gmicloud/fp8"],
        "allow_fallbacks": True,
        "data_collection": "deny",
    }
    # The standard ceiling is 65,536 tokens; a larger budget raises it up to the largest output of the route.
    assert DEEPSEEK_V41_FLASH.max_output_tokens == 384_000 and DEEPSEEK_V41_FLASH.record()["max_output_tokens"] == 384_000
    # The timeout is the longest wait for a byte: a long streamed answer can take longer as a whole.
    assert DEEPSEEK_V41_FLASH.attempt_timeout_seconds == 300.0
    assert DEEPSEEK_V41_FLASH.pi_definition()["input"] == ["text", "image"]


def test_each_built_in_route_denies_data_collection_and_a_request_cannot_change_it() -> None:
    # A request holds the code of the audited repository: OpenRouter may route it only to an endpoint
    # that does not collect user data.
    assert set(BUILTIN_POLICIES) == {DEEPSEEK_V41_FLASH.model_id, GLM_53_FLASH.model_id}
    for policy in BUILTIN_POLICIES.values():
        assert policy.provider is not None and policy.provider["data_collection"] == "deny"
        assert policy.record()["provider"]["data_collection"] == "deny"
        request = {**FUNNEL_REQUEST, "model": policy.model_id, "provider": {"data_collection": "allow", "sort": "price"}}
        forwarded, changes = policy.rewrite(request)
        assert forwarded["provider"] == dict(policy.provider)
        assert ("provider", "replaced") in {(change["key"], change["action"]) for change in changes}
        assert b'"data_collection":"deny"' in canonical_json(forwarded)
    # A model without a policy gets no provider route: the field belongs to the routes of OpenRouter.
    assert "provider" not in generic_policy("local/model").rewrite(FUNNEL_REQUEST)[0]


def test_the_fake_endpoint_of_the_smoke_refuses_a_built_in_model_without_the_data_policy() -> None:
    import importlib.util
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("fake_endpoint", Path(__file__).resolve().parent / "smoke" / "fake_endpoint.py")
    assert spec is not None and spec.loader is not None
    endpoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(endpoint)
    # The script cannot import SentryTower: its list of the built-in models must follow the policy table.
    assert set(endpoint.BUILTIN_MODELS) == set(BUILTIN_POLICIES)
    server = ThreadingHTTPServer(("127.0.0.1", 0), endpoint.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def post(body: dict[str, object]) -> tuple[int, bytes]:
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    try:
        for policy in BUILTIN_POLICIES.values():
            status, data = post({**FUNNEL_REQUEST, "model": policy.model_id, "provider": {"only": ["x"], "allow_fallbacks": True}})
            assert status == 400 and 'must set provider.data_collection to "deny"' in json.loads(data)["error"]["message"]
            status, _ = post({**FUNNEL_REQUEST, "model": policy.model_id})
            assert status == 400
            status, data = post(policy.rewrite({**FUNNEL_REQUEST, "model": policy.model_id})[0])
            assert status == 200 and data.startswith(b"data: ")
        status, _ = post({**FUNNEL_REQUEST, "model": "local/model"})
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()
