"""The model gateway: credential, model allowlist, rewrite, retries, budget refusals, usage and no key leakage."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from fakes import MODEL, FakeModel
from sentrytower.gateway import GatewayConfig, ModelGateway, http_transport
from sentrytower.limits import BUDGET_ERROR_TYPE
from sentrytower.policies import GLM_53_FLASH, canonical_json, resolve_policies

KEY = "provider-key-that-must-never-leak"
REQUEST = {
    "model": MODEL,
    "messages": [
        {"role": "system", "content": "You are a security code auditor."},
        {"role": "user", "content": "Audit this code for security vulnerabilities."},
    ],
    "stream": True,
    "stream_options": {"include_usage": True},
    "temperature": 1.0,
}


def gateway(fake: FakeModel, **settings: Any) -> ModelGateway:
    sleeps = settings.pop("sleeps", None)
    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key=settings.pop("api_key", KEY), policies=resolve_policies([MODEL]), **settings
    )
    return ModelGateway(config, transport=fake.transport, sleep=(sleeps.append if sleeps is not None else lambda _: None))


def post(url: str, body: Any, token: str | None, path: str = "/chat/completions") -> tuple[int, dict[str, str], bytes]:
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"content-type": "application/json"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def test_a_call_is_rewritten_with_the_policy_and_sent_with_the_provider_key() -> None:
    fake = FakeModel()
    with gateway(fake, headers={"X-Title": "SentryTower"}) as server:
        status, headers, body = post(server.url, REQUEST, server.token)
    assert status == 200 and headers["content-type"] == "text/event-stream"
    assert b"data: [DONE]" in body
    forwarded, _ = GLM_53_FLASH.rewrite(REQUEST)
    assert fake.bodies == [canonical_json(forwarded)]
    upstream = fake.headers[0]
    assert upstream["authorization"] == f"Bearer {KEY}" and upstream["X-Title"] == "SentryTower"
    totals = server.totals()["total"]
    assert totals["calls"] == 1 and totals["attempts"] == 1 and totals["total_tokens"] > 0
    assert totals["cost_source"] == "estimate" and totals["cost_usd"] > 0


@pytest.mark.parametrize(
    ("token", "path", "body", "status"),
    [
        (None, "/chat/completions", REQUEST, 401),
        ("wrong", "/chat/completions", REQUEST, 401),
        ("TOKEN", "/v1/chat/completions", REQUEST, 404),
        ("TOKEN", "/completions", REQUEST, 404),
        ("TOKEN", "/chat/completions", b"not json", 400),
        ("TOKEN", "/chat/completions", [1, 2], 400),
        ("TOKEN", "/chat/completions", {**REQUEST, "model": "other/model"}, 422),
    ],
)
def test_a_request_outside_the_contract_gets_no_upstream_call(token: str | None, path: str, body: Any, status: int) -> None:
    fake = FakeModel()
    with gateway(fake) as server:
        code, _, answer = post(server.url, body, server.token if token == "TOKEN" else token, path)
    assert code == status and fake.bodies == []
    assert KEY.encode() not in answer


def test_a_large_body_gets_413() -> None:
    fake = FakeModel()
    with gateway(fake, max_request_bytes=1000) as server:
        code, _, _ = post(server.url, {**REQUEST, "messages": [{"role": "user", "content": "x" * 5000}]}, server.token)
    assert code == 413 and fake.bodies == []


def test_transient_failures_are_retried_with_back_off() -> None:
    sleeps: list[float] = []
    fake = FakeModel(statuses=[429, 503])
    with gateway(fake, sleeps=sleeps) as server:
        code, _, _ = post(server.url, REQUEST, server.token)
    assert code == 200 and len(fake.bodies) == 3 and len(set(fake.bodies)) == 1
    assert sleeps == [2.0, 4.0]
    usage = server.totals()["models"][MODEL]
    assert (usage["attempts"], usage["retries"], usage["failures"]) == (3, 2, 0)


def test_the_last_failure_is_returned_after_the_attempts_of_the_policy() -> None:
    fake = FakeModel(statuses=[500, 502, 503, 200])
    with gateway(fake) as server:
        code, _, _ = post(server.url, REQUEST, server.token)
    # GLM 5.3 Flash: one attempt and two retries.
    assert code == 503 and len(fake.bodies) == 3
    assert server.totals()["models"][MODEL]["failures"] == 1


def test_a_client_error_without_an_error_body_is_not_retried() -> None:
    bodies: list[bytes] = []

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        bodies.append(body)
        return 404, "text/plain", b"no such route"

    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as server:
        code, _, _ = post(server.url, REQUEST, server.token)
    assert code == 404 and len(bodies) == 1


def test_an_answer_with_an_error_object_is_retried() -> None:
    # The gateway of the measured runs retried each answer whose body reports an error, also a 4xx answer.
    fake = FakeModel(statuses=[400])
    with gateway(fake) as server:
        code, _, _ = post(server.url, REQUEST, server.token)
    assert code == 200 and len(fake.bodies) == 2


def test_a_transport_error_and_a_response_without_usage_are_retried() -> None:
    calls: list[int] = []

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError("slow")
        if len(calls) == 2:
            return 200, "application/json", b'{"choices": [{"message": {"content": "x"}, "finish_reason": "stop"}]}'
        usage = {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
        answer = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}], "usage": usage}
        return 200, "application/json", json.dumps(answer).encode()

    config = GatewayConfig(base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]))
    with ModelGateway(config, transport=transport, sleep=lambda _: None) as server:
        code, _, body = post(server.url, REQUEST, server.token)
    assert code == 200 and json.loads(body)["choices"][0]["message"]["content"] == "ok" and len(calls) == 3
    assert server.totals()["total"]["total_tokens"] == 7


def test_the_token_ceiling_refuses_a_call_before_it_goes_upstream() -> None:
    fake = FakeModel()
    # One call reserves the request size / 3 + 131,072 completion tokens.
    with gateway(fake, max_total_tokens=100_000) as server:
        code, headers, body = post(server.url, REQUEST, server.token)
    assert code == 402 and fake.bodies == []
    error = json.loads(body)["error"]
    assert error["type"] == BUDGET_ERROR_TYPE and error["code"] == "token_ceiling"
    assert "token ceiling reached" in error["message"] and "quota exceeded" in error["message"]
    assert headers["x-should-retry"] == "false"
    assert server.totals()["total"]["budget_refusals"] == 1


def test_the_cost_cap_refuses_a_call_at_the_policy_prices() -> None:
    fake = FakeModel()
    with gateway(fake, max_cost_usd=0.01) as server:
        code, _, body = post(server.url, REQUEST, server.token)
    # The worst case of one call: 131,072 output tokens at $0.25 a million, about $0.033.
    assert code == 402 and json.loads(body)["error"]["code"] == "spend_ceiling" and fake.bodies == []


def test_the_cost_that_the_provider_reports_is_the_cost_of_the_run() -> None:
    fake = FakeModel(cost=0.0042)
    with gateway(fake) as server:
        post(server.url, REQUEST, server.token)
        post(server.url, REQUEST, server.token)
    total = server.totals()["total"]
    assert total["cost_usd"] == pytest.approx(0.0084) and total["cost_source"] == "provider"


def test_the_gateway_admits_at_most_the_parallel_requests_of_the_configuration() -> None:
    active, peak, lock = [0], [0], threading.Lock()

    def transport(url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.2)
        with lock:
            active[0] -= 1
        return FakeModel().respond(body)

    config = GatewayConfig(
        base_url="https://openrouter.ai/api/v1", api_key=KEY, policies=resolve_policies([MODEL]), max_parallel_requests=2
    )
    with ModelGateway(config, transport=transport) as server:
        threads = [threading.Thread(target=post, args=(server.url, REQUEST, server.token)) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert peak[0] == 2


def test_the_key_never_appears_in_a_representation_a_record_or_an_answer() -> None:
    fake = FakeModel(statuses=[500, 500, 500])
    with gateway(fake) as server:
        _, _, failed = post(server.url, REQUEST, server.token)
        _, _, refused = post(server.url, REQUEST, "wrong")
        assert KEY not in repr(server.config)
        assert KEY not in json.dumps(server.totals()) and KEY not in json.dumps(server.refusals)
    assert KEY.encode() not in failed and KEY.encode() not in refused


def test_a_local_endpoint_without_a_key_gets_no_authorization_header() -> None:
    fake = FakeModel()
    with gateway(fake, api_key="") as server:
        code, _, _ = post(server.url, REQUEST, server.token)
    assert code == 200 and "authorization" not in fake.headers[0]


def test_the_http_transport_reads_a_local_endpoint_and_enforces_the_deadline() -> None:
    received: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_POST(self) -> None:
            received.append(self.rfile.read(int(self.headers["content-length"])))
            if self.path.endswith("/slow/chat/completions"):
                time.sleep(2)
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        status, content_type, body = http_transport(url + "/v1/chat/completions", b'{"a":1}', {"content-type": "application/json"}, 10)
        assert (status, content_type, body) == (200, "application/json", b'{"ok": true}') and received == [b'{"a":1}']
        with pytest.raises(TimeoutError):
            http_transport(url + "/slow/chat/completions", b"{}", {}, 0.5)
    finally:
        server.shutdown()
        server.server_close()


def test_the_configuration_rejects_a_bad_endpoint() -> None:
    with pytest.raises(ValueError):
        GatewayConfig(base_url="file:///etc/passwd", api_key=KEY, policies=resolve_policies([MODEL]))
    with pytest.raises(ValueError):
        GatewayConfig(base_url="https://example.com", api_key=KEY, policies={})
