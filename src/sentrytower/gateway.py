"""The model gateway of a run: one local endpoint between the engines and the model provider.

Each model call of a run goes through the gateway: the direct calls of the
funnel and each request of each agent session. The gateway:

- listens on the loopback address only, on a free port, and accepts only
  ``POST /chat/completions`` with the credential of the run (a random token;
  the engines never get the provider key);
- accepts only the models of the run, and rewrites each request with the
  policy of its model (``policies.ModelPolicy.rewrite``) before it sends the
  request upstream as canonical JSON;
- holds the provider key, reads it from the environment of the parent
  process only, and never writes it to a log, a record or an error message;
- enforces the token ceiling of the run (None: dollars only) and the cost
  cap: each upstream attempt reserves its worst case (the request size / 3
  + the completion ceiling, and its cost at the policy prices). An attempt
  that fits only after the attempts in flight settle waits for them (the
  hold; it holds no reservation while it waits, at most
  ``hold_wait_seconds``). The hold is first in, first out: while earlier
  attempts wait, a new attempt queues behind them, and the first of the
  queue reserves first. Only an attempt that cannot fit with nothing in
  flight gets HTTP 402 with the budget error, and no upstream call. After
  a provider refusal and at the stop of the gateway, each waiting attempt
  is refused at once and never goes upstream. The completion ceiling of a
  call is the ceiling of its policy at every depth;
- answers ``GET /budget`` (with the credential of the run): numbers only,
  the money of the run and whether new work must stop
  (``soft_stop_fraction`` of the cap, 85%, is spent; or the provider
  refused the run). "Spent" is the committed cost of the finished attempts:
  the reservations of the attempts in flight are worst cases, often many
  times their real cost, and the last 15% of the cap is for them and for
  the final turns of the running sessions;
- retries a transient failure (HTTP 429 and 5xx, a transport error, a
  timeout, an error in the response, a response without usage) with a
  back-off (2 s, then 4 s), up to the attempts of the policy. An attempt
  has no time limit of its own: it fails when the endpoint sends no byte
  for the timeout of the policy (the wall clock of the run ends the rest);
- answers each request: an unexpected error gives HTTP 500 or 502, and
  each reservation is released;
- admits at most ``max_parallel_requests`` upstream attempts at the same
  time, in the order of arrival (``_Gate``);
- counts the usage of each attempt: tokens, and the cost that the provider
  reports (else the estimate at the policy prices). An attempt without a
  usage report (a timeout, a failure) counts no tokens and no cost, as in
  the measured runs;
- stops the run's model calls after the provider refuses the key, the
  account or the route (HTTP 401, 402, 403 or 404 from upstream,
  ``FATAL_STATUSES``): that attempt gets no retry, and each later or
  waiting request gets the same status at once, with no upstream call.
  ``provider_error`` holds the first such answer, so that the parent stops
  the engine. An upstream 402 (no credit) is not the budget refusal of the
  gateway, which never goes upstream.

A call fails when its last attempt ends with an HTTP error, a provider
error or a malformed answer (``failures``); a budget refusal and a request
after a provider refusal are not failed calls, and ``upstream_calls``
counts only the calls that reached the provider.

The gateway records numbers and codes only, never prompt or response text.
The one exception is the error message of a provider refusal, for the run
record: at most 200 characters, without control characters or the key, and
none at all when a part of it is in the request.

Standard library only.
"""

from __future__ import annotations

import base64
import hmac
import http.client
import json
import math
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from .limits import BUDGET_ERROR_TYPE, BUDGET_STATUS, SPEND_CEILING_TEXT, TOKEN_CEILING_TEXT
from .policies import ModelPolicy, canonical_json

ALLOWED_PATHS = ("/chat/completions",)
MAX_REQUEST_BYTES = 64 * 1024 * 1024
# Request bytes for each input token in the reservation estimate. Source
# code and JSON average about four bytes for each token; three makes the
# estimate an upper bound for nearly all requests.
RESERVATION_BYTES_PER_TOKEN = 3
ALLOWED_FINISH_REASONS = ("stop", "length", "tool_calls")
TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
# The upstream answers that end the model calls of a run: a refused key (401), an account
# without credit (402), a refused account (403), a route that no endpoint serves (404).
FATAL_STATUSES = frozenset({401, 402, 403, 404})
PROVIDER_REFUSED_TYPE = "sentrytower_provider_refused"
# Why the hold refused an attempt without a budget reason: a provider refusal of the run, or the stop of the gateway.
_BLOCKED = "provider refusal"
_CLOSED = "gateway stopped"
# The name of a failed call by the outcome of its last attempt (an HTTP error gives its status).
FAILURE_LABELS = {"provider_error": "provider error", "malformed": "malformed answer"}
# The longest provider message in the run record, and the shortest part of it that may not be in the request.
PROVIDER_MESSAGE_CHARS = 200
_ECHO_CHARS = 24
RETRY_BASE_DELAY_SECONDS = 2.0
DEFAULT_PARALLEL_REQUESTS = 8
# The longest wait of an attempt for the attempts in flight (the hold), and the share of the cap at which new work stops.
# The hold ends before the clients give up on a call (780 s in the funnel and in the deep engine): a call that a client
# gave up must not go upstream and cost money later.
HOLD_WAIT_SECONDS = 600.0
SOFT_STOP_FRACTION = 0.85
BUDGET_PATH = "/budget"
UPSTREAM_ERROR = {"error": {"message": "upstream request failed", "type": "upstream_error"}}
_READ_CHUNK = 1 << 16
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}")
# A long run of key characters in a provider message: a key or a part of one.
_KEY_LIKE = re.compile(r"[A-Za-z0-9_\-]{24,}")


class GatewayError(RuntimeError):
    """The gateway cannot start."""


def _count(value: Any) -> int:
    """A token count of a usage report: a whole number of at least 0; anything else counts 0."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value)) if math.isfinite(value) else 0
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit() and len(value.strip()) <= 15:
        return int(value.strip())
    return 0


def usage_from_payload(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return None
    details = usage.get("prompt_tokens_details") or {}
    completion = usage.get("completion_tokens_details") or {}
    cost = usage.get("cost")
    reported_cost: float | None = None
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and math.isfinite(cost) and cost >= 0:
        reported_cost = float(cost)
    return {
        "input_tokens": _count(usage.get("prompt_tokens")),
        "output_tokens": _count(usage.get("completion_tokens")),
        "reasoning_tokens": _count(completion.get("reasoning_tokens") if isinstance(completion, Mapping) else 0),
        "cache_read_tokens": _count(details.get("cached_tokens") if isinstance(details, Mapping) else 0),
        "total_tokens": _count(usage.get("total_tokens")),
        "cost_usd": reported_cost,
        "complete": "total_tokens" in usage,
    }


def _sse_payloads(body: bytes) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for line in body.splitlines():
        if not line.startswith(b"data:"):
            continue
        raw = line[5:].strip()
        if raw == b"[DONE]":
            continue
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(value, dict):
            payloads.append(value)
    return payloads


def read_response(body: bytes, content_type: str) -> tuple[dict[str, Any] | None, bool, list[str]]:
    """The usage, whether the body reports an error, and the finish reasons of one response body."""
    if "text/event-stream" in content_type:
        payloads = _sse_payloads(body)
    else:
        try:
            parsed = json.loads(body) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = {}
        payloads = [parsed] if isinstance(parsed, dict) else []
    usage: dict[str, Any] | None = None
    error = False
    reasons: dict[int, str] = {}
    for payload in payloads:
        found = usage_from_payload(payload)
        if found is not None:
            usage = found
        if payload.get("error"):
            error = True
        choices = payload.get("choices")
        for position, choice in enumerate(choices if isinstance(choices, list) else []):
            if isinstance(choice, dict) and isinstance(choice.get("finish_reason"), str):
                reasons[position] = choice["finish_reason"]
                if choice["finish_reason"] == "error":
                    error = True
    return usage, error, sorted(set(reasons.values()))


def request_text(value: Any) -> str:
    """The text of the messages of a request (each string in them), for the check of a provider message."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(request_text(item) for item in value.values())
    if isinstance(value, list):
        return "\n".join(request_text(item) for item in value)
    return ""


def provider_message(body: bytes, key: str, request: str) -> str | None:
    """The error message of a provider answer for the run record, or None.

    The message is at most ``PROVIDER_MESSAGE_CHARS`` characters, without
    control characters, the key or a long run of key characters. A message
    with a part of ``request`` (the text of the messages of the call) gives
    None: an echo of the request could hold code.
    """
    try:
        payload = json.loads(body) if body else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    if not isinstance(message, str):
        return None
    text = " ".join("".join(character if character.isprintable() else " " for character in message).split())
    if key:
        text = text.replace(key, "[key]")
    text = _KEY_LIKE.sub("[redacted]", text)[:PROVIDER_MESSAGE_CHARS].strip()
    if any(text[index : index + _ECHO_CHARS] in request for index in range(max(0, len(text) - _ECHO_CHARS + 1))):
        return None
    return text or None


def classify(status: int, error: bool, reasons: list[str], usage: dict[str, Any] | None) -> str:
    """One word for what an attempt returned: ok, truncated, malformed, provider_error or http_error."""
    if status >= 400:
        return "http_error"
    if error or any(reason not in ALLOWED_FINISH_REASONS for reason in reasons):
        return "provider_error"
    if usage is None or not usage.get("complete"):
        return "malformed"
    if "length" in reasons:
        return "truncated"
    return "ok"


@dataclass
class ModelUsage:
    """The usage of one model in a run."""

    calls: int = 0
    # The calls with at least one upstream attempt; a budget refusal and a blocked call have none.
    upstream_calls: int = 0
    attempts: int = 0
    retries: int = 0
    refusals: int = 0
    failures: int = 0
    # The calls that came after a provider refusal (FATAL_STATUSES): no upstream call.
    blocked: int = 0
    # The failed calls by the outcome of their last attempt: "HTTP 429", "provider error", "malformed answer".
    failed_by: dict[str, int] = field(default_factory=dict)
    # Attempts that ended at the output ceiling of their call ("length").
    length_stops: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_read_tokens: int = 0
    total_tokens: int = 0
    reported_cost_usd: float = 0.0
    estimated_cost_usd: float = 0.0
    attempts_with_reported_cost: int = 0
    attempts_with_estimated_cost: int = 0
    attempts_without_cost: int = 0

    def record(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "upstream_calls": self.upstream_calls,
            "attempts": self.attempts,
            "retries": self.retries,
            "refusals": self.refusals,
            "failures": self.failures,
            "blocked": self.blocked,
            "failed_by": dict(sorted(self.failed_by.items())),
            "length_stops": self.length_stops,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.reported_cost_usd + self.estimated_cost_usd, 6),
            "cost_reported_usd": round(self.reported_cost_usd, 6),
            "cost_estimated_usd": round(self.estimated_cost_usd, 6),
            "attempts_with_reported_cost": self.attempts_with_reported_cost,
            "attempts_with_estimated_cost": self.attempts_with_estimated_cost,
            "attempts_without_cost": self.attempts_without_cost,
        }


@dataclass
class _Ledger:
    committed_tokens: int = 0
    committed_cost: float = 0.0
    reserved_tokens: int = 0
    reserved_cost: float = 0.0
    # The attempts that hold a reservation.
    in_flight: int = 0


class _Gate:
    """At most ``limit`` upstream attempts at the same time; a waiting attempt enters in the order of arrival.

    A semaphore of the threading module is not fair: a thread that frees a
    place can take it again before a waiting thread wakes, so a long agent
    call could wait without end while short calls take each freed place.
    """

    def __init__(self, limit: int) -> None:
        self._free = limit
        self._waiting: deque[object] = deque()
        self._changed = threading.Condition()

    def __enter__(self) -> None:
        place = object()
        with self._changed:
            self._waiting.append(place)
            try:
                while self._waiting[0] is not place or self._free == 0:
                    self._changed.wait()
                self._free -= 1
            finally:
                self._waiting.remove(place)
                # The next attempt of the queue may enter now.
                self._changed.notify_all()

    def __exit__(self, *_: object) -> None:
        with self._changed:
            self._free += 1
            self._changed.notify_all()


@dataclass(frozen=True)
class GatewayConfig:
    """The settings of one gateway. The key is left out of ``repr``."""

    base_url: str
    api_key: str = field(repr=False)
    policies: Mapping[str, ModelPolicy] = field(default_factory=dict)
    max_total_tokens: int | None = None
    max_cost_usd: float | None = None
    max_parallel_requests: int = DEFAULT_PARALLEL_REQUESTS
    retry_base_delay: float = RETRY_BASE_DELAY_SECONDS
    hold_wait_seconds: float = HOLD_WAIT_SECONDS
    # None: no soft stop (a run that its token ceiling ends; the cap is an upper limit only).
    soft_stop_fraction: float | None = SOFT_STOP_FRACTION
    headers: Mapping[str, str] = field(default_factory=dict)
    max_request_bytes: int = MAX_REQUEST_BYTES

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("the provider base URL must be an http or https URL")
        if not self.policies:
            raise ValueError("the gateway needs at least one model policy")
        if self.max_parallel_requests < 1:
            raise ValueError("max_parallel_requests must be positive")


Transport = Callable[[str, bytes, Mapping[str, str], float], tuple[int, str, bytes]]


def proxy_problem(base_url: str) -> str | None:
    """Why the proxy of the environment cannot carry the requests to ``base_url``, or None."""
    proxy = _proxy_for(urllib.parse.urlsplit(base_url))
    if proxy is not None and proxy.scheme != "http":
        return f"the proxy of the endpoint must be an http:// URL; a {proxy.scheme}:// proxy is not supported"
    return None


def _proxy_headers(proxy: urllib.parse.SplitResult) -> dict[str, str]:
    """The Proxy-Authorization header for a proxy URL with a user part (``http://user:password@host:port``)."""
    if proxy.username is None:
        return {}
    pair = f"{urllib.parse.unquote(proxy.username)}:{urllib.parse.unquote(proxy.password or '')}"
    return {"Proxy-Authorization": "Basic " + base64.b64encode(pair.encode()).decode("ascii")}


def _proxy_for(url: urllib.parse.SplitResult) -> urllib.parse.SplitResult | None:
    """The proxy of the environment for ``url`` (HTTPS_PROXY, HTTP_PROXY, NO_PROXY), or None."""
    host = url.hostname or ""
    try:
        if urllib.request.proxy_bypass(host):
            return None
    except OSError:
        return None
    proxy = urllib.request.getproxies().get(url.scheme)
    if not proxy:
        return None
    parsed = urllib.parse.urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    return parsed if parsed.hostname else None


def http_transport(url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> tuple[int, str, bytes]:
    """One HTTP POST; returns the status, the content type and the body.

    ``timeout`` is the longest wait for a byte: the connection, the request
    and each read of the answer. A streamed answer can take as long as it
    sends bytes. It honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY (a CONNECT
    tunnel for an https endpoint), with the user and the password of the
    proxy URL. A timeout raises ``TimeoutError``.
    """
    target = urllib.parse.urlsplit(url)
    proxy = _proxy_for(target)
    port = target.port or (443 if target.scheme == "https" else 80)
    path = target.path or "/"
    if target.query:
        path += "?" + target.query
    connection: http.client.HTTPConnection
    headers = dict(headers)
    if proxy is not None:
        if proxy.scheme != "http":
            raise ValueError("only an http:// proxy is supported")
        proxy_port = proxy.port or 80
        if target.scheme == "https":
            connection = http.client.HTTPSConnection(
                proxy.hostname or "", proxy_port, timeout=timeout, context=ssl.create_default_context()
            )
            connection.set_tunnel(target.hostname or "", port, headers=_proxy_headers(proxy))
        else:
            connection = http.client.HTTPConnection(proxy.hostname or "", proxy_port, timeout=timeout)
            path = url
            headers.update(_proxy_headers(proxy))
    elif target.scheme == "https":
        connection = http.client.HTTPSConnection(target.hostname or "", port, timeout=timeout, context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(target.hostname or "", port, timeout=timeout)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        chunks: list[bytes] = []
        while True:
            if connection.sock is not None:
                connection.sock.settimeout(timeout)
            try:
                chunk = response.read1(_READ_CHUNK)
            except socket.timeout:
                raise TimeoutError("the endpoint sent no byte within the timeout") from None
            if not chunk:
                break
            chunks.append(chunk)
        return response.status, response.getheader("content-type", "") or "", b"".join(chunks)
    finally:
        connection.close()


class ModelGateway:
    """The local endpoint of a run. Use it as a context manager, or ``start`` and ``stop``."""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_call: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or http_transport
        self.sleep = sleep
        self.on_call = on_call
        self.token = secrets.token_urlsafe(32)
        self.upstream_url = config.base_url.rstrip("/") + "/chat/completions"
        self._gate = _Gate(config.max_parallel_requests)
        self._lock = threading.Lock()
        # Each settled attempt wakes the attempts that wait in the hold.
        self._settled = threading.Condition(self._lock)
        self._ledger = _Ledger()
        # The attempts that wait in the hold, in the order of arrival: only the first one may reserve.
        self._waiting: deque[object] = deque()
        # The gateway stopped: no attempt reserves, and none goes upstream later.
        self._closed = False
        self.usage: dict[str, ModelUsage] = {model: ModelUsage() for model in config.policies}
        self.refusals: list[dict[str, Any]] = []
        # The first provider refusal of the run (FATAL_STATUSES): status, model and the checked message.
        self.provider_error: dict[str, Any] | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise GatewayError("the gateway is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host if isinstance(host, str) else host.decode()}:{port}"

    def start(self) -> ModelGateway:
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SentryTowerGateway"
            sys_version = ""
            protocol_version = "HTTP/1.1"
            # An idle keep-alive connection closes after this time; the client opens a new one.
            timeout = 300

            def log_message(self, *_: object) -> None:
                # No access log: a request line holds no secret, but the gateway logs nothing.
                pass

            def do_GET(self) -> None:
                route = urllib.parse.urlsplit(self.path).path.rstrip("/")
                if route == "/healthz":
                    self._send(200, "application/json", json.dumps({"status": "ok"}).encode())
                elif route == BUDGET_PATH:
                    if gateway.authorized(self.headers):
                        self._send(200, "application/json", canonical_json(gateway.budget_state()))
                    else:
                        self._send(*_error(401, "the credential of the run is missing or wrong"))
                else:
                    self._send(404, "application/json", json.dumps({"error": {"message": "not found"}}).encode())

            def do_POST(self) -> None:
                # The path and the credential come before the body: a request without the credential
                # of the run gets its answer before the gateway reads a byte of its body.
                refusal = gateway.check_request(self.path, self.headers)
                if refusal is not None:
                    self.close_connection = True
                    self._send(*refusal)
                    return
                try:
                    body = self._body()
                except ValueError:
                    self.close_connection = True
                    self._send(*_error(400, "the request body is not valid HTTP"))
                    return
                try:
                    status, content_type, data, extra = gateway.handle(self.path, self.headers, body)
                except Exception as error:  # noqa: BLE001 - each request gets an answer
                    status, content_type, data, extra = _error(500, f"gateway error ({type(error).__name__})")
                self._send(status, content_type, data, extra)

            def _body(self) -> bytes | None:
                """The request body; None when it is larger than the limit. A malformed body raises ValueError."""
                length = (self.headers.get("content-length") or "").strip()
                if length:
                    if not (length.isascii() and length.isdigit()):
                        raise ValueError("content-length")
                    if int(length) > gateway.config.max_request_bytes:
                        # The body stays unread: the connection cannot carry another request.
                        self.close_connection = True
                        return None
                    return self.rfile.read(int(length))
                if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
                    chunks: list[bytes] = []
                    size = 0
                    while True:
                        field = self.rfile.readline(65537).strip().split(b";", 1)[0].strip()
                        if not _CHUNK_SIZE.fullmatch(field):
                            raise ValueError("chunk size")
                        count = int(field, 16)
                        if count == 0:
                            self.rfile.readline(65537)
                            break
                        size += count
                        if size > gateway.config.max_request_bytes:
                            self.close_connection = True
                            return None
                        chunk = self.rfile.read(count)
                        if len(chunk) != count:
                            raise ValueError("chunk")
                        chunks.append(chunk)
                        self.rfile.readline(65537)
                    return b"".join(chunks)
                return b""

            def _send(self, status: int, content_type: str, body: bytes, extra: Mapping[str, str] | None = None) -> None:
                try:
                    self.send_response(status)
                    if content_type:
                        self.send_header("content-type", content_type)
                    for name, value in (extra or {}).items():
                        self.send_header(name, value)
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = False
            # The stop does not wait for the handler threads of idle keep-alive connections.
            block_on_close = False

        try:
            self._server = Server(("127.0.0.1", 0), Handler)
        except OSError as error:
            raise GatewayError(f"the gateway cannot listen on the loopback address: {type(error).__name__}") from None
        self._thread = threading.Thread(target=self._server.serve_forever, name="gateway", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        with self._settled:
            # Each attempt that waits in the hold is refused at once: none goes upstream after the run.
            self._closed = True
            self._settled.notify_all()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)

    def __enter__(self) -> ModelGateway:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def check_request(self, path: str, headers: Any) -> tuple[int, str, bytes, dict[str, str]] | None:
        """The answer to a request with a path that is not served or without the credential of the run, else None."""
        route = urllib.parse.urlsplit(path).path.rstrip("/") or "/"
        if route not in ALLOWED_PATHS:
            return _error(404, "this path is not served")
        if not self.authorized(headers):
            return _error(401, "the credential of the run is missing or wrong")
        return None

    def authorized(self, headers: Any) -> bool:
        """Whether a request holds the credential of the run."""
        authorization = headers.get("authorization") or ""
        expected = f"Bearer {self.token}"
        return hmac.compare_digest(authorization.encode("utf-8", "surrogateescape"), expected.encode())

    def budget_state(self) -> dict[str, Any]:
        """The money of the run for the engines (``GET /budget``): numbers only.

        ``stop`` is true when the committed cost reached ``soft_stop_fraction``
        of the cap, or after a provider refusal: no new work may start.
        """
        with self._lock:
            spent, in_flight = self._ledger.committed_cost, self._ledger.reserved_cost
            tokens, refused = self._ledger.committed_tokens, self.provider_error is not None
        cap = self.config.max_cost_usd
        fraction = self.config.soft_stop_fraction
        soft_stop = cap * fraction if cap is not None and fraction is not None else None
        reason = "provider-error" if refused else ("budget" if soft_stop is not None and spent >= soft_stop else None)
        return {
            "cap_usd": cap,
            "spent_usd": round(spent, 6),
            "in_flight_usd": round(max(0.0, in_flight), 6),
            "soft_stop_usd": round(soft_stop, 6) if soft_stop is not None else None,
            "tokens": tokens,
            "token_ceiling": self.config.max_total_tokens,
            "stop": reason is not None,
            "reason": reason,
        }

    def handle(self, path: str, headers: Any, body: bytes | None) -> tuple[int, str, bytes, dict[str, str]]:
        """One request of an engine: the status, the content type, the body and extra headers of the answer."""
        refusal = self.check_request(path, headers)
        if refusal is not None:
            return refusal
        if body is None:
            return _error(413, "the request body is too large")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "the request body must be JSON")
        if not isinstance(payload, dict):
            return _error(400, "the request body must be a JSON object")
        model = payload.get("model")
        policy = self.config.policies.get(model) if isinstance(model, str) else None
        if policy is None:
            return _error(422, f"the model must be one of: {', '.join(sorted(self.config.policies))}")
        forwarded, _ = policy.rewrite(payload)
        data = canonical_json(forwarded)
        usage = self.usage[policy.model_id]
        with self._lock:
            usage.calls += 1
        reservation, refused = self._reserve(policy, data)
        if refused == _BLOCKED:
            with self._lock:
                usage.blocked += 1
                blocked = self.provider_error
            assert blocked is not None
            return _provider_refused(int(blocked["status"]))
        if refused == _CLOSED:
            return _closed()
        if refused is not None:
            return self._refuse(policy, refused)
        assert reservation is not None
        with self._lock:
            usage.upstream_calls += 1
        attempts = 1 + policy.max_retries
        upstream_headers = {"content-type": "application/json", **dict(self.config.headers)}
        if self.config.api_key:
            # A local endpoint without authentication gets no authorization header.
            upstream_headers["authorization"] = f"Bearer {self.config.api_key}"
        status, content_type, response = 502, "application/json", canonical_json(UPSTREAM_ERROR)
        outcome = "http_error"
        found: dict[str, Any] | None = None
        reasons: list[str] = []
        started = time.monotonic()
        for attempt in range(attempts):
            found, error, reasons, transport_failed, fatal = None, False, [], False, False
            try:
                with self._gate:
                    try:
                        status, content_type, response = self.transport(
                            self.upstream_url, data, upstream_headers, policy.attempt_timeout_seconds
                        )
                    except Exception:  # noqa: BLE001 - any transport failure is a failed attempt
                        status, content_type, response = 502, "application/json", canonical_json(UPSTREAM_ERROR)
                        transport_failed = True
                found, error, reasons = read_response(response, content_type)
                outcome = classify(status, error, reasons, found)
                if outcome == "truncated":
                    with self._lock:
                        usage.length_stops += 1
                fatal = status in FATAL_STATUSES and not transport_failed
                if fatal:
                    # Before the release of the reservation: no attempt that waits in the hold reserves after it.
                    self._provider_refused(policy, status, response, forwarded)
            finally:
                # The reservation of the attempt is released whatever happens.
                assert reservation is not None
                self._settle(policy, reservation, found, attempt)
            retry = (
                not fatal
                and attempt + 1 < attempts
                and (status in TRANSIENT_STATUSES or error or outcome in ("malformed", "provider_error"))
            )
            if retry:
                reservation, _ = self._reserve(policy, data)
                retry = reservation is not None
            if not retry:
                if outcome in ("http_error", "provider_error", "malformed"):
                    label = "transport error" if transport_failed else FAILURE_LABELS.get(outcome) or f"HTTP {status}"
                    with self._lock:
                        usage.failures += 1
                        usage.failed_by[label] = usage.failed_by.get(label, 0) + 1
                break
            self.sleep(self.config.retry_base_delay * (2**attempt))
        if self.on_call is not None:
            seconds = round(time.monotonic() - started, 3)
            call = {"model": policy.model_id, "status": status, "attempts": attempt + 1, "outcome": outcome, "seconds": seconds}
            self.on_call({**call, "tokens": (found or {}).get("total_tokens")})
        return status, content_type or "application/json", response, {}

    def _reserve(self, policy: ModelPolicy, data: bytes) -> tuple[tuple[int, float] | None, str | None]:
        """Reserve the worst case of one attempt; wait in the hold while it fits only after the attempts in flight settle.

        The hold is first in, first out: while earlier attempts wait, a new
        attempt queues behind them, and only the first attempt of the queue
        reserves. A large attempt (an agent call with a long context) thus
        never loses the room that it waits for to later, smaller attempts. A
        waiting attempt holds no reservation, so the attempts in flight
        always settle: no deadlock. The attempt is refused (the reason, and
        no reservation) when it does not fit with nothing in flight, after
        ``hold_wait_seconds``, after a provider refusal (``_BLOCKED``) and
        after the stop of the gateway (``_CLOSED``).
        """
        input_tokens = -(-len(data) // RESERVATION_BYTES_PER_TOKEN)
        tokens = input_tokens + policy.max_completion_tokens
        cost = policy.cost_estimate(input_tokens, policy.max_completion_tokens) or 0.0
        deadline = time.monotonic() + self.config.hold_wait_seconds
        place = object()
        with self._settled:
            self._waiting.append(place)
            try:
                while True:
                    if self.provider_error is not None:
                        return None, _BLOCKED
                    if self._closed:
                        return None, _CLOSED
                    over = self._over(tokens, cost)
                    if self._waiting[0] is place:
                        if over is None:
                            self._ledger.reserved_tokens += tokens
                            self._ledger.reserved_cost += cost
                            self._ledger.in_flight += 1
                            return (tokens, cost), None
                        if self._ledger.in_flight == 0:
                            return None, over
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        # An attempt that waited behind others gets the refusal of the ceiling that holds the queue.
                        return None, over or (SPEND_CEILING_TEXT if self.config.max_cost_usd is not None else TOKEN_CEILING_TEXT)
                    self._settled.wait(remaining)
            finally:
                self._waiting.remove(place)
                # The next attempt of the queue may reserve now.
                self._settled.notify_all()

    def _over(self, tokens: int, cost: float) -> str | None:
        """The ceiling that one more reservation of ``tokens`` and ``cost`` would pass, else None. The caller holds the lock."""
        ledger = self._ledger
        ceiling = self.config.max_total_tokens
        if ceiling is not None and ledger.committed_tokens + ledger.reserved_tokens + tokens > ceiling:
            return TOKEN_CEILING_TEXT
        cap = self.config.max_cost_usd
        if cap is not None and ledger.committed_cost + ledger.reserved_cost + cost >= cap:
            return SPEND_CEILING_TEXT
        return None

    def _settle(self, policy: ModelPolicy, reservation: tuple[int, float], found: dict[str, Any] | None, attempt: int) -> None:
        """Release a reservation and commit the usage of the attempt."""
        tokens, cost = reservation
        usage = self.usage[policy.model_id]
        with self._settled:
            self._ledger.reserved_tokens -= tokens
            self._ledger.reserved_cost -= cost
            self._ledger.in_flight -= 1
            self._settled.notify_all()
            usage.attempts += 1
            usage.retries += 1 if attempt else 0
            if not found:
                return
            self._ledger.committed_tokens += found["total_tokens"]
            usage.input_tokens += found["input_tokens"]
            usage.output_tokens += found["output_tokens"]
            usage.reasoning_tokens += found["reasoning_tokens"]
            usage.cache_read_tokens += found["cache_read_tokens"]
            usage.total_tokens += found["total_tokens"]
            if found["cost_usd"] is not None:
                usage.reported_cost_usd += found["cost_usd"]
                usage.attempts_with_reported_cost += 1
                self._ledger.committed_cost += found["cost_usd"]
            else:
                estimate = policy.cost_estimate(found["input_tokens"], found["output_tokens"], found["cache_read_tokens"])
                if estimate is None:
                    usage.attempts_without_cost += 1
                else:
                    usage.estimated_cost_usd += estimate
                    usage.attempts_with_estimated_cost += 1
                    self._ledger.committed_cost += estimate

    def _provider_refused(self, policy: ModelPolicy, status: int, response: bytes, forwarded: Mapping[str, Any]) -> None:
        """Keep the first provider refusal of the run: from now on no request goes upstream.

        Each attempt that waits in the hold wakes and gets the refusal at once.
        """
        with self._settled:
            if self.provider_error is not None:
                return
            self.provider_error = {"status": status, "model": policy.model_id, "at": time.time(), "message": None}
            self._settled.notify_all()
        message = provider_message(response, self.config.api_key, request_text(forwarded.get("messages")))
        with self._lock:
            self.provider_error["message"] = message

    def _refuse(self, policy: ModelPolicy, reason: str) -> tuple[int, str, bytes, dict[str, str]]:
        with self._lock:
            self.usage[policy.model_id].refusals += 1
            self.refusals.append({"model": policy.model_id, "reason": reason, "at": time.time()})
        code = "token_ceiling" if reason == TOKEN_CEILING_TEXT else "spend_ceiling"
        body = canonical_json(
            {"error": {"message": f"{reason}: the run is out of budget (quota exceeded)", "type": BUDGET_ERROR_TYPE, "code": code}}
        )
        return BUDGET_STATUS, "application/json", body, {"x-should-retry": "false"}

    def totals(self) -> dict[str, Any]:
        """The usage of the run: totals and each model."""
        with self._lock:
            models = {model: usage.record() for model, usage in self.usage.items()}
            refusals = len(self.refusals)
            committed_tokens = self._ledger.committed_tokens
            provider_error = dict(self.provider_error) if self.provider_error is not None else None
        keys = (
            "calls",
            "upstream_calls",
            "attempts",
            "retries",
            "refusals",
            "failures",
            "blocked",
            "length_stops",
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "cache_read_tokens",
            "total_tokens",
        )
        total: dict[str, Any] = {key: sum(item[key] for item in models.values()) for key in keys}
        failed_by: dict[str, int] = {}
        for item in models.values():
            for label, count in item["failed_by"].items():
                failed_by[label] = failed_by.get(label, 0) + count
        total["failed_by"] = dict(sorted(failed_by.items(), key=lambda pair: (-pair[1], pair[0])))
        reported = sum(item["cost_reported_usd"] for item in models.values())
        estimated = sum(item["cost_estimated_usd"] for item in models.values())
        without = sum(item["attempts_without_cost"] for item in models.values())
        with_reported = sum(item["attempts_with_reported_cost"] for item in models.values())
        with_estimate = sum(item["attempts_with_estimated_cost"] for item in models.values())
        if with_reported and not with_estimate and not without:
            source = "provider"
        elif with_estimate and not with_reported and not without:
            source = "estimate"
        elif with_reported or with_estimate:
            source = "mixed" if not without else "partial"
        else:
            source = "unknown" if without else "none"
        total.update(
            cost_usd=round(reported + estimated, 6) if (with_reported or with_estimate) else None,
            cost_source=source,
            budget_refusals=refusals,
            committed_tokens=committed_tokens,
            provider_error=provider_error,
        )
        return {"total": total, "models": models}


def _error(status: int, message: str) -> tuple[int, str, bytes, dict[str, str]]:
    return status, "application/json", canonical_json({"error": {"message": message, "type": "gateway_error"}}), {}


def _closed() -> tuple[int, str, bytes, dict[str, str]]:
    """The answer to an attempt that waited in the hold when the gateway stopped: final, no upstream call."""
    body = canonical_json({"error": {"message": "the run has ended: no more model calls", "type": "gateway_error"}})
    return 503, "application/json", body, {"x-should-retry": "false"}


def _provider_refused(status: int) -> tuple[int, str, bytes, dict[str, str]]:
    """The answer to each request after a provider refusal: the status of the refusal, final, no upstream call."""
    message = f"the provider refused an earlier call of the run (HTTP {status}): no more model calls (quota exceeded)"
    body = canonical_json({"error": {"message": message, "type": PROVIDER_REFUSED_TYPE, "code": "provider_refused"}})
    return status, "application/json", body, {"x-should-retry": "false"}
