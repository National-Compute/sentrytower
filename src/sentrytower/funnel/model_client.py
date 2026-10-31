"""The direct model calls of the funnel: one chat completion through the model gateway of the run.

The orchestrator calls the model for the rating, the unit checks, the
triage and the verification. Each call goes to the local model gateway of
the run with the model of its role. The gateway sets the reasoning effort,
the completion ceiling and the provider route of the model policy, and it
counts each call against the one token ceiling of the run.

- Each call streams (``"stream": true`` with ``stream_options.include_usage``),
  as the agent does. The client reads the server-sent events: the content
  deltas, the finish reason and the usage chunk.
- HTTP 429 and 5xx, an error event in the stream, a transport error and a
  timeout get a new attempt after a pause (``backoff_seconds``, doubled each
  time, at most ``max_backoff_seconds``), up to ``max_attempts`` attempts and
  never after the deadline of the call. The gateway also retries transient
  provider errors itself.
- HTTP 402 with the error type of a budget refusal is the refusal of the
  gateway at the run ceiling. It is final: no new attempt.
- The usage chunk of each attempt gives its tokens; the tokens of a call are
  the sum over its attempts. An answer without a usage chunk gives an
  estimate, and the result says so.
- ``reservation`` gives the tokens that the gateway holds for one attempt
  of a call: the size of the forwarded request / 3 + the completion ceiling
  of the model policy. The orchestrator counts it in its global rule while
  the call runs.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..limits import BUDGET_ERROR_TYPE, BUDGET_STATUS, CREDENTIAL_VARIABLE, PLACEHOLDER_CREDENTIAL

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
# The reservation of the gateway for one attempt: the forwarded request
# bytes / 3 (the gateway adds the settings of the model policy to the
# request, less than GATEWAY_REWRITE_BYTES) + the completion ceiling of the
# model policy.
GATEWAY_BYTES_PER_TOKEN = 3
GATEWAY_REWRITE_BYTES = 1024
_FENCED_BLOCK = re.compile(r"```[A-Za-z]*[ \t]*\n(.*?)```", re.DOTALL)
# The statuses of a call result.
OK = "ok"
BUDGET_REFUSED = "budget-refused"
HTTP_ERROR = "http-error"
TRANSPORT_ERROR = "transport-error"
TIMEOUT = "timeout"
DEADLINE = "deadline"
STOPPED = "stopped"
# The error of an attempt whose stream ends with an error event.
STREAM_ERROR = "stream-error"


@dataclass
class CallResult:
    """What one call gave. ``text`` is the answer text; it never goes to a log."""

    status: str
    text: str = ""
    finish_reason: str | None = None
    http_status: int | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_s: float = 0.0
    attempts: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK

    def ledger(self) -> dict[str, Any]:
        """The ledger fields of the result: numbers and codes only."""
        return {
            "status": self.status,
            "error": self.error,
            "tokens": self.total_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_s": round(self.latency_s, 2),
            "attempts": self.attempts,
            "http_status": self.http_status,
            "finish_reason": self.finish_reason,
        }


@dataclass
class ClientCounters:
    calls: int = 0
    attempts: int = 0
    retries: int = 0
    statuses: dict[str, int] = field(default_factory=dict)
    http_429: int = 0
    http_5xx: int = 0
    budget_refusals: int = 0

    def record(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "attempts": self.attempts,
            "retries": self.retries,
            "statuses": dict(sorted(self.statuses.items())),
            "http_429": self.http_429,
            "http_5xx": self.http_5xx,
            "budget_refusals": self.budget_refusals,
        }


def estimate_tokens(text: str) -> int:
    """An upper estimate of the tokens of a text: about three bytes for each token."""
    return len(text.encode("utf-8", "replace")) // 3 + 1


def _message_text(message: Any) -> str:
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict) and isinstance(part.get("text"), str))
    return ""


class ModelClient:
    """One OpenAI-compatible chat completion for each call, with retries.

    ``models`` gives the model of each role of a direct call (rating,
    unit_check, triage, verify); ``model`` is the model of a role that the
    mapping does not name. ``completion_ceilings`` gives the completion
    ceiling of the model policy of each model (``max_completion_tokens`` for
    a model that the mapping does not name).
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        temperature: float | None,
        timeout_seconds: float = 780.0,
        max_attempts: int = 4,
        backoff_seconds: float = 5.0,
        max_backoff_seconds: float = 60.0,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        stop_event: threading.Event | None = None,
        max_completion_tokens: int = 0,
        models: Mapping[str, str] | None = None,
        completion_ceilings: Mapping[str, int] | None = None,
    ) -> None:
        if not base_url or not model:
            raise ValueError("the model client needs a base URL and a model")
        self.max_completion_tokens = max(0, int(max_completion_tokens))
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.models = dict(models or {})
        self.completion_ceilings = {name: max(0, int(value)) for name, value in (completion_ceilings or {}).items()}
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)
        self.backoff_seconds = backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.opener = opener or urllib.request.urlopen
        self.clock = clock
        self.stop_event = stop_event or threading.Event()
        self.sleep = sleep or (lambda seconds: self.stop_event.wait(seconds))
        self.counters = ClientCounters()
        self._lock = threading.Lock()
        self.credential = os.environ.get(CREDENTIAL_VARIABLE) or PLACEHOLDER_CREDENTIAL

    def model_of(self, role: str | None) -> str:
        """The model of a role (the default model for an unknown role)."""
        return self.models.get(role or "", self.model)

    def completion_ceiling(self, model: str | None = None) -> int:
        """The completion ceiling of the policy of ``model`` (default: the default model)."""
        return self.completion_ceilings.get(model or self.model, self.max_completion_tokens)

    def payload(self, messages: list[dict[str, Any]], *, role: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model_of(role),
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        return payload

    def body(self, messages: list[dict[str, Any]], *, role: str | None = None) -> bytes:
        return json.dumps(self.payload(messages, role=role)).encode("utf-8")

    def reservation(self, messages: list[dict[str, Any]], *, role: str | None = None) -> int:
        """The tokens that the gateway reserves for one attempt of this call.

        The gateway measures the forwarded request in its canonical JSON form
        (sorted keys, no spaces, UTF-8) with the settings of the model policy.
        """
        payload = self.payload(messages, role=role)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        size = len(canonical.encode("utf-8")) + GATEWAY_REWRITE_BYTES
        return -(-size // GATEWAY_BYTES_PER_TOKEN) + self.completion_ceiling(payload["model"])

    def _count(self, **values: int) -> None:
        with self._lock:
            for name, value in values.items():
                setattr(self.counters, name, getattr(self.counters, name) + value)

    def _status(self, status: str) -> None:
        with self._lock:
            self.counters.statuses[status] = self.counters.statuses.get(status, 0) + 1

    def complete(self, messages: list[dict[str, Any]], *, deadline: float | None = None, role: str | None = None) -> CallResult:
        """One call; ``deadline`` is a ``clock`` value after which no attempt starts."""
        started = self.clock()
        body = self.body(messages, role=role)
        result = CallResult(status=TRANSPORT_ERROR)
        self._count(calls=1)
        spent = 0
        for attempt in range(1, self.max_attempts + 1):
            if self.stop_event.is_set():
                result = CallResult(status=STOPPED, attempts=attempt - 1, error="stopped")
                break
            now = self.clock()
            if deadline is not None and now >= deadline:
                result = CallResult(status=DEADLINE, attempts=attempt - 1, error="deadline")
                break
            timeout = self.timeout_seconds if deadline is None else max(5.0, min(self.timeout_seconds, deadline - now))
            self._count(attempts=1, retries=1 if attempt > 1 else 0)
            result = self._attempt(body, timeout)
            result.attempts = attempt
            if result.status != OK:
                # A failed attempt keeps the tokens that its usage chunk reports.
                spent += result.total_tokens
            if result.http_status == 429:
                self._count(http_429=1)
            elif result.http_status is not None and result.http_status >= 500:
                self._count(http_5xx=1)
            retry = result.status in (TRANSPORT_ERROR, TIMEOUT) or (
                result.status == HTTP_ERROR and (result.http_status in RETRY_STATUSES or result.error == STREAM_ERROR)
            )
            if not retry or attempt == self.max_attempts:
                break
            pause = min(self.max_backoff_seconds, self.backoff_seconds * (2 ** (attempt - 1)))
            if deadline is not None and self.clock() + pause >= deadline:
                break
            self.sleep(pause)
        if result.status == BUDGET_REFUSED:
            self._count(budget_refusals=1)
        if result.status == OK:
            result.total_tokens += spent
        else:
            result.total_tokens = spent
        result.latency_s = self.clock() - started
        self._status(result.status)
        return result

    def _attempt(self, body: bytes, timeout: float) -> CallResult:
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "accept": "text/event-stream",
                "authorization": f"Bearer {self.credential}",
            },
        )
        attempt_started = self.clock()
        try:
            response = self.opener(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            raw = b""
            try:
                raw = error.read()
            except OSError:
                pass
            return self._refusal_or_error(error.code, raw)
        except (TimeoutError, socket.timeout):
            return CallResult(status=TIMEOUT, error="timeout")
        except (urllib.error.URLError, ConnectionError, OSError) as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, (TimeoutError, socket.timeout)):
                return CallResult(status=TIMEOUT, error="timeout")
            return CallResult(status=TRANSPORT_ERROR, error=type(reason).__name__)
        try:
            with response:
                status = getattr(response, "status", 200)
                headers = getattr(response, "headers", None)
                content_type = str(headers.get("content-type", "") if headers is not None else "").lower()
                if status != 200:
                    return self._refusal_or_error(status, response.read())
                if "text/event-stream" in content_type:
                    return self._read_stream(response, body, attempt_started, timeout)
                raw = response.read()
        except (TimeoutError, socket.timeout):
            return CallResult(status=TIMEOUT, error="timeout")
        except (ConnectionError, OSError, http.client.HTTPException) as error:
            return CallResult(status=TRANSPORT_ERROR, error=type(error).__name__)
        return self._read_json(raw, body, status)

    def _read_stream(self, response: Any, body: bytes, attempt_started: float, timeout: float) -> CallResult:
        """The server-sent events of one attempt: content deltas, finish reason, usage, errors."""
        parts: list[str] = []
        finish: str | None = None
        usage: dict[str, Any] | None = None
        for raw in response:
            if self.clock() - attempt_started > timeout:
                return self._partial(TIMEOUT, "timeout", body, usage)
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            if isinstance(chunk.get("usage"), dict):
                usage = chunk["usage"]
            if chunk.get("error"):
                return self._partial(HTTP_ERROR, STREAM_ERROR, body, usage)
            for choice in chunk.get("choices") or []:
                if not isinstance(choice, dict):
                    continue
                delta = found if isinstance(found := choice.get("delta"), dict) else {}
                text = delta.get("content")
                if isinstance(text, str):
                    parts.append(text)
                if isinstance(choice.get("finish_reason"), str):
                    finish = choice["finish_reason"]
        if finish == "error":
            return self._partial(HTTP_ERROR, STREAM_ERROR, body, usage)
        text = "".join(parts)
        result = CallResult(status=OK, text=text, finish_reason=finish, http_status=200)
        self._usage(result, usage, body)
        return result

    def _partial(self, status: str, error: str, body: bytes, usage: dict[str, Any] | None) -> CallResult:
        """A failed attempt after a part of the stream: the tokens of its usage chunk, if any."""
        result = CallResult(status=status, error=error, http_status=200 if status == HTTP_ERROR else None)
        if usage is not None:
            self._usage(result, usage, body)
        return result

    @staticmethod
    def _usage(result: CallResult, usage: dict[str, Any] | None, body: bytes) -> None:
        usage = usage or {}
        complete = "total_tokens" in usage
        input_tokens = int(usage.get("prompt_tokens") or 0)
        output_tokens = int(usage.get("completion_tokens") or 0)
        total = int(usage.get("total_tokens") or 0) if complete else 0
        if not complete:
            # No usage record: count the request and the answer as an
            # estimate. The gateway has the exact count.
            input_tokens = input_tokens or estimate_tokens(body.decode("utf-8", "replace"))
            output_tokens = output_tokens or estimate_tokens(result.text)
            total = input_tokens + output_tokens
        result.input_tokens = input_tokens
        result.output_tokens = output_tokens
        result.total_tokens = total

    def _read_json(self, raw: bytes, body: bytes, status: int) -> CallResult:
        """An answer without a stream (an endpoint that does not stream)."""
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return CallResult(status=HTTP_ERROR, http_status=status, error="response-not-json")
        if not isinstance(payload, dict):
            return CallResult(status=HTTP_ERROR, http_status=status, error="response-not-object")
        if payload.get("error"):
            return CallResult(status=HTTP_ERROR, http_status=status, error="provider-error")
        choices = payload.get("choices") if isinstance(payload.get("choices"), list) else []
        first = choices[0] if choices and isinstance(choices[0], dict) else {}
        result = CallResult(
            status=OK,
            text=_message_text(first.get("message")),
            finish_reason=first.get("finish_reason") if isinstance(first.get("finish_reason"), str) else None,
            http_status=status,
        )
        self._usage(result, payload.get("usage") if isinstance(payload.get("usage"), dict) else None, body)
        return result

    @staticmethod
    def _refusal_or_error(status: int, raw: bytes) -> CallResult:
        try:
            payload = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        error = payload.get("error") if isinstance(payload, dict) else None
        if status == BUDGET_STATUS and isinstance(error, dict) and error.get("type") == BUDGET_ERROR_TYPE:
            return CallResult(status=BUDGET_REFUSED, http_status=status, error=str(error.get("code") or "budget"))
        return CallResult(status=HTTP_ERROR, http_status=status, error=f"http-{status}")


def json_candidates(text: str) -> list[Any]:
    """Each JSON value in the text: the whole text, each fenced block, and each embedded object.

    The last candidate comes first: an earlier object can be a draft or an
    echo of the format.
    """
    found: list[Any] = []
    stripped = text.strip()
    try:
        found.append(json.loads(stripped))
    except json.JSONDecodeError:
        pass
    for block in reversed(_FENCED_BLOCK.findall(text)):
        try:
            found.append(json.loads(block.strip()))
        except json.JSONDecodeError:
            continue
    decoder = json.JSONDecoder()
    embedded: list[Any] = []
    index = 0
    while True:
        index = text.find("{", index)
        if index < 0:
            break
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        embedded.append(value)
        index = end
    found.extend(reversed(embedded))
    return found


def extract_object(text: str, required_key: str) -> dict[str, Any]:
    """The JSON object in the answer that has ``required_key``; ValueError when there is none."""
    for value in json_candidates(text):
        if isinstance(value, dict) and required_key in value:
            return value
    raise ValueError(f"no JSON object with {required_key!r}")
