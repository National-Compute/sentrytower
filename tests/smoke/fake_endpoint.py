"""A fake OpenAI-compatible endpoint for smoke tests of the container image and of the GitHub Action.

    python tests/smoke/fake_endpoint.py --port 8099

It answers each chat completion as a stream. An agent request (a request
with tools) gets a final answer with one finding in the first file of the
system prompt's working folder; any other request gets an empty findings
object. It never calls a model and needs no key.

A request for a built-in model of SentryTower must carry the data policy of
the built-in routes, ``provider.data_collection`` "deny"; else the endpoint
answers HTTP 400 with a plain message, so that a smoke run catches a route
that lost the policy. The script uses the standard library only (no import
of SentryTower), so ``BUILTIN_MODELS`` repeats the built-in models; a unit
test keeps the two lists equal.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

BUILTIN_MODELS = ("deepseek/deepseek-v4.1-flash-1017", "z-ai/glm-5.3-flash")
ANSWER = {
    "findings": [
        {
            "title": "Smoke-test finding",
            "locations": [{"path": "README.md", "line_start": 1, "line_end": 1}],
            "cwe": ["CWE-20"],
            "severity": "low",
            "evidence": "The fake endpoint gives this finding for each agent session.",
            "exploit_conditions": "None: this is a smoke test.",
        }
    ]
}


def stream(model: str, text: str) -> bytes:
    base = {"id": "gen-smoke", "object": "chat.completion.chunk", "model": model}
    chunks = [
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {**base, "choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120, "cost": 0.0}},
    ]
    return ("".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n").encode()


def data_policy_problem(body: Any) -> str | None:
    """Why a request breaks the data policy of the built-in routes, or None."""
    if not isinstance(body, dict) or body.get("model") not in BUILTIN_MODELS:
        return None
    provider = body.get("provider")
    if not isinstance(provider, dict) or provider.get("data_collection") != "deny":
        return f'a request for the built-in model {body["model"]} must set provider.data_collection to "deny"'
    return None


class Handler(BaseHTTPRequestHandler):
    calls = 0
    refusals = 0

    def log_message(self, *_: object) -> None:
        pass

    def _send(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        Handler.calls += 1
        problem = data_policy_problem(body)
        if problem is not None:
            Handler.refusals += 1
            self._send(400, "application/json", json.dumps({"error": {"code": 400, "message": problem}}).encode())
            print(f"call {Handler.calls}: refused: {problem}", file=sys.stderr, flush=True)
            return
        text = json.dumps(ANSWER if body.get("tools") else {"findings": []})
        self._send(200, "text/event-stream", stream(str(body.get("model") or "fake"), text))
        print(f"call {Handler.calls}: {body.get('model')} tools={bool(body.get('tools'))}", file=sys.stderr, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"fake endpoint on http://{args.host}:{args.port}/v1", file=sys.stderr, flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
