"""Fakes of the test suite: a model that answers from the content of each request, and a Pi CLI.

No test calls a model provider and no test needs a key.

- ``FakeModel.respond`` is a gateway transport (or the body of an HTTP
  server): it records each body that the gateway forwards and answers it.
  The direct calls of the funnel get answers from their messages; an agent
  request (a request with tools) goes to a scripted agent when the test
  gives one.
- ``fake_pi_package`` writes a stand-in of the Pi CLI (a Python script with
  the package name and the pinned version). It records each invocation and
  writes a session file with a deterministic answer, as the real agent
  would after its tool calls.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MODEL = "z-ai/glm-5.3-flash"
_NUMBERED = re.compile(r"^\s*(\d+)│(.*)$", re.MULTILINE)


def _stable(text: str) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)


DANGEROUS = (
    ("os.system(", "CWE-78", "high"),
    ("subprocess.", "CWE-78", "medium"),
    ("child_process", "CWE-78", "high"),
    ("exec(", "CWE-78", "medium"),
    ("execute(", "CWE-89", "low"),
    ("eval(", "CWE-94", "high"),
    ("pickle.loads(", "CWE-502", "high"),
    ("yaml.load(", "CWE-502", "medium"),
    ("open(", "CWE-22", "medium"),
    ("redirect(", "CWE-601", "low"),
    ("innerHTML", "CWE-79", "medium"),
)


def kind_of(body: dict[str, Any]) -> str:
    """The kind of a request: rating, unit-check, verify (also the triage), agent or other."""
    messages = body.get("messages") or []
    system = messages[0].get("content") if messages and isinstance(messages[0].get("content"), str) else ""
    user = messages[-1].get("content") if messages and isinstance(messages[-1].get("content"), str) else ""
    if system.startswith("You rate units"):
        return "rating"
    if user.startswith("Audit this code for security vulnerabilities"):
        return "unit-check"
    if system.startswith("You examine one claim"):
        return "verify"
    if body.get("tools"):
        return "agent"
    return "other"


def answer_direct(body: dict[str, Any]) -> dict[str, Any]:
    """The answer of the fake model to one direct call of the funnel."""
    user = body["messages"][-1]["content"]
    kind = kind_of(body)
    if kind == "rating":
        ids = re.findall(r"^\[([^\]]+)\]", user, flags=re.MULTILINE)
        return {"ratings": [{"id": identifier, "score": 1 + _stable(identifier) % 5, "cwe": "CWE-78"} for identifier in ids]}
    if kind == "unit-check":
        findings = []
        for number, text in _NUMBERED.findall(user):
            for pattern, cwe, confidence in DANGEROUS:
                if pattern in text:
                    finding = {"file": "x", "line": int(number), "quote": text.strip(), "cwe": cwe, "confidence": confidence}
                    findings.append({**finding, "reason": "input reaches the operation"})
                    break
        if _stable(user) % 7 == 0:
            # Some answers come in a fenced block with prose around it.
            return {"__fenced__": {"findings": findings}}
        return {"findings": findings}
    if kind == "verify":
        if "isalnum" in user or "shlex.quote" in user:
            return {"conditions": [], "verdict": "safe", "keep_score": 0.1, "guard_quote": "if not name.isalnum():"}
        score = round(0.3 + (_stable(user) % 60) / 100, 2)
        return {
            "conditions": [{"condition": "input", "holds": True, "guard_quote": ""}],
            "verdict": "exploitable",
            "keep_score": score,
            "guard_quote": "",
        }
    return {"unknown": True}


def answer_text(answer: dict[str, Any]) -> str:
    if "__fenced__" in answer:
        return "Here is my answer:\n```json\n" + json.dumps(answer["__fenced__"]) + "\n```\nDone."
    return json.dumps(answer)


def usage_of(body_bytes: bytes, text: str) -> dict[str, int]:
    prompt = len(body_bytes) // 4 + 7
    completion = len(text) // 3 + 11
    return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}


def sse(model: str, text: str, usage: dict[str, Any]) -> bytes:
    half = len(text) // 2
    base = {"id": "gen-fake", "object": "chat.completion.chunk", "model": model, "provider": "fake"}
    chunks = [
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": text[:half]}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"reasoning": "a thought"}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"content": text[half:]}, "finish_reason": "stop"}]},
        {**base, "choices": [], "usage": usage},
    ]
    return (": keep-alive\n\n" + "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n").encode()


class FakeModel:
    """The upstream of a test: records each forwarded body and answers it."""

    def __init__(
        self,
        agent: Callable[[dict[str, Any]], tuple[str, bytes]] | None = None,
        statuses: list[int] | None = None,
        cost: float | None = None,
        delays: dict[str, float] | None = None,
    ) -> None:
        self.bodies: list[bytes] = []
        self.headers: list[dict[str, str]] = []
        self.lock = threading.Lock()
        self.agent = agent
        self.statuses = list(statuses or [])
        self.cost = cost
        # The answer time of each kind of request. A delay of the unit checks lets the search hits of
        # the free-roaming session reach the queue first, so that the run does not depend on timing.
        self.delays = dict(delays or {})

    def respond(self, body: bytes) -> tuple[int, str, bytes]:
        with self.lock:
            self.bodies.append(body)
            status = self.statuses.pop(0) if self.statuses else 200
        if status != 200:
            return status, "application/json", json.dumps({"error": {"message": "busy"}}).encode()
        payload = json.loads(body)
        if self.delays.get(kind_of(payload)):
            time.sleep(self.delays[kind_of(payload)])
        if kind_of(payload) == "agent" and self.agent is not None:
            content_type, data = self.agent(payload)
            return 200, content_type, data
        text = answer_text(answer_direct(payload))
        usage: dict[str, Any] = usage_of(body, text)
        if self.cost is not None:
            usage["cost"] = self.cost
        return 200, "text/event-stream", sse(payload["model"], text, usage)

    def transport(self, url: str, body: bytes, headers: Any, timeout: float) -> tuple[int, str, bytes]:
        """A gateway transport: the URL, the forwarded body, the headers and the timeout of one attempt."""
        with self.lock:
            self.headers.append(dict(headers))
        return self.respond(body)

    def requests(self) -> list[str]:
        with self.lock:
            return sorted(body.decode() for body in self.bodies)

    def kinds(self) -> list[str]:
        with self.lock:
            return [kind_of(json.loads(body)) for body in self.bodies]


FAKE_PI = r"""#!@PYTHON@
import json, os, sys, time, hashlib
from pathlib import Path
argv = sys.argv[1:]
prompt = argv[-1]
def option(name):
    return argv[argv.index(name) + 1] if name in argv[:-1] else None
resume = option("--session")
sessions = Path(option("--session-dir") or Path(resume).parent)
model = option("--model")
agent = os.environ.get("PI_CODING_AGENT_DIR", "")
log = os.environ.get("FAKE_PI_LOG")
config = {}
for name in ("settings.json", "models.json"):
    try:
        config[name] = json.loads((Path(agent) / name).read_text())
    except (OSError, ValueError):
        config[name] = None
worker = prompt.startswith("Examine one unit of this repository")
final = resume is not None
if log:
    with open(log, "a") as stream:
        stream.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "worker": worker, "final": final, "model": model,
                                 "env": {name: os.environ.get(name) for name in ("PI_CODING_AGENT_DIR", "PI_PACKAGE_DIR", "PI_OFFLINE")},
                                 "credential": bool(os.environ.get("OPENROUTER_API_KEY")),
                                 "extension_exists": [Path(argv[i + 1]).is_file() for i, part in enumerate(argv[:-1]) if part == "--extension"],
                                 "package_link": os.path.realpath(os.environ.get("PI_PACKAGE_DIR", "")),
                                 "tmpdir_set": bool(os.environ.get("TMPDIR")), "path": os.environ.get("PATH"),
                                 "config": config, "time": time.time()}) + "\n")
sessions.mkdir(parents=True, exist_ok=True)
mode = os.environ.get("FAKE_PI_MODE", "answer")
lines = []
if not final:
    lines.append({"type": "session", "version": 3, "id": "s", "cwd": os.getcwd()})
lines.append({"type": "message", "message": {"role": "user", "content": [{"type": "text", "text": "task"}]}})
searches = json.loads(os.environ.get("FAKE_PI_WORKER_SEARCH" if worker else "FAKE_PI_FREE_SEARCH") or "[]")
for index, item in enumerate(searches):
    call = f"call_{index}"
    lines.append({"type": "message", "message": {"role": "assistant", "stopReason": "toolUse", "usage": {"totalTokens": 150},
                  "provider": "openrouter", "model": model,
                  "content": [{"type": "toolCall", "id": call, "name": item["tool"], "arguments": item["arguments"]}]}})
    lines.append({"type": "message", "message": {"role": "toolResult", "toolCallId": call, "toolName": item["tool"],
                  "content": [{"type": "text", "text": item["output"]}], "isError": False}})
if worker:
    path = prompt.split("- File: ", 1)[1].split("\n", 1)[0]
    interest = [row[len("  - line "):] for row in prompt.split("\n") if row.startswith("  - line ")]
    items = []
    for row in interest:
        line = int(row.split(" ", 1)[0])
        quote = row.split(", which reads: ", 1)[1]
        digest = int(hashlib.sha256(f"{path}:{line}".encode()).hexdigest()[:8], 16)
        if digest % 5 == 0:
            continue
        cwe = row.split("weakness class to check: ", 1)[1].split(")", 1)[0]
        items.append({"title": f"Unsafe use at {path}:{line}", "locations": [{"path": path, "line_start": line, "line_end": line,
                      "note": "the operation"}, {"path": path, "line_start": max(1, line - 2), "line_end": line}],
                      "cwe": [cwe] if cwe.startswith("CWE-") else [], "severity": ["critical", "high", "medium", "low"][digest % 4],
                      "evidence": f"The code runs `{quote.strip()}` with request data.", "exploit_conditions": "The attacker controls the input."})
    answer = {"findings": items}
elif prompt.startswith("This session audits one slice") and os.environ.get("FAKE_PI_SLICE_ANSWER"):
    answer = json.loads(os.environ["FAKE_PI_SLICE_ANSWER"])
else:
    answer = json.loads(os.environ.get("FAKE_PI_FREE_ANSWER") or "{\"findings\": []}")
text = json.dumps(answer)
if mode == "no-answer" and not final or mode == "silent":
    # silent: no turn of any session gives an answer.
    text = "I looked at the code."
if mode == "blank-first" and not final and not list(sessions.parent.glob("blank-sessions/*.jsonl")):
    text = ""
reply = {"role": "assistant", "content": ([{"type": "text", "text": text}] if text else [{"type": "thinking", "thinking": "hm"}]),
         "provider": "openrouter", "model": model, "stopReason": "stop", "usage": {"totalTokens": int(os.environ.get("FAKE_PI_TOKENS", "2000"))}}
lines.append({"type": "message", "message": reply})
session = Path(resume) if final else sessions / "s1.jsonl"
with session.open("a") as stream:
    stream.write("".join(json.dumps(line) + "\n" for line in lines))
time.sleep(float(os.environ.get("FAKE_PI_SLEEP", "0.3")))
"""


def fake_pi_package(folder: Path) -> Path:
    """A fake Pi package (the name and the version of the pinned package); return its ``bin``, ``dist/bundle/cli.js``."""
    (folder / "dist" / "bundle").mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(json.dumps({"name": "@earendil-works/pi-coding-agent", "version": "1.5.0"}))
    cli = folder / "dist" / "bundle" / "cli.js"
    cli.write_text(FAKE_PI.replace("@PYTHON@", sys.executable))
    cli.chmod(cli.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    (folder / "README.md").write_text("fake\n")
    return cli


def fake_tools(folder: Path) -> dict[str, Path]:
    """Stand-ins of rg and fd for the links of the agent folder (the fake Pi does not run them)."""
    folder.mkdir(parents=True, exist_ok=True)
    tools = {}
    for name in ("rg", "fd"):
        path = folder / name
        path.write_text('#!/bin/sh\necho "' + name + ' 0.0.0"\n')
        path.chmod(0o755)
        tools[name] = path
    return tools


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class FakeServer:
    """An OpenAI-compatible endpoint on the loopback address that answers with a ``FakeModel``."""

    def __init__(self, fake: FakeModel) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.fake = fake
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                with server.fake.lock:
                    server.fake.headers.append({key.lower(): value for key, value in self.headers.items()})
                status, content_type, data = server.fake.respond(body)
                self.send_response(status)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def __enter__(self) -> FakeServer:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
