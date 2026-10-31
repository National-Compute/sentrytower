"""Readers of an agent session: the session file, the final answer and its findings object.

The agent (the Pi coding agent in print mode) writes one JSON line for each
entry of a session to ``<session folder>/*.jsonl``: a header (type
``session``, with the working folder ``cwd``) and one entry for each message
(type ``message``). An assistant message records its content blocks (text,
reasoning and tool calls), its stop reason and its token usage.

The agent runner, the funnel and the reader of the final answer use these
functions, so each one reads a session in the same way.

Standard library only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..funnel.slices import split_lines

_FENCED_BLOCK = re.compile(r"```[A-Za-z]*[ \t]*\n(.*?)```", re.DOTALL)
# A reply with one of these stop reasons did not end with an error. The
# agent gives toolUse when the provider ends the reply for a tool call; a
# reply with that stop reason and no tool call ends the turn without a call.
BLANK_STOP_REASONS = frozenset({"stop", "length", "toolUse"})
# The folder next to the session folder that holds the sessions that a
# restart after a blank first reply replaced.
BLANK_SESSIONS = "blank-sessions"


def find_session(session_root: Path) -> Path:
    sessions = sorted(session_root.glob("**/*.jsonl")) if session_root.is_dir() else []
    if len(sessions) != 1:
        raise FileNotFoundError(f"expected one agent session file under {session_root}, found {len(sessions)}")
    return sessions[0]


def blank_session_file(attempt: int) -> Path:
    """The blank session that restart ``attempt`` (1, 2, ...) replaced, relative to the parent of the session folder."""
    return Path(BLANK_SESSIONS) / f"attempt-{attempt}.jsonl"


def read_session(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Return the header, the messages in order, and whether a line was cut.

    A run that a limit stops can leave a partial last line; it is skipped and
    reported. The file is UTF-8 and splits on "\\n" only (``split_lines``): a
    JSON string can hold U+2028, U+2029 or U+0085, and ``str.splitlines``
    would split the line there and void the whole answer. A character that a
    stop cut becomes U+FFFD in the last line.
    """
    lines = [line for line in split_lines(path.read_bytes().decode("utf-8", "replace")) if line.strip()]
    header: dict[str, Any] = {}
    messages: list[dict[str, Any]] = []
    truncated = False
    for number, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            if number == len(lines) - 1:
                truncated = True
                continue
            raise
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "session" and not header:
            header = entry
        elif entry.get("type") == "message" and isinstance(entry.get("message"), dict):
            messages.append(entry["message"])
    return header, messages, truncated


def final_text(message: dict[str, Any]) -> str:
    return "\n".join(
        block["text"]
        for block in message.get("content") or []
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
    )


def extract_findings_document(text: str) -> tuple[dict[str, Any], str]:
    """Find the findings object in the final answer.

    The contract asks for the bare object. A fenced block or an object inside
    prose is accepted as well, and the method is recorded. When the text
    holds several candidates, the last one is the answer: an earlier object
    can be a draft or an echo of the schema.
    """
    candidates: list[tuple[str, Any]] = []
    try:
        candidates.append(("whole", json.loads(text.strip())))
    except json.JSONDecodeError:
        pass
    for block in reversed(_FENCED_BLOCK.findall(text)):
        try:
            candidates.append(("fenced", json.loads(block.strip())))
        except json.JSONDecodeError:
            continue
    decoder = json.JSONDecoder()
    embedded: list[dict[str, Any]] = []
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        # A schema echo has "findings" too, but its value is not a list.
        if isinstance(value, dict) and isinstance(value.get("findings"), list):
            embedded.append(value)
    candidates.extend(("embedded", value) for value in reversed(embedded))
    for method, value in candidates:
        if isinstance(value, dict) and isinstance(value.get("findings"), list):
            return value, method
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return {"findings": value}, f"{method}-list"
    raise ValueError("the final answer of the agent has no findings JSON object")


def has_tool_call(message: dict[str, Any]) -> bool:
    content = message.get("content")
    return isinstance(content, list) and any(isinstance(block, dict) and block.get("type") == "toolCall" for block in content)


def blank_reply(message: dict[str, Any]) -> bool:
    """Whether an assistant reply without an error has no text and no tool call.

    A reply with only reasoning or only white space is blank, also when its
    stop reason is toolUse. A reply that ended with an error or an abort, a
    reply with a tool call, and a reply with any other text, for example a
    short answer or a findings JSON object, is not.
    """
    return message.get("stopReason") in BLANK_STOP_REASONS and not has_tool_call(message) and not final_text(message).strip()


def read_answer(session_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    """The findings document of the last reply of the session, or None and the reason."""
    try:
        session = find_session(session_dir)
        _, messages, _ = read_session(session)
    except (OSError, ValueError) as error:
        return None, f"session: {type(error).__name__}"
    assistant = [message for message in messages if message.get("role") == "assistant"]
    if not assistant:
        return None, "no-reply"
    final = assistant[-1]
    if final.get("stopReason") not in ("stop", "length"):
        return None, f"ended-{final.get('stopReason')}"
    try:
        document, _ = extract_findings_document(final_text(final))
    except ValueError:
        return None, "no-findings-object"
    return document, None
