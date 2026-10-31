"""Model lists: the model list of an endpoint, the models that SentryTower knows, and model servers on this computer.

- ``fetch_models``: ``GET <base_url>/models`` of an OpenAI-compatible
  endpoint. OpenRouter gives the name, the context window, the prices and
  the supported parameters of each model; other endpoints give the IDs.
- ``local_servers``: Ollama, LM Studio, vLLM and llama.cpp on their usual
  loopback ports, each with its models.
- ``resolve``: a short name (``deepseek``, ``glm``) to a model ID of a list.

A list is cached for one day in ``~/.cache/sentrytower/models``. Nothing
here sends the key except ``check_key``, and only to the configured
endpoint.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..policies import BUILTIN_POLICIES, DEFAULT_MODEL

OPENROUTER = "https://openrouter.ai/api/v1"
CACHE_SECONDS = 24 * 3600
LOCAL_SERVERS = (
    ("Ollama", 11434),
    ("LM Studio", 1234),
    ("vLLM", 8000),
    ("llama.cpp", 8080),
)
USER_AGENT = "SentryTower setup (+https://github.com/National-Compute/sentrytower)"


@dataclass
class Model:
    id: str
    name: str = ""
    context: int | None = None
    max_output: int | None = None
    input_per_million: float | None = None
    output_per_million: float | None = None
    cache_read_per_million: float | None = None
    tools: bool | None = None
    reasoning: bool | None = None
    # The default model of SentryTower: the setup lists it first.
    default: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def price_text(self) -> str:
        if self.input_per_million is None or self.output_per_million is None:
            return "price n/a"
        if self.input_per_million == 0 and self.output_per_million == 0:
            return "free"
        return f"${self.input_per_million:.2f} / ${self.output_per_million:.2f} per M"

    @property
    def context_text(self) -> str:
        if not self.context:
            return ""
        if self.context >= 1_000_000:
            return f"{self.context / 1_000_000:.1f}M ctx".replace(".0M", "M")
        return f"{self.context // 1000}k ctx" if self.context >= 1000 else f"{self.context} ctx"

    def policy_table(self) -> dict[str, Any]:
        """A request policy for the configuration file, from what the list says about the model."""
        table: dict[str, Any] = {"reasoning_effort": "medium" if self.reasoning else "none"}
        if self.context:
            table["context_window"] = self.context
        if self.max_output:
            table["max_completion_tokens"] = min(self.max_output, 65_536)
        if self.input_per_million is not None:
            table["input_cost_per_million"] = round(self.input_per_million, 6)
        if self.output_per_million is not None:
            table["output_cost_per_million"] = round(self.output_per_million, 6)
        if self.cache_read_per_million is not None:
            table["cache_read_cost_per_million"] = round(self.cache_read_per_million, 6)
        return table


def _per_million(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number * 1_000_000 if number >= 0 else None


def parse_models(document: Any) -> list[Model]:
    """The models of an OpenAI-compatible ``/models`` answer (OpenRouter fields when present)."""
    items = document.get("data") if isinstance(document, dict) else document
    if not isinstance(items, list):
        items = document.get("models") if isinstance(document, dict) else None
    models: list[Model] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        # An OpenAI-compatible list has "id"; a list of Ollama's own API has "model" and "name".
        identifier = item.get("id") if "id" in item else (item.get("model") or item.get("name"))
        if not isinstance(identifier, str) or not identifier.strip():
            continue
        raw_pricing, raw_top = item.get("pricing"), item.get("top_provider")
        pricing: dict[str, Any] = raw_pricing if isinstance(raw_pricing, dict) else {}
        top: dict[str, Any] = raw_top if isinstance(raw_top, dict) else {}
        parameters = item.get("supported_parameters") if isinstance(item.get("supported_parameters"), list) else None
        context = item.get("context_length") or top.get("context_length")
        models.append(
            Model(
                id=identifier.strip(),
                name=str(item.get("name") or ""),
                context=int(context) if isinstance(context, (int, float)) and context > 0 else None,
                max_output=int(top["max_completion_tokens"]) if isinstance(top.get("max_completion_tokens"), (int, float)) else None,
                input_per_million=_per_million(pricing.get("prompt")),
                output_per_million=_per_million(pricing.get("completion")),
                cache_read_per_million=_per_million(pricing.get("input_cache_read")),
                tools=("tools" in parameters) if parameters is not None else None,
                reasoning=("reasoning" in parameters) if parameters is not None else None,
                default=identifier.strip() == DEFAULT_MODEL,
            )
        )
    return models


def known_models() -> list[Model]:
    """The models with a built-in request policy (the default model first)."""
    out = []
    for model_id, policy in BUILTIN_POLICIES.items():
        model = Model(
            id=model_id,
            name=policy.name,
            context=policy.context_window,
            max_output=policy.max_completion_tokens,
            input_per_million=policy.input_cost_per_million,
            output_per_million=policy.output_cost_per_million,
            cache_read_per_million=policy.cache_read_cost_per_million,
            tools=True,
            reasoning=True,
            default=model_id == DEFAULT_MODEL,
        )
        out.append(model)
    return out


def cache_folder(environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    base = env.get("XDG_CACHE_HOME") or str(Path(env.get("HOME") or Path.home()) / ".cache")
    return Path(base) / "sentrytower" / "models"


def _cache_file(base_url: str, environ: dict[str, str] | None = None) -> Path:
    return cache_folder(environ) / (hashlib.sha256(base_url.rstrip("/").encode()).hexdigest()[:16] + ".json")


def _get_json(url: str, *, key: str | None = None, timeout: float = 8.0) -> Any:
    headers = {"accept": "application/json", "user-agent": USER_AGENT}
    if key:
        headers["authorization"] = f"Bearer {key}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(16 * 1024 * 1024).decode("utf-8"))


def fetch_models(base_url: str, *, key: str | None = None, use_cache: bool = True, environ: dict[str, str] | None = None) -> list[Model]:
    """The models of an endpoint (cached for a day). Raises OSError or ValueError when the list cannot be read."""
    cache = _cache_file(base_url, environ)
    if use_cache:
        try:
            if time.time() - cache.stat().st_mtime < CACHE_SECONDS:
                return [Model(**item) for item in json.loads(cache.read_text())]
        except (OSError, ValueError, TypeError):
            pass
    try:
        document = _get_json(base_url.rstrip("/") + "/models", key=key)
    except urllib.error.HTTPError as error:
        raise OSError(f"HTTP {error.code} from {base_url}/models") from None
    except (urllib.error.URLError, TimeoutError) as error:
        raise OSError(f"{base_url} cannot be reached ({type(error).__name__})") from None
    models = parse_models(document)
    if not models:
        raise ValueError(f"{base_url}/models lists no model")
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps([asdict(model) for model in models]))
    except OSError:
        pass
    return models


def check_key(base_url: str, key: str) -> tuple[bool, str]:
    """Whether the endpoint accepts the key: OpenRouter's key endpoint, else the model list with the key."""
    try:
        if base_url.rstrip("/") == OPENROUTER:
            document = _get_json(OPENROUTER + "/key", key=key)
            data = document.get("data") if isinstance(document, dict) else None
            if isinstance(data, dict):
                limit = data.get("limit_remaining")
                return True, ("credit left: $" + f"{float(limit):.2f}") if isinstance(limit, (int, float)) else "the key is valid"
            return True, "the key is valid"
        _get_json(base_url.rstrip("/") + "/models", key=key)
        return True, "the endpoint accepted the key"
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            return False, f"the endpoint refused the key (HTTP {error.code})"
        return False, f"HTTP {error.code} from the endpoint"
    except (OSError, ValueError) as error:
        return False, f"the endpoint cannot be reached ({type(error).__name__})"


@dataclass
class LocalServer:
    name: str
    base_url: str
    models: list[str]


def local_servers(timeout: float = 0.35) -> list[LocalServer]:
    """The model servers on this computer that answer on their usual port, with their models."""
    found = []
    for name, port in LOCAL_SERVERS:
        base = f"http://127.0.0.1:{port}/v1"
        try:
            document = _get_json(base + "/models", timeout=timeout)
        except (OSError, ValueError):
            continue
        ids = [model.id for model in parse_models(document)]
        if ids:
            found.append(LocalServer(name, base, ids))
    return found


def resolve(query: str, models: list[Model]) -> list[Model]:
    """The models that a short name matches, the best first: the exact ID, then the end of the ID, then a part."""
    text = query.strip().lower()
    exact = [model for model in models if model.id.lower() == text]
    if exact:
        return exact
    tail = [model for model in models if model.id.lower().split("/")[-1] == text]
    if tail:
        return tail
    starts = [model for model in models if model.id.lower().split("/")[-1].startswith(text)]
    parts = [model for model in models if text in model.id.lower() and model not in starts]
    ordered = sorted(starts, key=lambda model: (not model.default, len(model.id))) + sorted(parts, key=lambda model: len(model.id))
    return ordered
