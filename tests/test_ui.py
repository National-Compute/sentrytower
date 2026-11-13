"""The interactive terminal: colours and widths, keys, the screen, the prompts, the guided setup, the live view and the results.

The prompts read scripted keys and write to a string; no test needs a
terminal, a network or a keychain. The setup writes its settings file into
the private folders of the test (``_private_user_folders`` in conftest).
"""

from __future__ import annotations

import io
import json
import os
import stat
import tomllib
from pathlib import Path
from typing import Any

import pytest

from sentrytower.config import FAST_ROLES, ROLES, load_config
from sentrytower.findings import OutputFinding, OutputLocation
from sentrytower.policies import DEFAULT_MODEL
from sentrytower.ui import catalog
from sentrytower.ui.catalog import LocalServer, Model
from sentrytower.ui.keys import KeyReader, ScriptedKeys
from sentrytower.ui.live import LiveAudit
from sentrytower.ui.mascot import BADGE, HERO, art
from sentrytower.ui.results import from_document, last_run, remember, summary_lines
from sentrytower.ui.screen import Recorder, Screen
from sentrytower.ui.setup import Services, Setup, estimate
from sentrytower.ui.term import (
    COLOR16,
    COLOR256,
    NOCOLOR,
    TRUECOLOR,
    Caps,
    Style,
    cells,
    clip,
    color_mode,
    detect,
    line_cells,
    to_256,
    to_ansi,
    to_plain,
)
from sentrytower.ui.theme import AGENT_COLORS, theme_for
from sentrytower.ui.widgets import CancelledError, Choice, Prompter, fuzzy_score

KEY = "sk-or-v1-" + "0123456789abcdef" * 4
WRONG_KEY = "sk-or-v1-" + "f" * 64
CAPS = Caps(color=TRUECOLOR, unicode=True, interactive=True, width=110, height=40)
MODELS = [
    Model(
        "qwen/qwen3-coder",
        "Qwen: Qwen3 Coder",
        context=262_144,
        max_output=65_536,
        input_per_million=0.2,
        output_per_million=0.8,
        tools=True,
        reasoning=False,
    ),
    Model(
        DEFAULT_MODEL,
        "DeepSeek: DeepSeek V4.1 Flash 1017",
        context=1_048_576,
        input_per_million=0.15,
        output_per_million=0.6,
        tools=True,
        reasoning=True,
        default=True,
    ),
    Model("vendor/no-tools", "No tools", context=8_192, input_per_million=0.0, output_per_million=0.0, tools=False, reasoning=False),
]


def make_prompter(keys: list[str | float], *, caps: Caps = CAPS, record: Path | None = None) -> tuple[Prompter, io.StringIO]:
    stream = io.StringIO()
    screen = Screen(caps, stream=stream, recorder=Recorder(record, caps) if record else None)
    return Prompter(screen, ScriptedKeys(keys), theme_for("sand", "dark"), caps), stream


@pytest.mark.parametrize(
    ("environ", "mode"),
    [
        ({"NO_COLOR": "1", "COLORTERM": "truecolor"}, NOCOLOR),
        ({"TERM": "dumb"}, NOCOLOR),
        ({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, TRUECOLOR),
        ({"TERM": "xterm-256color", "TERM_PROGRAM": "iTerm.app"}, TRUECOLOR),
        ({"TERM": "xterm-256color", "TERM_PROGRAM": "Apple_Terminal"}, COLOR256),
        ({"TERM": "xterm"}, COLOR16),
        ({}, NOCOLOR),
    ],
)
def test_the_colour_mode_follows_the_terminal(environ: dict[str, str], mode: str) -> None:
    assert color_mode(environ) == mode


def test_a_terminal_is_interactive_unless_ci_plain_or_dumb() -> None:
    master, slave = os.openpty()
    try:
        with open(slave, "w", encoding="utf-8", closefd=False) as tty:
            base = {"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}
            caps = detect(tty, tty, base)
            assert caps.interactive and caps.color == COLOR256 and caps.unicode
            assert not detect(tty, tty, {**base, "CI": "true"}).interactive
            assert not detect(tty, tty, {**base, "GITHUB_ACTIONS": "true"}).interactive
            assert not detect(tty, tty, base, plain=True).interactive
            assert not detect(tty, tty, {**base, "TERM": "dumb"}).interactive
            assert not detect(io.StringIO(), io.StringIO(), base).interactive
            assert detect(io.StringIO(), io.StringIO(), base).color == NOCOLOR
    finally:
        os.close(master)
        os.close(slave)


def test_widths_count_terminal_cells_and_a_cut_line_ends_with_an_ellipsis() -> None:
    assert cells("abc") == 3 and cells("日本") == 4 and cells("é") == 1 and cells("a‍b") == 2
    line = [("hello ", Style()), ("world", Style(bold=True))]
    assert to_plain(clip(line, 8)) == "hello w…" and line_cells(clip(line, 8)) == 8
    assert clip(line, 20) == line


def test_colours_degrade_to_256_and_16_colours_and_to_none() -> None:
    sand = AGENT_COLORS["sand"][2]
    assert to_ansi([("x", Style(fg=sand))], TRUECOLOR) == "\x1b[38;2;224;181;120mx\x1b[0m"
    assert to_ansi([("x", Style(fg=sand))], COLOR256) == f"\x1b[38;5;{to_256(sand)}mx\x1b[0m"
    assert to_ansi([("x", Style(fg=sand))], COLOR16).startswith("\x1b[")
    assert to_256((0, 0, 0)) == 16 and to_256((255, 255, 255)) == 231 and to_256((128, 128, 128)) == 244
    assert to_ansi([("x", Style(fg=sand, bold=True))], NOCOLOR) == "x"


def test_the_agent_art_needs_256_colours_and_has_each_colour_in_each_size() -> None:
    for color in AGENT_COLORS:
        for width in (HERO, BADGE):
            lines = art(color, width, TRUECOLOR)
            assert lines and max(line_cells(line) for line in lines) <= width
            assert any("▀" in text or "▄" in text for line in lines for text, _ in line)
    assert art("sand", BADGE, COLOR16) == [] and art("sand", BADGE, NOCOLOR) == []
    assert art("no-such-colour", BADGE, TRUECOLOR) == art("sand", BADGE, TRUECOLOR)


def test_the_key_reader_reads_arrows_enter_text_and_escape() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, "\x1b[A\x1b[Bx\ré\x7f\x1b[Z\x1bOB".encode())
        reader = KeyReader(read_fd)
        assert [reader.read(0.5) for _ in range(8)] == ["up", "down", "x", "enter", "é", "backspace", "shift-tab", "down"]
        os.write(write_fd, b"\x1b")
        assert reader.read(0.5) == "esc"
        assert reader.read(0.05) is None
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_the_screen_redraws_the_live_region_in_place_and_records_each_change(tmp_path: Path) -> None:
    caps = Caps(color=TRUECOLOR, interactive=True, width=40, height=10)
    stream = io.StringIO()
    record = tmp_path / "screen.jsonl"
    screen = Screen(caps, stream=stream, recorder=Recorder(record, caps))
    screen.draw([[("one", Style())], [("two", Style(fg=(1, 2, 3)))]])
    screen.draw([[("three " * 20, Style())]])
    screen.print([[("kept", Style(bold=True))]])
    screen.clear()
    screen.close()
    output = stream.getvalue()
    assert output.startswith("\x1b[?25l") and output.endswith("\x1b[?25h")
    assert "\x1b[1A" in output and "\x1b[38;2;1;2;3mtwo" in output
    events = [json.loads(line) for line in record.read_text().splitlines()]
    assert [event["kind"] for event in events] == ["size", "draw", "draw", "print", "draw", "draw"]
    assert events[0]["width"] == 40 and events[3]["lines"] == [[["kept", {"bold": True}]]]
    # The recording keeps what the terminal shows: the long line is cut to the width less one cell.
    cut = events[2]["lines"][0]
    assert sum(cells(text) for text, _ in cut) == 39 and cut[-1][0] == "…"


def test_select_moves_with_the_arrows_and_skips_a_disabled_choice() -> None:
    prompter, stream = make_prompter(["down", "enter"])
    choices = [Choice("a", "Alpha"), Choice("b", "Beta", disabled="not here"), Choice("c", "Gamma")]
    assert prompter.select("Which?", choices).value == "c"
    assert "not here" in stream.getvalue()
    prompter, _ = make_prompter(["2", "3", "enter"])
    assert prompter.select("Which?", choices).value == "c"


def test_esc_and_ctrl_c_cancel_a_prompt() -> None:
    prompter, _ = make_prompter(["esc"])
    with pytest.raises(CancelledError):
        prompter.select("Which?", [Choice(1, "one")])

    class Interrupted(ScriptedKeys):
        def read(self, timeout: float | None = None) -> str | None:
            raise KeyboardInterrupt

    prompter = Prompter(Screen(CAPS, stream=io.StringIO()), Interrupted([]), theme_for("sand", "dark"), CAPS)
    with pytest.raises(CancelledError):
        prompter.text("Name?")


def test_text_checks_the_answer_and_never_shows_a_secret() -> None:
    prompter, stream = make_prompter([*"short", "enter", "ctrl-u", *KEY, "enter"])
    value = prompter.text("Paste your key", secret=True, validate=lambda text: None if len(text) >= 8 else "too short")
    assert value == KEY
    assert "too short" in stream.getvalue() and KEY not in stream.getvalue() and KEY[:12] not in stream.getvalue()


def test_text_keeps_the_default_on_enter() -> None:
    prompter, _ = make_prompter(["enter"])
    assert prompter.text("Name?", default="Juno") == "Juno"
    prompter, _ = make_prompter(["backspace", "backspace", "backspace", "backspace", *"Ada", "enter"])
    assert prompter.text("Name?", default="Juno") == "Ada"


def test_search_filters_while_typing_and_ranks_the_best_match_first() -> None:
    names = ["openai/gpt-5.1", "z-ai/glm-5.3-flash", "z-ai/glm-4.6", "qwen/qwen3-coder"]
    prompter, stream = make_prompter([*"glm", "down", "enter"])
    assert prompter.search("Which model?", [Choice(name, name) for name in names]).value == "z-ai/glm-4.6"
    assert "2 of 4" in stream.getvalue()
    score = fuzzy_score("glm flash", "z-ai/glm-5.3-flash")
    assert score is not None and score > (fuzzy_score("glm", "z-ai/glm-4.6") or 0)
    assert fuzzy_score("xyz", "z-ai/glm-4.6") is None


def test_the_palette_shows_the_agents_and_falls_back_to_a_list() -> None:
    prompter, stream = make_prompter(["right", "right", "enter"])
    assert prompter.palette("Pick a colour", default="sand", name="Juno") == "moss"
    assert "▀" in stream.getvalue() and "Cobalt" in stream.getvalue()
    plain = Caps(color=NOCOLOR, unicode=True, interactive=True, width=110, height=40)
    prompter, stream = make_prompter(["down", "enter"], caps=plain)
    assert prompter.palette("Pick a colour", default="sand", name="Juno") == "cobalt"
    assert "▀" not in stream.getvalue()


def test_wait_returns_the_result_or_raises_the_error_of_the_work() -> None:
    prompter, _ = make_prompter([])
    assert prompter.wait("Working", lambda: 41 + 1) == 42

    def fail() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        prompter.wait("Working", fail)


class FakeServices:
    """The outside world of the setup: a model list, a key check and a keychain that only records."""

    def __init__(
        self,
        *,
        backend: str | None = "macos",
        stored: str | None = None,
        servers: list[LocalServer] | None = None,
        models: list[Model] | None = None,
    ) -> None:
        self.backend = backend
        self.stored = stored
        self.saved: list[str] = []
        self.checked: list[str] = []
        self.servers = servers or []
        self.models = models if models is not None else MODELS

    def check_key(self, base_url: str, key: str) -> tuple[bool, str]:
        self.checked.append(key)
        return (True, "credit left: $12.00") if key == KEY else (False, "the endpoint refused the key (HTTP 401)")

    def services(self) -> Services:
        return Services(
            fetch_models=lambda base, key: list(self.models),
            local_servers=lambda: list(self.servers),
            check_key=self.check_key,
            keychain_backend=lambda: self.backend,
            keychain_label=lambda: "the macOS Keychain",
            keychain_store=self.saved.append,
            keychain_read=lambda: self.stored,
        )


def run_setup(keys: list[str | float], fake: FakeServices, environ: dict[str, str], tmp_path: Path, **options: Any) -> Any:
    prompter, stream = make_prompter(keys)
    config = load_config(environment=environ)
    setup = Setup(prompter, environ=environ, config=config, services=fake.services(), cwd=tmp_path, **options)
    return setup.run(), stream.getvalue()


def test_setup_with_one_model_saves_the_key_in_the_keychain_and_never_in_the_file(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "config")}
    fake = FakeServices()
    keys: list[str | float] = [
        "enter",  # the name: Juno
        "enter",  # the colour: Sand
        "enter",  # OpenRouter
        *KEY,
        "enter",  # paste the key
        "enter",  # save it in the keychain
        "enter",  # one model
        "enter",  # the default model is the first
        "enter",  # the cap: $2 (a first setup)
        "enter",  # the time limit: 4 hours
        "enter",  # the results folder
        "down",
        "down",
        "enter",  # not now
    ]
    result, screen = run_setup(keys, fake, environ, tmp_path)
    path = tmp_path / "config" / "sentrytower" / "config.toml"
    assert result.path == path and result.audit is None and result.key == KEY
    text = path.read_text()
    assert KEY not in text and KEY not in screen and fake.saved == [KEY]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    document = tomllib.loads(text)
    assert document["ui"] == {"agent_name": "Juno", "agent_color": "sand"}
    assert document["provider"] == {"keychain": True, "base_url": "https://openrouter.ai/api/v1"}
    assert document["models"] == {"default": DEFAULT_MODEL} and "policies" not in document
    # No max_tokens: the cap of $2 is the measured standard run (20M tokens of the default model).
    assert document["budget"] == {"wall_clock_seconds": 14_400, "max_cost_usd": 2.0}
    assert document["run"] == {"out_dir": "~/sentrytower-results"}
    assert "Hi, I'm " in screen and "the measured run" in screen and "How much may one audit spend?" in screen
    # The deeper choices carry the preview label.
    assert "preview: more checks; effect on findings not yet measured" in screen
    assert "default" in screen and "benchmark" not in screen
    config = load_config(path, environment={})
    assert config.provider.keychain and config.ui.agent_name == "Juno" and config.out_dir == "~/sentrytower-results"


def test_setup_with_a_fast_and_a_strong_model_keeps_a_session_key_out_of_every_file(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "config"), "OPENROUTER_API_KEY": WRONG_KEY}
    fake = FakeServices()
    keys: list[str | float] = [
        "ctrl-u",
        *"Ada",
        "enter",  # the name
        "left",
        "enter",  # Plum
        "enter",  # OpenRouter
        *WRONG_KEY,
        "enter",  # the key of the environment is refused; a pasted copy of it too
        *KEY,
        "enter",  # accepted
        "down",
        "enter",  # keep it out of every file
        "down",
        "enter",  # a fast and a strong model
        *"qwen",
        "enter",  # the fast model
        "enter",  # the strong model: the default one, the first with tool calls
        "down",
        "enter",  # the depth: deep, $10
        "up",
        "enter",  # 2 hours
        "ctrl-u",
        *str(tmp_path / "results"),
        "enter",
        "enter",  # audit this folder
    ]
    result, screen = run_setup(keys, fake, environ, tmp_path)
    text = result.path.read_text()
    assert KEY not in text and WRONG_KEY not in text and fake.saved == []
    assert fake.checked == [WRONG_KEY, WRONG_KEY, KEY] and result.audit == tmp_path
    document = tomllib.loads(text)
    assert document["ui"] == {"agent_name": "Ada", "agent_color": "plum"}
    assert "keychain" not in document["provider"]
    assert document["models"] == {
        "default": "qwen/qwen3-coder",
        "deep_check": DEFAULT_MODEL,
        "free_roaming": DEFAULT_MODEL,
        "agent": DEFAULT_MODEL,
    }
    policy = document["policies"]["qwen/qwen3-coder"]
    assert policy["context_window"] == 262_144 and policy["reasoning_effort"] == "none" and policy["max_completion_tokens"] == 65_536
    # The prices of the model of the list are saved, so that a cost cap (the default one too) works for it.
    assert policy["input_cost_per_million"] == 0.2 and policy["output_cost_per_million"] == 0.8
    assert document["budget"]["max_cost_usd"] == 10.0 and document["budget"]["wall_clock_seconds"] == 7_200
    assert "the endpoint refused the key" in screen
    config = load_config(result.path, environment={"SENTRYTOWER_API_KEY": KEY})
    assert all(config.model_for(role) == "qwen/qwen3-coder" for role in FAST_ROLES)
    assert config.model_for("agent") == DEFAULT_MODEL and config.api_key({"SENTRYTOWER_API_KEY": KEY}) == (KEY, "SENTRYTOWER_API_KEY")


def test_setup_with_a_model_server_on_this_computer_needs_no_key(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "config")}
    fake = FakeServices(servers=[LocalServer("Ollama", "http://127.0.0.1:11434/v1", ["qwen3:8b"])], models=[Model("qwen3:8b")])
    # A model without prices gets no cost cap question: an audit has no cap and the standard ceiling.
    keys: list[str | float] = ["enter", "enter", "down", "down", "enter", "enter", "enter", "enter", "enter", "down", "down", "enter"]
    result, screen = run_setup(keys, fake, environ, tmp_path)
    document = tomllib.loads(result.path.read_text())
    assert document["provider"] == {"base_url": "http://127.0.0.1:11434/v1", "require_api_key": False, "max_parallel_requests": 4}
    assert document["models"] == {"default": "qwen3:8b"} and document["policies"]["qwen3:8b"] == {"reasoning_effort": "none"}
    assert document["budget"] == {"wall_clock_seconds": 14_400} and "no cost cap" in screen and result.audit is None
    assert load_config(result.path, environment={}).cost_cap("funnel") is None
    assert fake.checked == [] and "needs no key" in screen and "found Ollama with 1 model" in screen
    assert load_config(result.path, environment={}).api_key({}) == (None, None)


def test_setup_stops_on_esc_without_a_change(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "config")}
    fake = FakeServices()
    with pytest.raises(CancelledError):
        run_setup(["enter", "enter", "enter", *KEY, "enter", "enter", "esc"], fake, environ, tmp_path)
    assert not (tmp_path / "config").exists() and fake.saved == []


def test_setup_of_a_profile_writes_the_profile_file(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "config"), "SENTRYTOWER_API_KEY": KEY}
    keys: list[str | float] = ["enter", "enter", "enter", "enter", "enter", "enter", "enter", "enter", "enter", "down", "down", "enter"]
    result, _ = run_setup(keys, FakeServices(backend=None), environ, tmp_path, profile="work")
    assert result.path == tmp_path / "config" / "sentrytower" / "profiles" / "work.toml"
    assert f"file: {result.path}" in load_config(environment={**environ, "SENTRYTOWER_PROFILE": "work"}).sources


def test_the_estimate_is_measured_for_the_default_model_only() -> None:
    assert "measured" in estimate([MODELS[1]])
    assert "estimate" in estimate([MODELS[0], MODELS[1]])
    assert "not known" in estimate([Model("vendor/unknown")])


OPENROUTER_LIST = {
    "data": [
        {
            "id": DEFAULT_MODEL,
            "name": "DeepSeek: DeepSeek V4.1 Flash 1017",
            "context_length": 200_000,
            "pricing": {"prompt": "0.0000001", "completion": "0.0000004", "input_cache_read": "0.00000002"},
            "top_provider": {"max_completion_tokens": 131_072},
            "supported_parameters": ["tools", "reasoning", "max_tokens"],
        },
        {
            "id": "vendor/text-only",
            "name": "Text only",
            "context_length": 1_048_576,
            "pricing": {"prompt": "0", "completion": "0"},
            "supported_parameters": ["max_tokens"],
        },
        {"id": "", "name": "no id"},
        "not a model",
    ]
}


def test_a_model_list_of_openrouter_gives_prices_context_and_tool_support() -> None:
    models = catalog.parse_models(OPENROUTER_LIST)
    assert [model.id for model in models] == [DEFAULT_MODEL, "vendor/text-only"]
    default, text_only = models
    assert default.default and default.tools and default.reasoning and default.max_output == 131_072
    assert default.input_per_million == pytest.approx(0.1) and default.cache_read_per_million == pytest.approx(0.02)
    assert default.context_text == "200k ctx" and default.price_text == "$0.10 / $0.40 per M"
    assert text_only.tools is False and text_only.context_text == "1M ctx" and text_only.price_text == "free"
    assert [model.id for model in catalog.parse_models({"data": [{"id": "m1"}]})] == ["m1"]


def test_a_short_name_resolves_to_the_full_model_id() -> None:
    models = [*catalog.parse_models(OPENROUTER_LIST), Model("deepseek/deepseek-v3.2"), Model("z-ai/glm-4.6")]
    # The default model comes first among the models that a short name matches.
    assert [model.id for model in catalog.resolve("deepseek", models)] == [DEFAULT_MODEL, "deepseek/deepseek-v3.2"]
    assert [model.id for model in catalog.resolve("glm", models)] == ["z-ai/glm-4.6"]
    assert [model.id for model in catalog.resolve("glm-4.6", models)] == ["z-ai/glm-4.6"]
    assert catalog.resolve(DEFAULT_MODEL.upper(), models)[0].id == DEFAULT_MODEL
    assert catalog.resolve("nothing", models) == []


def test_the_model_list_is_cached_for_a_day_and_holds_no_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str | None]] = []

    def get_json(url: str, *, key: str | None = None, timeout: float = 8.0) -> Any:
        calls.append((url, key))
        return OPENROUTER_LIST

    monkeypatch.setattr(catalog, "_get_json", get_json)
    environ = {"XDG_CACHE_HOME": str(tmp_path / "cache")}
    first = catalog.fetch_models("https://example.com/v1", key=KEY, environ=environ)
    second = catalog.fetch_models("https://example.com/v1/", key=KEY, environ=environ)
    assert [model.id for model in first] == [model.id for model in second] and calls == [("https://example.com/v1/models", KEY)]
    cached = list((tmp_path / "cache" / "sentrytower" / "models").iterdir())
    assert len(cached) == 1 and KEY not in cached[0].read_text()
    catalog.fetch_models("https://example.com/v1", key=KEY, use_cache=False, environ=environ)
    assert len(calls) == 2


def test_the_key_check_reads_the_credit_of_an_openrouter_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def get_json(url: str, *, key: str | None = None, timeout: float = 8.0) -> Any:
        if key != KEY:
            raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]
        return {"data": {"limit_remaining": 12.5}}

    monkeypatch.setattr(catalog, "_get_json", get_json)
    assert catalog.check_key(catalog.OPENROUTER, KEY) == (True, "credit left: $12.50")
    assert catalog.check_key(catalog.OPENROUTER, WRONG_KEY) == (False, "the endpoint refused the key (HTTP 401)")


def test_the_live_view_shows_the_route_the_activity_and_the_budget(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    sessions = tmp_path / "sessions"
    sessions.mkdir(parents=True)
    repository.mkdir()
    stream = io.StringIO()
    screen = Screen(CAPS, stream=stream)
    live = LiveAudit(screen, theme_for("sand", "dark"), CAPS, agent_name="Juno", agent_color="sand")
    live.route_known(
        repository=repository,
        files=1_001,
        more=True,
        route="agent",
        models={role: DEFAULT_MODEL for role in ROLES},
        max_tokens=20_000_000,
        wall_clock_seconds=14_400,
        max_cost_usd=5.0,
    )
    live.engine_started(
        route="agent", work=tmp_path / "work", sessions=sessions, snapshot=lambda: {"tokens": 1_234_567, "cost": 0.42, "calls": 9}
    )
    entries = [
        {
            "message": {
                "role": "assistant",
                "content": [{"type": "toolCall", "name": "grep", "arguments": {"pattern": "eval(", "path": str(repository)}}],
            }
        },
        {"message": {"role": "user", "content": [{"type": "toolCall", "name": "read", "arguments": {"path": "ignored.py"}}]}},
        {
            "message": {
                "role": "assistant",
                "content": [{"type": "toolCall", "name": "read", "arguments": {"path": f"{repository}/src/app.py"}}],
            }
        },
    ]
    (sessions / "agent.jsonl").write_text("".join(json.dumps(entry) + "\n" for entry in entries) + '{"partial')
    live.last_poll = live.last_frame = 0.0
    live.tick()
    text = to_plain_screen(screen)
    assert "Juno is auditing repo" in text and "more than 1,000 files" in text and "single-agent engine" in text
    assert "DeepSeek V4.1 Flash" in text and "cap $5.00" in text and "4 h" in text
    assert "reading src/app.py" in text and "1 file read · 1 search" in text
    assert "1.2M of 20M tokens" in text and "$0.42 of $5.00" in text and "ctrl-c stops the audit and keeps the report" in text
    assert "ignored.py" not in text
    live.interrupted()
    assert "stopping; writing the report of the work so far" in to_plain_screen(screen)
    live.close()
    assert screen.live == []


def test_the_live_view_of_the_funnel_counts_the_units_that_the_searches_add(tmp_path: Path) -> None:
    # The numbers of a real audit: 287 checks planned at the start, then the searches of the agents added units.
    work = tmp_path / "work"
    work.mkdir()
    (work / "funnel-run.json").write_text(
        json.dumps(
            {
                "phase0": {"status": "complete", "units": 292, "files": 153},
                "pacing": {"planned_checks": 287},
                "parameters": {"max_unit_checks": 1500},
            }
        )
    )
    funnel = {"units": 427, "checked": 367, "units_left": 55, "leads": 275, "deep_checked": 166, "verified": 59, "findings": 208}
    (work / "summary.json").write_text(json.dumps({"funnel": funnel, "phase_seconds": {"unit_check": [2.6, 878.8]}}))
    screen = Screen(CAPS, stream=io.StringIO())
    live = LiveAudit(screen, theme_for("sand", "dark"), CAPS, agent_name="Juno", agent_color="sand")
    live.route_known(
        repository=tmp_path,
        files=252,
        more=False,
        route="funnel",
        models={role: DEFAULT_MODEL for role in ROLES},
        max_tokens=20_000_000,
        wall_clock_seconds=14_400,
        max_cost_usd=5.0,
    )
    live.engine_started(route="funnel", work=work, sessions=tmp_path / "sessions", snapshot=lambda: {"tokens": 4_900_000, "cost": 0.28})
    live.last_poll = live.last_frame = 0.0
    live.tick()
    text = to_plain_screen(screen)
    assert "367 of 422" in text and " 87%" in text and "128%" not in text
    assert "✓ Check each unit" not in text and "Check each unit" in text
    assert "275 leads · 166 checked in depth" in text and "59 verified" in text and "208 candidate findings" in text
    assert all(line_cells(line) <= CAPS.width - 1 for line in screen.live)
    # The queue is empty: the checks are done.
    (work / "summary.json").write_text(json.dumps({"funnel": {"units": 430, "checked": 430, "units_left": 0}}))
    live.last_poll = live.last_frame = 0.0
    live.tick()
    assert "✓ Check each unit" in to_plain_screen(screen) and "430 of 430" in to_plain_screen(screen)


def to_plain_screen(screen: Screen) -> str:
    return "\n".join(to_plain(line) for line in screen.live)


def finding(rank: int, severity: str, path: str, line: int, cwe: str) -> OutputFinding:
    return OutputFinding(
        rank=rank,
        title=f"Finding {rank}",
        severity=severity,
        cwe=[cwe],
        locations=[OutputLocation(path, line, line + 2)],
        evidence="e",
        exploit_conditions="c",
        engine="funnel",
        route="funnel",
    )


def test_the_summary_lists_the_findings_by_severity_and_says_where_the_files_are(tmp_path: Path) -> None:
    findings = [finding(1, "medium", "app/views.py", 40, "CWE-79"), finding(2, "critical", "app/db.py", 12, "CWE-89")]
    run = {
        "status": "complete",
        "repository": {"name": "shop"},
        "seconds": 754,
        "route": "funnel",
        "usage": {"total": {"total_tokens": 3_400_000, "cost_usd": 0.31}},
        "warnings": ["shown already", "a new warning"],
    }
    files = {"json": tmp_path / "findings.json", "markdown": tmp_path / "report.md"}
    lines = summary_lines(
        findings,
        run,
        files,
        theme=theme_for("sand", "dark"),
        caps=CAPS,
        agent_name="Juno",
        agent_color="sand",
        width=100,
        shown_warnings=["shown already"],
    )
    text = "\n".join(to_plain(line) for line in lines)
    assert "Juno found 2 issues in shop" in text and "12 min 34 s · 3.4M tokens · $0.31 · funnel engine" in text
    assert text.index("app/db.py:12") < text.index("app/views.py:40") and "CRIT" in text and "CWE-89" in text
    assert "findings.json · report.md" in text and "a new warning" in text and "shown already" not in text
    assert "confirm it in the code" in text
    empty = summary_lines(
        [], {**run, "warnings": []}, files, theme=theme_for("sand", "dark"), caps=CAPS, agent_name="Juno", agent_color="sand", width=100
    )
    assert "not proof that the code is safe" in "\n".join(to_plain(line) for line in empty)


def test_the_summary_states_the_result_and_shows_tier_2_under_the_preview_label() -> None:
    deeper = finding(3, "critical", "app/api.py", 7, "CWE-78")
    deeper.tier = 2
    result = {
        "status": "complete",
        "stop_text": "The run spent 85% of the $10.00 cost cap, so no new work started; the running work finished.",
        "failure": None,
        "spent_usd": 8.61,
        "cap_usd": 10.0,
        "units": {"kind": "code units", "checked": 120, "failed": 0, "total": 400},
        "depth_factor": 5.0,
        "preview": True,
    }
    run = {
        "status": "complete",
        "repository": {"name": "shop"},
        "seconds": 754,
        "route": "funnel",
        "result": result,
        "usage": {"total": {"total_tokens": 3_400_000, "cost_usd": 8.61}},
        "warnings": [],
    }
    lines = summary_lines(
        [finding(1, "medium", "app/views.py", 40, "CWE-79"), deeper],
        run,
        {},
        theme=theme_for("sand", "dark"),
        caps=CAPS,
        agent_name="Juno",
        agent_color="sand",
        width=120,
    )
    text = "\n".join(to_plain(line) for line in lines)
    assert "Spent $8.61 of the $10.00 cost cap." in text and "Checked 120 of 400 code units." in text and "85% of the $10.00" in text
    assert "Depth 5 times the standard run (preview: more checks; effect on findings not yet measured)." in text
    # The finding of tier 2 comes after the standard findings, under the label, whatever its severity.
    assert text.index("app/views.py:40") < text.index("More findings (preview:") < text.index("app/api.py:7")


def test_the_last_run_is_remembered_without_findings_or_code(tmp_path: Path) -> None:
    environ = {"XDG_STATE_HOME": str(tmp_path / "state")}
    assert last_run(environ) is None
    remember(tmp_path / "out", {"repository": {"name": "shop"}, "ended_at": "2026-10-28T10:00:00Z", "findings": {"count": 3}}, environ)
    record = last_run(environ)
    assert record == {"out_dir": str((tmp_path / "out").resolve()), "repository": "shop", "ended_at": "2026-10-28T10:00:00Z", "findings": 3}


def test_the_findings_of_a_findings_document_come_back_for_the_last_run() -> None:
    finding = OutputFinding(
        rank=2,
        title="SQL injection",
        severity="high",
        cwe=["CWE-89"],
        locations=[OutputLocation("db.py", 3, 4), OutputLocation("views.py", 9, 9, "the request")],
        evidence="e",
        exploit_conditions="",
        engine="deep-check",
        route="funnel",
        tier=2,
        verification_status="unverified",
        verification_reason="the verification call failed",
    )
    (item, *_) = from_document({"schema_version": "2.0.0", "findings": [finding.record(), "junk"]})
    assert item.record() == finding.record() and item.verification_label() == "unverified: the verification call failed"
    assert from_document(None) == []


def test_a_findings_document_of_version_1_still_comes_back_for_the_last_run() -> None:
    document = {
        "schema_version": "1.0.0",
        "findings": [
            {
                "rank": 1,
                "title": "SQL injection",
                "severity": "high",
                "cwe": ["CWE-89"],
                "location": {"path": "db.py", "start_line": 3, "end_line": 4},
            },
            "junk",
        ],
    }
    (item,) = from_document(document)
    assert item.title == "SQL injection" and item.location is not None and item.location.path == "db.py" and item.cwe == ["CWE-89"]
    assert (item.location.start_line, item.location.end_line) == (3, 4)


def test_paths_are_shown_from_the_home_folder_also_through_a_symbolic_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sentrytower.ui.widgets import tilde

    real = tmp_path / "real-home"
    (real / "code" / "app").mkdir(parents=True)
    link = tmp_path / "home-link"
    link.symlink_to(real)
    monkeypatch.setenv("HOME", str(link))
    assert tilde(real / "code" / "app") == "~/code/app" and tilde(link / "code" / "app") == "~/code/app" and tilde(link) == "~"
    monkeypatch.chdir(tmp_path)
    assert tilde(tmp_path / "out", from_cwd=True) == "./out" and tilde(tmp_path / "out") == str(tmp_path / "out")


def test_a_long_location_loses_whole_leading_folders_first() -> None:
    from sentrytower.ui.results import short_location

    assert short_location("vulnerabilities/exec/source/low.php:5", 34) == "…/exec/source/low.php:5"
    assert short_location("vulnerabilities/api/src/HealthController.php:83", 34) == "…/api/src/HealthController.php:83"
    assert short_location("login.php:20", 34) == "login.php:20"
    assert short_location("a" * 50 + ".py:1", 20) == "…" + ("a" * 50 + ".py:1")[-19:]


def test_the_report_opens_only_where_a_person_can_see_it(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentrytower.ui import results

    assert results.report_file({"markdown": Path("r.md"), "html": Path("r.html")}) == Path("r.html")
    assert results.report_file({"markdown": Path("r.md")}) == Path("r.md") and results.report_file({}) is None
    assert not results.can_open({"CI": "true", "DISPLAY": ":0"})
    assert not results.can_open({"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22", "DISPLAY": ":0"})
    monkeypatch.setattr(results.sys, "platform", "linux")
    assert not results.can_open({}) and results.can_open({"WAYLAND_DISPLAY": "wayland-0"})
    monkeypatch.setattr(results.sys, "platform", "darwin")
    assert results.can_open({})
