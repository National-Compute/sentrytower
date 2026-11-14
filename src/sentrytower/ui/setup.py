"""``sentrytower setup``: the guided setup. It writes the user's settings file and checks the tools.

The steps: the agent's name and colour; where the models come from
(OpenRouter, an OpenAI-compatible endpoint, or a model server on this
computer); the key; one model, a fast and a strong model, or a model for
each role; the budget of an audit; the results folder. Then it saves
``~/.config/sentrytower/config.toml`` (or the file of a profile), checks
the tools and offers to audit the current folder.

The key never goes into the settings file. It stays in the environment, or
the setup saves it in the system keychain when the person asks for it
(``provider.keychain = true`` in the file). Nothing is saved before the
last step; Esc or Ctrl-C stops without a change.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Mapping

from .. import __version__
from ..budget import DEFAULT_MAX_TOKENS, DEPTHS, STANDARD_COST_USD, plan_tokens, price_per_million
from ..config import (
    AGENT_ROLES,
    DEFAULT_BASE_URL,
    DEFAULT_KEY_VARIABLES,
    FAST_ROLES,
    ROLES,
    Config,
    ConfigError,
    _base_url,
    user_config_path,
    write_config,
)
from ..policies import BUILTIN_POLICIES, ModelPolicy, policy_from_table
from ..result import PREVIEW_LABEL
from ..router import LARGE_REPO_FILES
from . import catalog, keychain
from .catalog import LocalServer, Model
from .mascot import BADGE, HERO, art, beside
from .term import PLAIN, Line
from .theme import theme_for
from .widgets import Choice, Prompter, money, tilde, tokens_text

ROLE_TEXT = {
    "rating": "ranks the code units of a large queue (short answers)",
    "unit_check": "one question for each code unit (the most calls)",
    "triage": "a blind check of each lead (short answers)",
    "verify": "a blind check of each finding (short answers)",
    "deep_check": "an agent session for each strong lead (reads and traces code)",
    "free_roaming": "an agent session on the whole repository",
    "agent": "the agent of a repository of more than 1,000 files",
}
# The cost budget that a first setup proposes: the standard depth.
PROPOSED_CAP = DEPTHS["standard"]
WALL_CLOCKS = ((3600, "1 hour"), (7200, "2 hours"), (14_400, "4 hours"), (28_800, "8 hours"))


@dataclass
class Services:
    """What the setup reads from outside: the endpoints, the keychain, the tools. Tests replace them."""

    fetch_models: Callable[[str, str | None], list[Model]] = lambda base, key: catalog.fetch_models(base, key=key)
    local_servers: Callable[[], list[LocalServer]] = catalog.local_servers
    check_key: Callable[[str, str], tuple[bool, str]] = catalog.check_key
    keychain_backend: Callable[[], str | None] = keychain.backend
    keychain_label: Callable[[], str] = keychain.label
    keychain_store: Callable[[str], None] = keychain.store
    keychain_read: Callable[[], str | None] = keychain.read
    tool_checks: Callable[[Config], list[Any]] | None = None
    count_files: Callable[[Path], int] | None = None


@dataclass
class SetupResult:
    path: Path
    document: dict[str, Any]
    audit: Path | None = None
    key: str | None = field(default=None, repr=False)


def model_policy(model: Model) -> ModelPolicy:
    """The request policy that an audit uses for a model of the list: the built-in one, else one from the list."""
    return BUILTIN_POLICIES.get(model.id) or policy_from_table(model.id, model.policy_table())


def estimate(models: list[Model]) -> str:
    """What an audit with the default token ceiling of 20M tokens costs at most with these models: an estimate from the prices."""
    prices = [price_per_million(model_policy(model), "funnel") for model in models]
    if not models or any(price is None for price in prices):
        return "the price of these models is not known: set a token ceiling in the settings file"
    high = DEFAULT_MAX_TOKENS * max(price for price in prices if price is not None) / 1e6
    return f"with 20M tokens, an audit costs up to about {money(high)} with these models (estimate)"


class Setup:
    def __init__(
        self,
        prompter: Prompter,
        *,
        environ: Mapping[str, str],
        config: Config,
        profile: str | None = None,
        services: Services | None = None,
        cwd: Path | None = None,
    ) -> None:
        self.p = prompter
        self.env = environ
        self.config = config
        self.profile = profile
        self.services = services or Services()
        self.cwd = cwd or Path.cwd()
        self.document: dict[str, Any] = {}
        self.models: list[Model] = []
        self.key: str | None = None
        self.keychain_wanted = False

    def run(self) -> SetupResult:
        theme, caps = self.p.theme, self.p.caps
        hero = art(self.config.ui.agent_color, HERO, caps.color)
        welcome: list[Line] = [
            [("SentryTower ", theme.bold), (__version__, theme.dim)],
            [],
            [("Let's set up your security agent.", PLAIN)],
            [("About a minute. Nothing is saved until the last step.", theme.dim)],
        ]
        intro = beside(hero, welcome, gap=4, top=max(0, len(hero) // 2 - 2)) if hero else welcome
        self.p.intro([*intro, []])
        title = "Setup" + (f" of profile {self.profile}" if self.profile else "")
        self.p.print([[(f"{self.p.sym.start}  ", theme.mark), (title, theme.bold)], self.p.rail()])
        name, color = self.agent()
        base_url, local = self.source()
        require_key = not local
        if require_key:
            self.key_step(base_url)
        else:
            self.p.note([[(f"{self.p.sym.check} ", theme.good), ("A model server on this computer needs no key.", PLAIN)], []])
        chosen = self.models_step(base_url)
        budget = self.budget_step(chosen)
        out_dir = self.p.text(
            "Where should the results go?",
            default=self.config.out_dir or "~/sentrytower-results",
            hint="each repository gets its own folder in it · enter confirm",
        )
        path = user_config_path(self.profile, self.env)
        self.save_key()
        self.document = self.compose(name, color, base_url, local, chosen, budget, out_dir)
        write_config(
            path,
            self.document,
            header=f"SentryTower settings, written by `sentrytower setup` ({__version__}).\nThe provider key is never stored in this file.",
        )
        self.p.note([[(f"{self.p.sym.check} ", theme.good), ("Saved ", PLAIN), (tilde(path), theme.bold)]])
        self.tools_step()
        audit = self.audit_step()
        if audit is not None:
            self.p.outro([("Setup done. ", PLAIN), (name, self.p.theme.name), (" starts the audit.", PLAIN)])
        else:
            hint = "sentrytower" if not self.profile else f"sentrytower --profile {self.profile}"
            done = [("Done. Run ", PLAIN), (hint, theme.bold), (" any time; change a setting with ", PLAIN)]
            self.p.outro([*done, ("sentrytower settings", theme.bold), (".", PLAIN)])
        return SetupResult(path=path, document=self.document, audit=audit, key=self.key)

    def agent(self) -> tuple[str, str]:
        theme, caps = self.p.theme, self.p.caps

        def valid(text: str) -> str | None:
            if not 1 <= len(text) <= 24 or not text.isprintable():
                return "a name of 1 to 24 characters"
            return None

        name = self.p.text("What should your agent be called?", default=self.config.ui.agent_name, validate=valid)
        color = self.p.palette(f"Pick a colour for {name}", default=self.config.ui.agent_color, name=name)
        badge = art(color, BADGE, caps.color)
        # From here on, the screens wear the agent's colour.
        self.p.theme = theme_for(color, theme.background)
        hello: list[Line] = [
            [("Hi, I'm ", PLAIN), (name, self.p.theme.name), (".", PLAIN)],
            [("I read your code like an attacker would and report", self.p.theme.dim)],
            [("what I find, with the file and the line.", self.p.theme.dim)],
        ]
        block = beside(badge, hello, gap=3, top=2) if badge else hello
        self.p.note([*block, []])
        return name, color

    def source(self) -> tuple[str, bool]:
        servers = self.p.wait("Looking for model servers on this computer", self.services.local_servers)
        local_hint = (
            f"found {servers[0].name} with {len(servers[0].models)} model{'s' if len(servers[0].models) != 1 else ''}"
            if servers
            else "none answers on the usual ports"
        )
        choices = [
            Choice("openrouter", "OpenRouter", "one key, 300+ models", tag="recommended"),
            Choice("endpoint", "Your own endpoint", "any OpenAI-compatible URL"),
            Choice("local", "This computer", local_hint),
        ]
        current = 0
        if self.config.provider.base_url.rstrip("/") != DEFAULT_BASE_URL:
            current = 2 if "127.0.0.1" in self.config.provider.base_url or "localhost" in self.config.provider.base_url else 1
        picked = self.p.select("Where do your models come from?", choices, default=current).value
        if picked == "openrouter":
            return DEFAULT_BASE_URL, False

        def valid(text: str) -> str | None:
            try:
                _base_url(text, "the URL")
            except ConfigError as error:
                return str(error)
            return None

        if picked == "local" and servers:
            if len(servers) == 1:
                return servers[0].base_url, True
            server = self.p.select("Which server?", [Choice(item.base_url, item.name, item.base_url) for item in servers]).value
            return str(server), True
        url = self.p.text(
            "The base URL of the endpoint",
            placeholder="https://example.com/v1" if picked == "endpoint" else "http://127.0.0.1:11434/v1",
            validate=valid,
        )
        return url.rstrip("/"), picked == "local"

    def key_step(self, base_url: str) -> None:
        theme, sym = self.p.theme, self.p.sym
        names = list(self.config.provider.api_key_env or DEFAULT_KEY_VARIABLES)
        found = next(((self.env[name].strip(), name) for name in names if self.env.get(name, "").strip()), None)
        if found is None and self.services.keychain_backend():
            stored = self.services.keychain_read()
            if stored:
                found = (stored, "keychain")
        self.document.setdefault("provider", {})
        while True:
            if found is not None:
                key, source = found
                where = self.services.keychain_label() if source == "keychain" else source
                ok, detail = self.p.wait("Checking the key", partial(self.services.check_key, base_url, key))
                prefix = key.split("-v1-")[0] + "-v1-" if "-v1-" in key[:12] else key[:3]
                lines: list[Line] = [
                    [
                        (f"{sym.check if ok else sym.cross} ", theme.good if ok else theme.bad),
                        ("Found a key in ", PLAIN),
                        (where, theme.bold),
                        (f"  {prefix}••••", theme.dim),
                    ]
                ]
                lines.append([(f"{sym.check if ok else sym.warning} ", theme.good if ok else theme.caution), (detail, PLAIN)])
                self.p.note([*lines, []])
                if ok:
                    choice = self.p.select("Use this key?", [Choice("use", "Use this key"), Choice("paste", "Paste another key")]).value
                    if choice == "use":
                        self.key = key
                        if source == "keychain":
                            self.document["provider"]["keychain"] = True
                        return
                found = None
            key = self.p.text(
                "Paste your key",
                secret=True,
                validate=lambda text: None if len(text) >= 8 else "the key looks too short",
                hint="it is never shown, logged or written to a file · enter confirm",
            )
            ok, detail = self.p.wait("Checking the key", partial(self.services.check_key, base_url, key))
            if not ok:
                self.p.note([[(f"{sym.cross} ", theme.bad), (detail, PLAIN)], []])
                continue
            self.p.note([[(f"{sym.check} ", theme.good), (detail, PLAIN)], []])
            self.key = key
            backend = self.services.keychain_backend()
            options = []
            if backend:
                options.append(
                    Choice("keychain", f"Save it in {self.services.keychain_label()}", "new terminals find it", tag="recommended")
                )
            options.append(Choice("session", "Keep it out of every file", "set SENTRYTOWER_API_KEY in your shell yourself"))
            where_to = self.p.select("Where should SentryTower find the key?", options).value
            # The key goes into the keychain in the last step, with the settings file (save_key).
            self.keychain_wanted = where_to == "keychain"
            return

    def save_key(self) -> None:
        """Save a pasted key in the keychain when the person asked for it; on a refusal, say how to give the key instead."""
        if not self.keychain_wanted or not self.key:
            return
        label = self.services.keychain_label()
        try:
            self.p.wait(f"Saving the key in {label}", partial(self.services.keychain_store, self.key), done=f"Saved the key in {label}")
        except OSError as error:
            theme = self.p.theme
            self.p.note([[(f"{self.p.sym.warning} ", theme.caution), (f"{error}. Set SENTRYTOWER_API_KEY in your shell instead.", PLAIN)]])
            return
        self.document.setdefault("provider", {})["keychain"] = True

    def _model_choices(self, models: list[Model], *, needs_tools: bool) -> list[Choice]:
        ordered = sorted(models, key=lambda model: (not model.default, model.id))
        choices = []
        for model in ordered:
            star = f"{self.p.sym.star} " if model.default else "  "
            tools = f"tools {self.p.sym.check}" if model.tools else ("no tools" if model.tools is False else "")
            disabled = "no tool calls: cannot drive an agent" if needs_tools and model.tools is False else None
            columns = [star + model.id, model.context_text, model.price_text, disabled or tools]
            if model.default:
                columns.append("default")
            choices.append(
                Choice(
                    model,
                    model.id,
                    tag="default" if model.default else "",
                    disabled=disabled,
                    search_text=f"{model.id} {model.name}",
                    columns=columns,
                )
            )
        return choices

    def _pick(self, question: str, models: list[Model], *, needs_tools: bool) -> Model:
        choices = [choice for choice in self._model_choices(models, needs_tools=needs_tools) if not choice.disabled]
        if not choices:
            raise ConfigError("the endpoint lists no model that fits")
        return self.p.search(question, choices, answer=lambda choice: str(choice.value.id)).value  # type: ignore[no-any-return]

    def models_step(self, base_url: str) -> dict[str, Model]:
        theme = self.p.theme
        label = "OpenRouter" if base_url == DEFAULT_BASE_URL else base_url
        try:
            models = self.p.wait(f"Loading the models of {label}", lambda: self.services.fetch_models(base_url, self.key))
            self.p.note([[(f"{self.p.sym.check} ", theme.good), (f"{len(models)} models available", PLAIN)], []])
        except (OSError, ValueError) as error:
            self.p.note(
                [
                    [
                        (f"{self.p.sym.warning} ", theme.caution),
                        (f"The model list cannot be read ({error}); the known models follow.", PLAIN),
                    ],
                    [],
                ]
            )
            models = catalog.known_models()
        self.models = models
        mode = self.p.select(
            "How many models?",
            [
                Choice("one", "One model for everything", "recommended"),
                Choice("two", "A fast and a strong model", "fast for the many short checks, strong for the agents"),
                Choice("roles", "Expert", "a model for each of the 7 roles"),
            ],
        ).value
        chosen: dict[str, Model] = {}
        if mode == "one":
            model = self._pick("Which model?", models, needs_tools=True)
            chosen = {role: model for role in ROLES}
        elif mode == "two":
            fast = self._pick("The fast model, for the many short checks", models, needs_tools=False)
            strong = self._pick("The strong model, for the agent sessions", models, needs_tools=True)
            chosen = {**{role: fast for role in FAST_ROLES}, **{role: strong for role in AGENT_ROLES}}
        else:
            for role in ROLES:
                chosen[role] = self._pick(f"{role}: {ROLE_TEXT[role]}", models, needs_tools=role in AGENT_ROLES)
        return chosen

    def budget_step(self, chosen: dict[str, Model]) -> dict[str, Any]:
        distinct = list({model.id: model for model in chosen.values()}.values())
        policies = [model_policy(model) for model in distinct]
        note = estimate(distinct)
        clock_choices = [Choice(seconds, label, "default" if seconds == 14_400 else "") for seconds, label in WALL_CLOCKS]
        clock_default = next(
            (index for index, (seconds, _) in enumerate(WALL_CLOCKS) if seconds == self.config.budget.wall_clock_seconds), 2
        )
        if any(price_per_million(policy, "funnel") is None for policy in policies):
            # A cost cap needs the prices of each model: without them an audit has no cap and the standard ceiling.
            text = (
                f"The prices of these models are not known, so an audit has no cost cap and the standard ceiling of "
                f"{tokens_text(DEFAULT_MAX_TOKENS)} tokens. Add the prices to the [policies] table of a model for a cap."
            )
            self.p.note([[(text, self.p.theme.dim)], []])
            clock = self.p.select("Time limit of an audit", clock_choices, default=clock_default).value
            return {"max_cost_usd": None, "wall_clock_seconds": clock, "write_cap": False}

        def buys(cap: float) -> str:
            plan = plan_tokens(None, cap, policies, "funnel")
            if plan.depth > 1:
                # A depth above the standard run: more checks, with an effect on the findings that is not yet measured.
                return PREVIEW_LABEL
            if plan.source == "standard run":
                return "the standard run of 20M tokens"
            return f"about {tokens_text(plan.tokens)} tokens" if plan.source == "cost cap" else ""

        # A first setup proposes PROPOSED_CAP; a later one proposes the saved cap (0: no cap; none saved: the default cap).
        saved = any(source.startswith("file:") for source in self.config.sources)
        setting = self.config.budget.max_cost_usd
        current = (STANDARD_COST_USD if setting is None else setting or None) if saved else PROPOSED_CAP
        choices = [Choice(value, f"{name.capitalize()} · {money(value)} an audit", buys(value)) for name, value in DEPTHS.items()]
        choices.append(Choice(None, "No cap", f"{tokens_text(DEFAULT_MAX_TOKENS)} tokens; the cost follows the price"))
        choices.append(Choice("other", "Another amount"))
        default = next((index for index, choice in enumerate(choices) if choice.value == current), list(DEPTHS).index("standard"))
        self.p.note(
            [
                [(note, self.p.theme.dim)],
                [("A larger budget buys a deeper audit; a small repository can end with less.", self.p.theme.dim)],
                [],
            ]
        )
        cap = self.p.select("How much may one audit spend?", choices, default=default).value
        if cap == "other":

            def valid(text: str) -> str | None:
                try:
                    return None if float(text.lstrip("$")) > 0 else "a positive amount"
                except ValueError:
                    return "a number of US dollars, for example 2.50"

            cap = float(self.p.text("The cost cap in US dollars", placeholder="2.50", validate=valid).lstrip("$"))
        clock = self.p.select("Time limit of an audit", clock_choices, default=clock_default).value
        return {"max_cost_usd": cap, "wall_clock_seconds": clock, "write_cap": True}

    def compose(
        self, name: str, color: str, base_url: str, local: bool, chosen: dict[str, Model], budget: dict[str, Any], out_dir: str
    ) -> dict[str, Any]:
        document: dict[str, Any] = {"ui": {"agent_name": name, "agent_color": color}}
        ids = {role: model.id for role, model in chosen.items()}
        default = max(set(ids.values()), key=lambda model_id: sum(1 for value in ids.values() if value == model_id))
        models: dict[str, Any] = {"default": default}
        models.update({role: model_id for role, model_id in ids.items() if model_id != default})
        document["models"] = models
        provider: dict[str, Any] = dict(self.document.get("provider") or {})
        provider["base_url"] = base_url
        if local:
            provider["require_api_key"] = False
            provider["max_parallel_requests"] = 4
        document["provider"] = provider
        # No max_tokens: the cost cap sets the token plan of each audit (budget.plan_tokens). "No cap" is a cap of 0:
        # without the key, the default cap would apply. Models without prices get no key: no cap until they have prices.
        document["budget"] = {"wall_clock_seconds": budget["wall_clock_seconds"]}
        if budget.get("write_cap", True):
            document["budget"]["max_cost_usd"] = float(budget["max_cost_usd"] or 0)
        document["run"] = {"out_dir": out_dir}
        policies: dict[str, Any] = {}
        for model in {model.id: model for model in chosen.values()}.values():
            if model.id not in BUILTIN_POLICIES:
                policies[model.id] = model.policy_table()
        if policies:
            document["policies"] = policies
        return document

    def tools_step(self) -> None:
        if self.services.tool_checks is None:
            return
        from ..config import load_config
        from ..doctor import FAIL, OK, WARN

        try:
            config = load_config(user_config_path(self.profile, self.env), environment={**self.env, "SENTRYTOWER_API_KEY": self.key or "x"})
        except ConfigError:
            return
        checks = [check for check in self.services.tool_checks(config) if check.name not in ("api key", "endpoint")]
        theme, sym = self.p.theme, self.p.sym
        if all(check.status == OK for check in checks):
            self.p.note(
                [
                    [
                        (f"{sym.check} ", theme.good),
                        ("Ready: ", PLAIN),
                        (" · ".join(check.detail.split(" at ")[0] for check in checks), theme.dim),
                    ],
                    [],
                ]
            )
            return
        lines: list[Line] = []
        for check in checks:
            mark = {OK: (sym.check, theme.good), WARN: (sym.warning, theme.caution), FAIL: (sym.cross, theme.bad)}.get(
                check.status, (sym.dot, theme.dim)
            )
            lines.append([(f"{mark[0]} ", mark[1]), (check.detail, PLAIN)])
            if check.hint and check.status in (WARN, FAIL):
                lines.append([("    " + check.hint, theme.dim)])
        self.p.note([*lines, []])

    def audit_step(self) -> Path | None:
        folder = self.cwd
        files = self.services.count_files(folder) if self.services.count_files else None
        size = "" if files is None else f"more than {LARGE_REPO_FILES:,} files" if files > LARGE_REPO_FILES else f"{files:,} files"
        choices = [
            Choice("here", "Audit this folder", f"{tilde(folder)}" + (f", {size}" if size else "")),
            Choice("other", "Audit another folder"),
            Choice("later", "Not now"),
        ]
        picked = self.p.select("Audit a repository now?", choices).value
        if picked == "here":
            return folder
        if picked == "other":

            def valid(text: str) -> str | None:
                return None if Path(text).expanduser().is_dir() else "no such folder"

            return Path(self.p.text("Which folder?", placeholder="~/code/my-app", validate=valid)).expanduser()
        return None
