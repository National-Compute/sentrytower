"""The configuration: defaults, a TOML file, environment variables, options, roles and policies."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentrytower.config import AGENT_ROLE, AGENT_ROLES, FAST_ROLES, FUNNEL_ROLES, ROLES, ConfigError, config_home, load_config, write_config
from sentrytower.policies import DEFAULT_MODEL


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sentrytower.toml"
    path.write_text(text)
    return path


def test_the_defaults() -> None:
    config = load_config(environment={})
    assert DEFAULT_MODEL == "deepseek/deepseek-v4.1-flash-1017"
    assert config.models == {role: DEFAULT_MODEL for role in ROLES}
    assert config.single_model
    # No token ceiling and no cost cap of a setting: the default cap of $2, the measured standard run of 20M tokens.
    assert config.budget.max_tokens is None and config.budget.wall_clock_seconds == 14_400
    assert config.budget.max_cost_usd is None and config.cost_cap("funnel") == config.cost_cap("agent") == 2.0
    assert config.token_plan("funnel").tokens == 20_000_000 and config.token_plan("agent").source == "standard run"
    assert config.provider.base_url == "https://openrouter.ai/api/v1"
    assert config.large_repo_files == 1000
    assert config.open_report is True
    record = config.record()
    assert "benchmarked_configuration" not in record and "benchmark_deviations" not in record
    policy = config.policies()[DEFAULT_MODEL]
    assert policy.reasoning_effort == "medium" and policy.max_completion_tokens == 65_536
    assert policy.attempt_timeout_seconds == 300.0 and policy.context_window == 1_024_000 and policy.max_output_tokens == 384_000


def test_single_llm_file(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, '[models]\ndefault = "vendor/model-a"\n'), environment={})
    assert set(config.models.values()) == {"vendor/model-a"} and config.single_model


def test_multi_llm_roles(tmp_path: Path) -> None:
    text = """
[models]
default = "deepseek/deepseek-v4.1-flash-1017"
unit_check = "vendor/small"
triage = "vendor/small"
deep_check = "vendor/large"
agent = "vendor/large"
"""
    config = load_config(write(tmp_path, text), environment={})
    assert config.model_for("unit_check") == "vendor/small"
    assert config.model_for("rating") == DEFAULT_MODEL
    assert config.model_for("free_roaming") == DEFAULT_MODEL
    assert config.models_of("funnel") == {
        "rating": DEFAULT_MODEL,
        "unit_check": "vendor/small",
        "triage": "vendor/small",
        "verify": DEFAULT_MODEL,
        "deep_check": "vendor/large",
        "free_roaming": DEFAULT_MODEL,
    }
    assert config.models_of("agent") == {AGENT_ROLE: "vendor/large"}
    assert not config.single_model
    assert set(config.policies()) == {DEFAULT_MODEL, "vendor/small", "vendor/large"}


def test_the_environment_overrides_the_file_and_the_options_override_both(tmp_path: Path) -> None:
    file = write(tmp_path, '[models]\ndefault = "a/file"\ntriage = "a/triage"\n[budget]\nmax_tokens = 5000000\n')
    environment = {
        "SENTRYTOWER_MODEL": "b/env",
        "SENTRYTOWER_MODEL_VERIFY": "b/verify",
        "SENTRYTOWER_MAX_TOKENS": "3000000",
        "SENTRYTOWER_WALL_CLOCK": "600",
    }
    config = load_config(file, environment=environment)
    assert config.default_model == "b/env"
    assert config.model_for("triage") == "a/triage" and config.model_for("verify") == "b/verify"
    assert config.budget.max_tokens == 3_000_000 and config.budget.wall_clock_seconds == 600
    # --model runs one model everywhere: it clears the role overrides.
    config = load_config(file, environment=environment, model="c/option", max_tokens=1_000_000, max_cost_usd=2.5)
    assert set(config.models.values()) == {"c/option"}
    assert config.budget.max_tokens == 1_000_000 and config.budget.max_cost_usd == 2.5
    assert any(source.startswith("options:") for source in config.sources)


def test_the_config_variable_names_the_file(tmp_path: Path) -> None:
    file = write(tmp_path, "[budget]\nwall_clock_seconds = 900\n")
    config = load_config(environment={"SENTRYTOWER_CONFIG": str(file)})
    assert config.budget.wall_clock_seconds == 900


@pytest.mark.parametrize(
    "text",
    [
        '[provider]\napi_key = "not-a-real-key-123"\n',
        '[provider.headers]\nAuthorization = "Bearer x"\n',
        '[policies."m/x"]\ntoken = "abc"\n',
        "[unknown]\nx = 1\n",
        '[models]\nwizard = "m/x"\n',
        '[models]\ndefault = "has space"\n',
        "[budget]\nmax_tokens = 10\n",
        '[budget]\nmax_cost_usd = "lots"\n',
        "[funnel]\nmax_findings_total = 0\n",
        "[funnel]\nnot_a_parameter = 1\n",
        "[funnel]\nlarge_repo_files = 10\n",
        '[provider]\nbase_url = "ftp://example"\n',
        '[policies."m/x"]\nreasoning_effort = "extreme"\n',
        "not toml = = =\n",
    ],
)
def test_an_invalid_file_is_an_error_that_shows_no_secret(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError) as error:
        load_config(write(tmp_path, text), environment={})
    assert "not-a-real-key-123" not in str(error.value) and "Bearer x" not in str(error.value)


def test_the_key_comes_from_the_environment_only() -> None:
    config = load_config(environment={})
    assert config.api_key({}) == (None, None)
    assert config.api_key({"OPENROUTER_API_KEY": " key-2 "}) == ("key-2", "OPENROUTER_API_KEY")
    assert config.api_key({"SENTRYTOWER_API_KEY": "key-1", "OPENROUTER_API_KEY": "key-2"}) == ("key-1", "SENTRYTOWER_API_KEY")
    record = config.record()
    assert "key-1" not in repr(record) and record["provider"]["api_key_env"] == ["SENTRYTOWER_API_KEY", "OPENROUTER_API_KEY"]


def test_a_local_endpoint_can_need_no_key(tmp_path: Path) -> None:
    text = '[provider]\nbase_url = "http://localhost:8000/v1"\nrequire_api_key = false\napi_key_env = ["LOCAL_KEY"]\n'
    config = load_config(write(tmp_path, text), environment={})
    assert not config.provider.require_api_key and config.provider.api_key_env == ("LOCAL_KEY",)


def test_policy_tables_change_or_add_a_policy(tmp_path: Path) -> None:
    text = """
[models]
default = "local/qwen"

[policies."local/qwen"]
reasoning_effort = "none"
max_completion_tokens = 8192
token_field = "max_tokens"
context_window = 32768

[policies."deepseek/deepseek-v4.1-flash-1017"]
max_completion_tokens = 32768
"""
    config = load_config(write(tmp_path, text), environment={})
    local = config.policies(["local/qwen"])["local/qwen"]
    assert local.reasoning_effort is None and local.token_field == "max_tokens" and local.max_completion_tokens == 8192
    default = config.policies([DEFAULT_MODEL])[DEFAULT_MODEL]
    assert default.max_completion_tokens == 32_768 and default.provider is not None and default.attempt_timeout_seconds == 300.0


def test_funnel_parameters_are_checked(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, "[funnel]\nmax_findings_total = 8\n[router]\nlarge_repo_files = 500\n"), environment={})
    parameters = config.parameters()
    assert parameters.max_findings_total == 8 and parameters.large_repo_files == 500


def test_the_roles_are_documented() -> None:
    assert FUNNEL_ROLES == ("rating", "unit_check", "triage", "verify", "deep_check", "free_roaming")
    assert ROLES[-1] == "agent"


def test_the_user_settings_file_and_a_profile_are_found_in_the_config_folder(tmp_path: Path) -> None:
    folder = tmp_path / "config" / "sentrytower"
    (folder / "profiles").mkdir(parents=True)
    (folder / "config.toml").write_text('[ui]\nagent_name = "Ada"\nagent_color = "plum"\ntheme = "light"\n')
    (folder / "profiles" / "work.toml").write_text('[models]\ndefault = "vendor/work-model"\n')
    environment = {"XDG_CONFIG_HOME": str(tmp_path / "config")}
    config = load_config(environment=environment)
    assert (config.ui.agent_name, config.ui.agent_color, config.ui.theme) == ("Ada", "plum", "light")
    assert config.sources[1] == f"file: {folder / 'config.toml'}" and config.record()["agent"] == {"name": "Ada", "color": "plum"}
    # A profile replaces the user's file; the variable and the option name it.
    assert load_config(environment=environment, profile="work").default_model == "vendor/work-model"
    profiled = load_config(environment={**environment, "SENTRYTOWER_PROFILE": "work"})
    assert profiled.default_model == "vendor/work-model" and profiled.ui.agent_name == "Juno"
    with pytest.raises(ConfigError, match="sentrytower setup --profile home"):
        load_config(environment=environment, profile="home")
    with pytest.raises(ConfigError, match="profile name"):
        load_config(environment=environment, profile="../escape")
    # Without a file: the defaults.
    assert load_config(environment={"XDG_CONFIG_HOME": str(tmp_path / "empty")}).sources == ("defaults",)


def test_an_environment_without_a_settings_folder_takes_the_folder_of_the_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    (home / ".config" / "sentrytower").mkdir(parents=True)
    (home / ".config" / "sentrytower" / "config.toml").write_text("[budget]\nmax_tokens = 5000000\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    # The XDG_CONFIG_HOME of the process comes before its home folder: the file under the home folder is not read.
    assert config_home({}) == tmp_path / "xdg" / "sentrytower"
    assert load_config(environment={}).sources == ("defaults",)
    # An environment that names a home folder keeps it.
    assert config_home({"HOME": str(home)}) == home / ".config" / "sentrytower"
    assert load_config(environment={"HOME": str(home)}).budget.max_tokens == 5_000_000


@pytest.mark.parametrize(
    "text",
    [
        '[ui]\nagent_color = "teal"\n',
        '[ui]\ntheme = "sepia"\n',
        '[ui]\nagent_name = ""\n',
        '[ui]\nagent_name = "a name that is much longer than twenty-four"\n',
        '[ui]\nmascot = "cat"\n',
        "[provider]\nkeychain = 1\n",
        '[run]\nfail_on = "severe"\n',
        '[run]\nout_dir = ""\n',
    ],
)
def test_invalid_values_of_the_new_keys_are_errors(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text), environment={})


def test_the_results_folder_and_the_fail_on_threshold_come_from_the_run_table(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, '[run]\nout_dir = "~/results"\nfail_on = "high"\n'), environment={})
    assert config.out_dir == "~/results" and config.fail_on == "high"
    assert load_config(write(tmp_path, '[run]\nfail_on = "off"\n'), environment={}).fail_on is None


def test_a_fast_and_an_agent_model_split_the_roles() -> None:
    config = load_config(environment={}, fast_model="vendor/fast", agent_model="vendor/strong")
    assert all(config.model_for(role) == "vendor/fast" for role in FAST_ROLES)
    assert all(config.model_for(role) == "vendor/strong" for role in AGENT_ROLES)
    assert set(FAST_ROLES) | set(AGENT_ROLES) == set(ROLES) and not set(FAST_ROLES) & set(AGENT_ROLES)
    # --model runs one model everywhere, then --fast-model changes the short calls.
    config = load_config(environment={}, model="vendor/one", fast_model="vendor/fast")
    assert config.model_for("agent") == "vendor/one" and config.model_for("triage") == "vendor/fast"


def test_the_keychain_gives_the_key_only_when_the_settings_ask_and_the_environment_has_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sentrytower.ui import keychain

    monkeypatch.setattr(keychain, "read", lambda: "key-from-keychain")
    assert load_config(environment={}).api_key({}) == (None, None)
    config = load_config(write(tmp_path, "[provider]\nkeychain = true\n"), environment={})
    assert config.api_key({}) == ("key-from-keychain", "keychain")
    assert config.api_key({"SENTRYTOWER_API_KEY": "key-1"}) == ("key-1", "SENTRYTOWER_API_KEY")
    assert "key-from-keychain" not in repr(config.record())


def test_write_config_checks_the_document_and_keeps_the_file_private(tmp_path: Path) -> None:
    import stat

    path = tmp_path / "settings" / "config.toml"
    document = {
        "ui": {"agent_name": "Juno", "agent_color": "sand"},
        "models": {"default": DEFAULT_MODEL},
        "policies": {"vendor/model:free": {"reasoning_effort": "none", "context_window": 32_768}},
    }
    write_config(path, document, header="written by a test")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text().startswith("# written by a test\n")
    config = load_config(path, environment={})
    assert config.policies(["vendor/model:free"])["vendor/model:free"].context_window == 32_768 and config.ui.agent_name == "Juno"
    with pytest.raises(ConfigError, match="must not hold a key"):
        write_config(tmp_path / "bad.toml", {"provider": {"api_key": "not-a-real-key-123"}})
    with pytest.raises(ConfigError):
        write_config(tmp_path / "bad.toml", {"ui": {"agent_color": "teal"}})
    assert not (tmp_path / "bad.toml").exists()


def test_the_run_table_can_turn_off_the_report_in_the_browser(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, "[run]\nopen_report = false\n"), environment={})
    assert config.open_report is False
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, '[run]\nopen_report = "no"\n'), environment={})


def test_the_cost_cap_sets_the_depth_and_max_tokens_limits_it() -> None:
    capped = load_config(environment={}, max_cost_usd=5.0)
    funnel, agent = capped.token_plan("funnel"), capped.token_plan("agent")
    assert funnel.source == agent.source == "cost cap"
    # $5 buys two and a half standard runs on both routes with the default model.
    assert funnel.tokens == agent.tokens == 50_000_000 and funnel.depth == agent.depth == 2.5
    limited = load_config(environment={}, max_cost_usd=5.0, max_tokens=20_000_000)
    assert limited.token_plan("funnel").tokens == 20_000_000 and limited.token_plan("funnel").depth == 1.0
    small = load_config(environment={}, max_cost_usd=0.5, max_tokens=20_000_000)
    assert small.token_plan("funnel").source == "cost cap" and small.token_plan("funnel").tokens < 6_000_000


def test_two_dollars_is_the_default_cap_and_zero_means_no_cap(tmp_path: Path) -> None:
    # The command line, the file and the environment: 0 is no cap; nothing gives the default cap.
    assert load_config(environment={}).cost_cap("funnel") == 2.0
    assert load_config(environment={}, max_cost_usd=0).cost_cap("funnel") is None
    assert load_config(write(tmp_path, "[budget]\nmax_cost_usd = 0\n"), environment={}).cost_cap("agent") is None
    assert load_config(environment={"SENTRYTOWER_MAX_COST_USD": "0"}).cost_cap("funnel") is None
    assert load_config(environment={"SENTRYTOWER_MAX_COST_USD": "7.5"}).cost_cap("funnel") == 7.5
    no_cap = load_config(environment={}, max_cost_usd=0)
    assert no_cap.token_plan("funnel").tokens == 20_000_000 and no_cap.token_plan("funnel").source == "default"


def test_a_cap_needs_the_prices_of_each_model_of_the_route(tmp_path: Path) -> None:
    file = write(tmp_path, '[models]\ndefault = "local/qwen"\n')
    # Without prices and without a cap of a setting: no cap, the standard ceiling, and a note that says so.
    config = load_config(file, environment={})
    assert config.cost_cap("funnel") is None and config.token_plan("funnel").tokens == 20_000_000
    assert "no cost cap" in str(config.unpriced_note("funnel")) and "local/qwen" in str(config.unpriced_note("funnel"))
    config.check_cost_cap("funnel")
    # A cap that the person gives is an error that names the model and the fix.
    capped = load_config(file, environment={}, max_cost_usd=3.0)
    with pytest.raises(ConfigError) as error:
        capped.check_cost_cap("funnel")
    assert "local/qwen" in str(error.value) and "[policies" in str(error.value) and "--max-cost-usd 0" in str(error.value)
    # With the prices of a model of a list (as setup saves them), the default cap applies.
    priced = write(
        tmp_path, '[models]\ndefault = "local/qwen"\n[policies."local/qwen"]\ninput_cost_per_million = 0.2\noutput_cost_per_million = 0.8\n'
    )
    assert load_config(priced, environment={}).cost_cap("funnel") == 2.0


def test_a_cap_must_pay_for_one_model_call_at_its_worst_case(tmp_path: Path) -> None:
    # The default model: a call can reserve 65,536 completion tokens at $0.60 for one million, about $0.04.
    with pytest.raises(ConfigError) as error:
        load_config(environment={}, max_cost_usd=0.03).check_cost_cap("funnel")
    message = str(error.value)
    assert "the cost cap of $0.03 cannot pay for one model call" in message and DEFAULT_MODEL in message
    assert "up to $0.0393" in message and "give a cap of at least $0.04" in message
    load_config(environment={}, max_cost_usd=0.04).check_cost_cap("agent")
    # The quick depth ($0.50) stays valid on both routes.
    for route in ("funnel", "agent"):
        load_config(environment={}, max_cost_usd=0.5).check_cost_cap(route)
    # The default cap too: one call of an expensive model can cost more than $2.
    large = write(
        tmp_path,
        '[models]\ndefault = "vendor/large"\n[policies."vendor/large"]\n'
        "max_completion_tokens = 100_000\ninput_cost_per_million = 15\noutput_cost_per_million = 75\n",
    )
    with pytest.raises(ConfigError) as default:
        load_config(large, environment={}).check_cost_cap("funnel")
    assert "the default cost cap of $2.00" in str(default.value) and "at least $7.51" in str(default.value)
    load_config(large, environment={}, max_cost_usd=0).check_cost_cap("funnel")
