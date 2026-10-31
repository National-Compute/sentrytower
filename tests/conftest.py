"""Fixtures of the test suite: a repository, a fake model, a fake Pi CLI and an audit runner."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes import FakeModel, fake_pi_package, fake_tools
from sentrytower.audit import AuditOutcome, AuditRequest, Log, run_audit
from sentrytower.config import load_config

KEY = "test-provider-key-0000000000000000"


@dataclass
class Rig:
    """A test bench for whole audits: the paths, the fake model and the environment."""

    base: Path
    pi: Path
    tools: dict[str, Path]
    log: Path
    environment: dict[str, str] = field(default_factory=dict)

    def env(self, **extra: str) -> dict[str, str]:
        return {**self.environment, **extra}

    def audit(
        self,
        repository: Path,
        *,
        fake: FakeModel | None = None,
        out: Path | None = None,
        state: Path | None = None,
        extra_env: dict[str, str] | None = None,
        config_file: Path | None = None,
        **options: Any,
    ) -> tuple[AuditOutcome, FakeModel]:
        fake = fake or FakeModel()
        environment = self.env(**(extra_env or {}))
        config = load_config(config_file, environment=environment, **options)
        request = AuditRequest(repository=repository, out_dir=out or self.base / "out", keep_state=state is not None, state_dir=state)
        outcome = run_audit(config, request, log=Log(quiet=True), environment=environment, transport=fake.transport)
        return outcome, fake

    def pi_log(self) -> list[dict[str, Any]]:
        if not self.log.is_file():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _private_user_folders(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No test reads or writes the settings, the state, the cache or the keychain of the person who runs the tests."""
    home = tmp_path_factory.mktemp("user")
    for name, folder in (("XDG_CONFIG_HOME", "config"), ("XDG_STATE_HOME", "state"), ("XDG_CACHE_HOME", "cache")):
        monkeypatch.setenv(name, str(home / folder))
    for name in ("SENTRYTOWER_CONFIG", "SENTRYTOWER_PROFILE", "SENTRYTOWER_RECORD", "SENTRYTOWER_THEME", "SENTRYTOWER_PLAIN"):
        monkeypatch.delenv(name, raising=False)
    from sentrytower.ui import keychain

    monkeypatch.setattr(keychain, "backend", lambda: None)
    return home


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    pi = fake_pi_package(tmp_path / "fake-pi")
    tools = fake_tools(tmp_path / "fake-tools")
    log = tmp_path / "pi-log.jsonl"
    environment = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "SENTRYTOWER_API_KEY": KEY,
        "SENTRYTOWER_PI": str(pi),
        "SENTRYTOWER_RG": str(tools["rg"]),
        "SENTRYTOWER_FD": str(tools["fd"]),
        "FUNNEL_INVENTORY_SCANNER": "python",
        "FAKE_PI_LOG": str(log),
        "FAKE_PI_SLEEP": "0.2",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if os.environ.get("COVERAGE_PROCESS_START"):
        environment["COVERAGE_PROCESS_START"] = os.environ["COVERAGE_PROCESS_START"]
    return Rig(base=tmp_path, pi=pi, tools=tools, log=log, environment=environment)


@pytest.fixture
def write_repo(tmp_path: Path) -> Callable[..., Path]:
    from synthetic import write_repository

    def write(files: dict[str, str], name: str = "repo") -> Path:
        return write_repository(tmp_path / name, files)

    return write
