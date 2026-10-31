"""Each install pin and version reference of the release files names the package version.

A release moves the version in many files: the install commands, the GitHub
Action, the image tags, the citation and the examples. This test finds each
reference and fails when one names another version, so that a release
cannot ship with a stale pin.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

from sentrytower import __version__

ROOT = Path(__file__).resolve().parents[1]

# A version as the package writes it (0.2.0, 0.2.0rc2, 0.2.0.dev1) and the other forms that a stale pin can have
# (0.2.0-rc.1, 0.2.0-beta).
VERSION = r"(?P<version>\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|alpha|beta|pre|dev|post)\.?\d*)*)"
# Each kind of reference that names the version of SentryTower. A version of another tool (Pi 0.84.1,
# actions/checkout@v7) is not a reference: each pattern names SentryTower or a field of its own files.
PATTERNS = {
    "a git or Action pin": re.compile(r"(?i)\bsentrytower(?:\.git)?@v" + VERSION),
    "an image tag": re.compile(r"(?i)\bsentrytower:" + VERSION),
    "a package pin": re.compile(r"(?i)\bsentrytower\s*==\s*" + VERSION),
    "a distribution file": re.compile(r"(?i)\bsentrytower-" + VERSION + r"(?=-py3|\.tar\.gz)"),
    "a version key": re.compile(r"(?m)^version:\s*[\"']?" + VERSION),
    "the image label": re.compile(r"org\.opencontainers\.image\.version=\"" + VERSION),
    "the BibTeX version": re.compile(r"\bversion\s*=\s*\{" + VERSION),
    "the tool of an example output": re.compile(r"\"name\":\s*\"SentryTower\",\s*\"version\":\s*\"" + VERSION),
}
# The major tag of the Action (@v1) moves with each release: it is right when it names the major version.
MAJOR_TAG = re.compile(r"(?i)\bsentrytower@v(?P<major>\d+)(?![\d.])")

# Left out on purpose. These files state history or hold the versions of other software; each version in
# them is right for its time, and a release must not rewrite it.
EXCLUDED = {
    "CHANGELOG.md": "the change history: each section names the version that it describes",
    "docs/benchmarks.md": "the record of the measured runs: it names the internal builds that ran (the owner assesses the benchmark pages)",
    "benchmarks": "the material of the measured runs of internal builds",
    "docs/assets": "images: recordings of earlier sessions and the benchmark art",
    "src": "the source of the version; the tests below compare it with pyproject.toml",
    "tests": "fixtures that hold versions on purpose, and this test",
}
# Folders of tools and of local runs, never part of a release.
SKIPPED = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", "sentrytower-results"}
TEXT_SUFFIXES = {".md", ".yml", ".yaml", ".toml", ".cff", ".txt", ".conf", ".json", ".sh", ".py"}
TEXT_NAMES = {"Makefile", "Dockerfile", "NOTICE"}
# The files that must hold a pin: a scan that finds none of them has stopped working.
PINNED = (
    "README.md",
    "CITATION.cff",
    "Makefile",
    "action.yml",
    "docker-compose.yml",
    "docker/Dockerfile",
    "docs/deployment.md",
    "examples/github-workflow.yml",
)


@dataclass(frozen=True)
class Reference:
    path: str
    line: int
    kind: str
    version: str


def package_version(root: Path = ROOT) -> str:
    return str(tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])


def scanned_files(root: Path) -> list[Path]:
    """The text files below ``root``, without the excluded paths and the folders of tools."""
    excluded = {root / name for name in EXCLUDED}
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIPPED or (part.startswith(".") and part != ".github") for part in relative.parts):
            continue
        if any(path == item or item in path.parents for item in excluded) or not path.is_file():
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return files


def references(root: Path) -> list[Reference]:
    """Each version reference of SentryTower in the scanned files."""
    found = []
    for path in scanned_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                found.append(Reference(path.relative_to(root).as_posix(), line, kind, match.group("version")))
    return found


def stale(root: Path, version: str) -> list[Reference]:
    """The references that name another version, and the major tags of another major version."""
    wrong = [reference for reference in references(root) if reference.version != version]
    major = version.partition(".")[0]
    for path in scanned_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in MAJOR_TAG.finditer(text):
            if match.group("major") != major:
                line = text.count("\n", 0, match.start()) + 1
                wrong.append(Reference(path.relative_to(root).as_posix(), line, "a major tag of the Action", f"v{match.group('major')}"))
    return wrong


def test_the_package_and_its_metadata_have_one_version() -> None:
    assert __version__ == package_version()
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert re.search(r"(?m)^date-released: \d{4}-\d{2}-\d{2}$", citation)


def test_each_pin_names_the_package_version() -> None:
    version = package_version()
    wrong = stale(ROOT, version)
    assert not wrong, f"these references do not name {version}:\n" + "\n".join(
        f"  {item.path}:{item.line}: {item.kind} names {item.version}" for item in wrong
    )


def test_the_security_policy_supports_the_release_line() -> None:
    major, minor, _ = package_version().split(".", 2)
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    rows = re.findall(r"(?m)^\| ([^|]+?) \| (Yes|No) \|$", policy)
    assert rows[0] == (f"{major}.{minor}.x", "Yes"), "the first row of the supported versions names the release line"
    assert [support for _, support in rows[1:]] == ["No"] * (len(rows) - 1)


@pytest.mark.parametrize("name", PINNED)
def test_the_release_files_hold_a_pin(name: str) -> None:
    assert any(item.path == name for item in references(ROOT)), f"{name} holds no version reference: the scan or the file changed"


def test_the_excluded_paths_are_left_out() -> None:
    files = {path.relative_to(ROOT).as_posix() for path in scanned_files(ROOT)}
    assert "README.md" in files and "docs/deployment.md" in files and "docker/Dockerfile" in files
    assert not any(name == item or name.startswith(item + "/") for name in files for item in EXCLUDED)


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("uv tool install git+https://github.com/National-Compute/sentrytower@v0.1.0\n", "a git or Action pin"),
        ("      - uses: National-Compute/sentrytower@v0.2.0rc2\n", "a git or Action pin"),
        ("docker run --rm ghcr.io/national-compute/sentrytower:0.1.0 --version\n", "an image tag"),
        ("IMAGE ?= sentrytower:0.2.0-rc.1\n", "an image tag"),
        ("pip install sentrytower==0.1.0\n", "a package pin"),
        ("uv tool install ./sentrytower-0.1.0-py3-none-any.whl\n", "a distribution file"),
        ("tar -xzf sentrytower-0.2.0rc2.tar.gz\n", "a distribution file"),
        ("cff-version: 1.2.0\nversion: 0.1.0\n", "a version key"),
        ('LABEL org.opencontainers.image.version="0.1.0"\n', "the image label"),
        ("  version = {0.1.0},\n", "the BibTeX version"),
        ('  "tool": {"name": "SentryTower", "version": "0.1.0"},\n', "the tool of an example output"),
    ],
)
def test_the_scan_finds_a_stale_pin(tmp_path: Path, text: str, kind: str) -> None:
    (tmp_path / "README.md").write_text(text)
    wrong = stale(tmp_path, "0.2.0")
    assert [(item.path, item.kind) for item in wrong] == [("README.md", kind)]


def test_the_scan_accepts_the_current_pins_and_other_tools(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "deployment.md").write_text(
        "uv tool install git+https://github.com/National-Compute/sentrytower@v0.2.0\n"
        "docker run --rm ghcr.io/national-compute/sentrytower:0.2.0 --version\n"
        "uv tool install ./sentrytower-0.2.0-py3-none-any.whl\n"
        "      - uses: National-Compute/sentrytower@v0\n"
        "      - uses: actions/checkout@v7\n"
        "npm install -g @earendil-works/pi-coding-agent@0.84.1\n"
        "cff-version: 1.2.0\n"
        "The default model of SentryTower 0.1 and 0.2.\n"
    )
    assert stale(tmp_path, "0.2.0") == [] and len(references(tmp_path)) == 3


def test_the_scan_finds_a_stale_major_tag(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("      - uses: National-Compute/sentrytower@v1\n")
    assert [item.version for item in stale(tmp_path, "0.2.0")] == ["v1"]


def test_the_scan_leaves_out_the_history(tmp_path: Path) -> None:
    for name in ("CHANGELOG.md", "docs/benchmarks.md", "benchmarks/README.md", ".venv/README.md"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("pipx install git+https://github.com/National-Compute/sentrytower@v0.0.1\n")
    assert stale(tmp_path, "0.2.0") == []


def test_each_package_of_the_pi_lockfile_carries_its_integrity() -> None:
    # npm ci checks the hash of each tarball against the lockfile; a package without an integrity value is not checked.
    lock = json.loads((ROOT / "docker" / "pi" / "package-lock.json").read_text(encoding="utf-8"))
    unchecked = [path for path, entry in lock["packages"].items() if path and not entry.get("link") and not entry.get("integrity")]
    assert unchecked == []
