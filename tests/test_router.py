"""The size rule of the hybrid: 1,000 counted files or fewer go to the funnel, more go to the single agent."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentrytower import router
from sentrytower.funnel.orchestrator import repository_files
from sentrytower.router import LARGE_REPO_FILES, ROUTE_AGENT, ROUTE_FUNNEL, count_files, decide, route_of, skipped_folder


def counted_tree(root: Path, count: int) -> Path:
    """``count`` counted files, and files in version-control folders (at any depth) that do not count."""
    for index in range(count):
        path = root / "src" / f"d{index % 7}" / f"file_{index:04d}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{index}\n")
    for name in (
        ".git/HEAD",
        ".git/objects/aa/bb",
        ".hg/store/data",
        ".svn/entries",
        "nested/.git/config",
        "nested/deep/.svn/wc.db",
        "src/.hg/x",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
    return root


def test_the_threshold_is_1000_files() -> None:
    assert LARGE_REPO_FILES == 1000
    assert [route_of(files) for files in (0, 1, 999, 1000, 1001, 50_000)] == [ROUTE_FUNNEL] * 4 + [ROUTE_AGENT] * 2


@pytest.mark.parametrize(("count", "route"), [(1000, ROUTE_FUNNEL), (1001, ROUTE_AGENT)])
def test_the_edge_1000_and_1001_counted_files(tmp_path: Path, count: int, route: str) -> None:
    root = counted_tree(tmp_path / "repo", count)
    decision = decide(root)
    assert (decision.route, decision.files_counted, decision.counted_up_to, decision.threshold) == (route, count, 1001, 1000)
    record = decision.record()
    assert record["rule"] == "size-route-v2" and record["route"] == route
    # The version-control folders are skipped folders. A count that stops at the limit saw only some of them.
    skipped = record["skipped"]
    if route == ROUTE_FUNNEL:
        assert skipped == {"folders": 6, "files": 7, "names": [".git", ".hg", ".svn"]}
    else:
        assert skipped["folders"] <= 6 and skipped["files"] <= 7 and set(skipped["names"]) <= {".git", ".hg", ".svn"}


def test_version_control_folders_do_not_count_at_any_depth(tmp_path: Path) -> None:
    root = counted_tree(tmp_path / "repo", 10)
    assert repository_files(root, 10_000) == 10
    # Without the version-control folders the count is the same; with them as plain names it grows.
    (root / "git").mkdir()
    (root / "git" / "x").write_text("x\n")
    (root / ".github").mkdir()
    (root / ".github" / "y").write_text("y\n")
    assert repository_files(root, 10_000) == 12


def test_the_count_stops_at_the_limit_and_ignores_links(tmp_path: Path) -> None:
    root = counted_tree(tmp_path / "repo", 1500)
    assert repository_files(root, 1001) == 1001
    outside = counted_tree(tmp_path / "outside", 5)
    (root / "link-to-folder").symlink_to(outside, target_is_directory=True)
    (root / "link-to-file").symlink_to(outside / "src" / "d0" / "file_0000.txt")
    small = counted_tree(tmp_path / "small", 3)
    (small / "link").symlink_to(outside / "src", target_is_directory=True)
    assert repository_files(small, 100) == 3


def test_an_unreadable_folder_does_not_count(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    root = counted_tree(tmp_path / "repo", 4)
    locked = root / "locked"
    locked.mkdir()
    (locked / "a").write_text("a\n")
    locked.chmod(0)
    try:
        assert repository_files(root, 100) == 4
    finally:
        locked.chmod(0o755)


def test_another_threshold_is_a_configuration_value(tmp_path: Path) -> None:
    root = counted_tree(tmp_path / "repo", 5)
    assert decide(root, 5).route == ROUTE_FUNNEL
    assert decide(root, 4).route == ROUTE_AGENT
    with pytest.raises(ValueError):
        decide(root, 0)


def write_files(root: Path, paths: list[str]) -> Path:
    for name in paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
    return root


# One file in each folder that holds no code of the project, at the root and deeper.
NOT_PROJECT_CODE = [
    "node_modules/react/index.js",
    "web/node_modules/left-pad/index.js",
    "vendor/github.com/x/y.go",
    "bower_components/a/a.js",
    "jspm_packages/b/b.js",
    ".venv/bin/python",
    "venv/lib/site.py",
    "tools/env/lib/python3.12/os.py",
    "tools/env/pyvenv.cfg",
    "__pycache__/m.cpython-312.pyc",
    "lib/python3.12/site-packages/six.py",
    "dist/app.min.js",
    "build/out.o",
    "target/debug/app",
    ".next/server/page.js",
    ".nuxt/app.js",
    ".svelte-kit/output/x.js",
    ".gradle/caches/x.bin",
    "ios/Pods/AFNetworking/AF.m",
    "ios/Carthage/Build/x.framework",
    ".tox/py312/bin/python",
    "coverage/lcov.info",
    "third_party/zlib/zlib.c",
    "src/generated/api.py",
    ".git/HEAD",
    ".hg/store/data",
    ".svn/entries",
    ".bzr/branch",
    "CVS/Entries",
    ".jj/repo/store",
    "app/build/intermediates/R.java",
    "packages/ui/dist/index.js",
]
# Code of the project, also in folders that look like build output but are source code.
PROJECT_CODE = [
    "app.py",
    "web/index.js",
    "src/build/compile.py",
    "pkg/build/build.go",
    "internal/out/writer.go",
    "app/build.gradle",
    "app/src/main/java/App.java",
    "packages/ui/package.json",
    "packages/ui/src/button.js",
    "docs/guide.md",
    "tests/test_app.py",
    ".github/workflows/ci.yml",
]


def test_dependency_vendor_build_and_vcs_folders_do_not_count(tmp_path: Path) -> None:
    root = write_files(tmp_path / "repo", NOT_PROJECT_CODE + PROJECT_CODE)
    found = count_files(root, 10_000)
    assert found.files == len(PROJECT_CODE)
    assert found.skipped_folders == len(NOT_PROJECT_CODE) - 1  # tools/env holds two files
    assert found.skipped_files == len(NOT_PROJECT_CODE)
    assert set(found.skipped_names) == {
        "node_modules",
        "vendor",
        "bower_components",
        "jspm_packages",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
        "target",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".gradle",
        "Pods",
        "Carthage",
        ".tox",
        "coverage",
        "third_party",
        "generated",
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "CVS",
        ".jj",
    }
    # The large-repository rule of the funnel counts the same files.
    assert repository_files(root, 10_000) == len(PROJECT_CODE)


def test_a_build_folder_below_a_source_folder_counts_unless_a_build_file_is_next_to_it() -> None:
    assert skipped_folder("dist", "dist") and skipped_folder("target", "crates/core/target")
    assert not skipped_folder("build", "src/build") and not skipped_folder("dist", "packages/ui/dist", {"src", "README.md"})
    assert skipped_folder("dist", "packages/ui/dist", {"package.json", "src"}) and skipped_folder("build", "app/build", {"build.gradle"})
    assert skipped_folder("obj", "src/App/obj", {"App.csproj"}) and skipped_folder("target", "app/target", {"pom.xml"})
    assert not skipped_folder("src", "src", {"package.json"}) and not skipped_folder("docs", "docs") and not skipped_folder("test", "test")


def test_the_root_always_counts_also_as_a_virtual_environment_or_a_build_folder(tmp_path: Path) -> None:
    root = write_files(tmp_path / "build", ["pyvenv.cfg", "a.py", "lib/b.py"])
    assert count_files(root, 100).files == 3


def test_a_small_app_with_node_modules_goes_to_the_funnel(tmp_path: Path) -> None:
    root = counted_tree(tmp_path / "app", 40)
    write_files(root, [f"node_modules/pkg{index // 50}/file{index}.js" for index in range(2500)])
    decision = decide(root)
    assert decision.route == ROUTE_FUNNEL and decision.files_counted == 40
    skipped = decision.record()["skipped"]
    assert skipped["files"] == 1001 and "node_modules" in skipped["names"]


def test_the_count_of_the_skipped_folders_stops_at_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = counted_tree(tmp_path / "app", 5)
    write_files(root, [f"node_modules/pkg{index // 10}/file{index}.js" for index in range(5000)])
    calls: list[str] = []
    scandir = os.scandir

    def counting(path: str) -> os._ScandirIterator[str]:  # type: ignore[name-defined]
        calls.append(path)
        return scandir(path)

    monkeypatch.setattr(router.os, "scandir", counting)
    found = count_files(root, 1001)
    # 500 folders of 10 files: the count reads about 1001 / 10 of them, then stops.
    assert found.files == 5 and found.skipped_files == 1001
    assert len(calls) < 150


def test_the_names_of_skipped_folders_are_capped(tmp_path: Path) -> None:
    root = write_files(tmp_path / "repo", [f"env{index:02d}/pyvenv.cfg" for index in range(60)] + ["a.py"])
    found = count_files(root, 1001)
    assert found.files == 1 and found.skipped_folders == 60 and len(found.skipped_names) == router.MAX_SKIPPED_NAMES
