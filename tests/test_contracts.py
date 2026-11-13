"""The vendored data contracts: each file is the released file, and scripts/vendor_contracts.py vendors only a checked release."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
from pathlib import Path

import jsonschema
import pytest

from sentrytower.contracts import FINDING_SCHEMA_ID, schema_documents
from sentrytower.contracts.nc_contracts import CONTRACTS_VERSION

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "src" / "sentrytower" / "contracts"
# The files of SentryTower in the folder; every other file is in SHA256SUMS.
OWN_FILES = {"__init__.py", "SHA256SUMS", "VERSION", "BUNDLE.sha256"}
_SPEC = importlib.util.spec_from_file_location("vendor_contracts", ROOT / "scripts" / "vendor_contracts.py")
assert _SPEC is not None and _SPEC.loader is not None
vendor = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = vendor
_SPEC.loader.exec_module(vendor)


def manifest(folder: Path = VENDORED) -> dict[str, str]:
    lines = (folder / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    return {path: digest for digest, path in (line.split("  ", 1) for line in lines)}


def vendored_files(folder: Path) -> set[str]:
    return {
        path.relative_to(folder).as_posix()
        for path in folder.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.relative_to(folder).as_posix() not in OWN_FILES
    }


def test_each_vendored_file_is_the_file_of_the_manifest() -> None:
    listed = manifest()
    assert vendored_files(VENDORED) == set(listed)
    for path, digest in listed.items():
        assert hashlib.sha256((VENDORED / path).read_bytes()).hexdigest() == digest, f"{path} is not the released file"
    for required in (
        "schemas/finding/1.json",
        "nc_contracts/sarif.py",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "NOTICE",
        "schemas/vendor/osv-schema/LICENSE",
    ):
        assert required in listed


def test_the_version_files_name_the_vendored_release() -> None:
    version = (VENDORED / "VERSION").read_text(encoding="utf-8").strip()
    assert version == CONTRACTS_VERSION
    assert re.fullmatch(
        rf"[0-9a-f]{{64}}  contracts-{re.escape(version)}\.tar\.gz\n", (VENDORED / "BUNDLE.sha256").read_text(encoding="utf-8")
    )


def test_each_contract_schema_is_a_valid_schema_under_its_id() -> None:
    documents = schema_documents()
    assert FINDING_SCHEMA_ID in documents
    for uri, document in documents.items():
        jsonschema.Draft202012Validator.check_schema(document)
        if "$id" in document and "/vendor/" not in uri:
            assert document["$id"] == uri


def make_bundle(folder: Path, files: dict[str, bytes], version: str = CONTRACTS_VERSION, *, sums: dict[str, str] | None = None) -> Path:
    """A release in ``folder``: contracts-<version>.tar.gz with its inner SHA256SUMS, and the SHA256SUMS of the tarball."""
    inner = sums if sums is not None else {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
    members = {**files, "SHA256SUMS": "".join(f"{digest}  {path}\n" for path, digest in sorted(inner.items())).encode()}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, data in sorted(members.items()):
            info = tarfile.TarInfo(path if path.startswith(("/", "..")) else f"contracts-{version}/{path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    folder.mkdir(parents=True, exist_ok=True)
    bundle = folder / f"contracts-{version}.tar.gz"
    bundle.write_bytes(buffer.getvalue())
    (folder / "SHA256SUMS").write_text(f"{hashlib.sha256(buffer.getvalue()).hexdigest()}  {bundle.name}\n", encoding="utf-8")
    return bundle


def released_files() -> dict[str, bytes]:
    """The files of a release as the bundle holds them: the module under python/, and a README that SentryTower does not vendor."""
    files = {}
    for path in manifest():
        bundle_path = "python/" + path if path.startswith("nc_contracts/") else path
        files[bundle_path] = (VENDORED / path).read_bytes()
    return files | {"README.md": b"# Data contracts\n"}


def test_vendoring_a_release_writes_the_vendored_files(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path / "release", released_files())
    dest = tmp_path / "contracts"
    dest.mkdir()
    (dest / "__init__.py").write_text("# SentryTower's own\n")
    (dest / "SHA256SUMS").write_text(f"{'0' * 64}  schemas/stale/1.json\n")
    (dest / "schemas" / "stale").mkdir(parents=True)
    (dest / "schemas" / "stale" / "1.json").write_text("{}")
    assert vendor.main([str(bundle), "--dest", str(dest)]) == 0
    assert manifest(dest) == manifest()
    assert all((dest / path).read_bytes() == (VENDORED / path).read_bytes() for path in manifest())
    # The files of the old manifest are gone, the file of SentryTower stays, and the README of the bundle is not vendored.
    assert not (dest / "schemas" / "stale").exists() and (dest / "__init__.py").read_text() == "# SentryTower's own\n"
    assert vendored_files(dest) == set(manifest())
    assert (dest / "VERSION").read_text() == f"{CONTRACTS_VERSION}\n"
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert (dest / "BUNDLE.sha256").read_text() == f"{digest}  {bundle.name}\n"


@pytest.mark.parametrize("defect", ["tarball digest", "file digest", "unlisted file", "path outside", "link", "version"])
def test_a_release_that_fails_a_check_changes_nothing(tmp_path: Path, defect: str, capsys: pytest.CaptureFixture[str]) -> None:
    files = released_files()
    release = tmp_path / "release"
    if defect == "file digest":
        sums = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
        files["schemas/finding/1.json"] = files["schemas/finding/1.json"].replace(b"Finding", b"Findings")
        bundle = make_bundle(release, files, sums=sums)
    elif defect == "unlisted file":
        sums = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
        bundle = make_bundle(release, files | {"schemas/extra/1.json": b"{}"}, sums=sums)
    elif defect == "path outside":
        bundle = make_bundle(release, files | {"../escape.py": b"print()"})
    elif defect == "version":
        bundle = make_bundle(release, files, version="9.9.9")
    else:
        bundle = make_bundle(release, files)
    if defect == "tarball digest":
        (release / "SHA256SUMS").write_text(f"{'0' * 64}  {bundle.name}\n")
    if defect == "link":
        buffer = io.BytesIO(bundle.read_bytes())
        with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
            members = [(member, archive.extractfile(member)) for member in archive.getmembers()]
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w:gz") as rewritten:
                for member, handle in members:
                    rewritten.addfile(member, io.BytesIO(handle.read()) if handle else None)
                link = tarfile.TarInfo(f"contracts-{CONTRACTS_VERSION}/schemas/link.json")
                link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
                rewritten.addfile(link)
        bundle.write_bytes(out.getvalue())
        (release / "SHA256SUMS").write_text(f"{hashlib.sha256(out.getvalue()).hexdigest()}  {bundle.name}\n")
    dest = tmp_path / "contracts"
    dest.mkdir()
    (dest / "keep.txt").write_text("unchanged")
    assert vendor.main([str(bundle), "--dest", str(dest)]) == 1
    assert sorted(path.name for path in dest.iterdir()) == ["keep.txt"]
    assert "vendor_contracts:" in capsys.readouterr().err


def test_the_findings_schema_names_the_contract_finding() -> None:
    schema = json.loads((ROOT / "src" / "sentrytower" / "schemas" / "findings-v2.schema.json").read_text(encoding="utf-8"))
    assert {"$ref": FINDING_SCHEMA_ID} in schema["properties"]["findings"]["items"]["allOf"]
    assert not (ROOT / "src" / "sentrytower" / "schemas" / "findings-v1.schema.json").exists()
