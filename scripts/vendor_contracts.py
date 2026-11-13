#!/usr/bin/env python3
"""Vendor a release of the National Compute data contracts into ``src/sentrytower/contracts/``.

    python3 scripts/vendor_contracts.py path/to/contracts-<version>.tar.gz [--sums path/to/SHA256SUMS]

A release of the contracts is two files: ``contracts-<version>.tar.gz`` and
``SHA256SUMS``, the SHA-256 of the tarball (``--sums``; by default the
``SHA256SUMS`` next to the tarball). The script checks the tarball against
that digest, then checks each file of the tarball against the
``SHA256SUMS`` inside it. It reads the tarball in memory and changes no
file until every check passes. A member that is not a regular file or a
folder, or whose path leaves the bundle folder, fails the check.

It then replaces the vendored files of the destination (``--dest``):

- ``schemas/``: the JSON Schemas of the bundle, unchanged;
- ``nc_contracts/``: ``python/nc_contracts/`` of the bundle, unchanged;
- ``LICENSE-APACHE``, ``LICENSE-MIT`` and ``NOTICE`` of the bundle;
- ``SHA256SUMS``: the SHA-256 of each of these files, which
  ``tests/test_contracts.py`` checks;
- ``VERSION``: the version of the bundle;
- ``BUNDLE.sha256``: the SHA-256 of the tarball, in ``sha256sum`` format.

The files of SentryTower in the destination (``__init__.py``) stay. The
script removes only the files that the previous ``SHA256SUMS`` lists.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = ROOT / "src" / "sentrytower" / "contracts"
BUNDLE_NAME = re.compile(r"contracts-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)\.tar\.gz")
SUM_LINE = re.compile(r"(?P<digest>[0-9a-f]{64}) [ *](?P<path>\S.*)")
VERSION_LINE = re.compile(r'(?m)^CONTRACTS_VERSION = "(?P<version>[^"]+)"$')
# The files of the bundle that SentryTower uses: (path in the bundle, path in the destination).
LICENSE_FILES = ("LICENSE-APACHE", "LICENSE-MIT", "NOTICE")
MODULE_PREFIX = "python/nc_contracts/"
# A bundle is a few hundred kilobytes; this bound stops a gzip bomb before it fills the memory.
MAX_BYTES = 16 * 1024 * 1024


class BundleError(Exception):
    """The bundle failed a check; nothing was written."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_sums(text: str, source: str) -> dict[str, str]:
    """The path and the digest of each line of a ``sha256sum`` file."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = SUM_LINE.fullmatch(line)
        if not match:
            raise BundleError(f"{source}: line {number} is not a sha256sum line")
        sums[match.group("path")] = match.group("digest")
    return sums


def read_bundle(path: Path, sums_path: Path) -> tuple[str, str, dict[str, bytes]]:
    """The version, the tarball digest and the files of a checked bundle, by their path in the bundle."""
    match = BUNDLE_NAME.fullmatch(path.name)
    if not match:
        raise BundleError(f"{path.name}: the name of a bundle is contracts-<version>.tar.gz")
    version = match.group("version")
    data = path.read_bytes()
    digest = sha256(data)
    released = parse_sums(sums_path.read_text(encoding="utf-8"), sums_path.name)
    if path.name not in released:
        raise BundleError(f"{sums_path}: no line for {path.name}")
    if released[path.name] != digest:
        raise BundleError(f"{path.name}: SHA-256 {digest} is not the released {released[path.name]}")

    prefix = f"contracts-{version}/"
    files: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            name = member.name
            parts = PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or not (name + "/").startswith(prefix):
                raise BundleError(f"{path.name}: the member {name!r} is outside {prefix}")
            if member.isdir():
                continue
            if not member.isfile():
                raise BundleError(f"{path.name}: the member {name!r} is not a regular file")
            total += member.size
            if total > MAX_BYTES:
                raise BundleError(f"{path.name}: more than {MAX_BYTES} bytes")
            handle = archive.extractfile(member)
            assert handle is not None
            relative = name[len(prefix) :]
            if relative in files:
                raise BundleError(f"{path.name}: the member {name!r} occurs twice")
            files[relative] = handle.read()

    if "SHA256SUMS" not in files:
        raise BundleError(f"{path.name}: no SHA256SUMS in the bundle")
    inner = parse_sums(files.pop("SHA256SUMS").decode("utf-8"), f"{prefix}SHA256SUMS")
    if set(inner) != set(files):
        missing, unlisted = sorted(set(inner) - set(files)), sorted(set(files) - set(inner))
        raise BundleError(f"{path.name}: the inner SHA256SUMS does not list the files (missing {missing}, unlisted {unlisted})")
    for relative, content in files.items():
        if sha256(content) != inner[relative]:
            raise BundleError(f"{path.name}: {relative} does not match the inner SHA256SUMS")
    return version, digest, files


def select(files: dict[str, bytes], version: str) -> dict[str, bytes]:
    """The files that SentryTower vendors, by their path in the destination."""
    chosen: dict[str, bytes] = {}
    for relative, content in files.items():
        if relative.startswith("schemas/") or relative in LICENSE_FILES:
            chosen[relative] = content
        elif relative.startswith(MODULE_PREFIX) and relative.endswith(".py"):
            chosen["nc_contracts/" + relative[len(MODULE_PREFIX) :]] = content
    for required in ("schemas/finding/1.json", "nc_contracts/__init__.py", "nc_contracts/types.py", *LICENSE_FILES):
        if required not in chosen:
            raise BundleError(f"the bundle has no {required}")
    stated = VERSION_LINE.search(chosen["nc_contracts/types.py"].decode("utf-8"))
    if not stated or stated.group("version") != version:
        raise BundleError(f"nc_contracts states version {stated.group('version') if stated else None}, the bundle name {version}")
    return chosen


def write(dest: Path, chosen: dict[str, bytes], version: str, bundle: str, digest: str) -> None:
    """Replace the vendored files of ``dest``: remove the files of the old manifest, write the new ones."""
    manifest = dest / "SHA256SUMS"
    if manifest.is_file():
        for relative in parse_sums(manifest.read_text(encoding="utf-8"), str(manifest)):
            target = dest / relative
            if dest.resolve() not in target.resolve().parents:
                raise BundleError(f"{manifest}: {relative} is outside {dest}")
            target.unlink(missing_ok=True)
        for folder in sorted((path for path in dest.rglob("*") if path.is_dir()), key=lambda item: -len(item.parts)):
            if not any(folder.iterdir()):
                folder.rmdir()
    for relative, content in sorted(chosen.items()):
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    manifest.write_text("".join(f"{sha256(content)}  {relative}\n" for relative, content in sorted(chosen.items())), encoding="utf-8")
    (dest / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (dest / "BUNDLE.sha256").write_text(f"{digest}  {bundle}\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vendor a checked release of the data contracts.")
    parser.add_argument("bundle", type=Path, help="contracts-<version>.tar.gz")
    parser.add_argument("--sums", type=Path, help="the SHA256SUMS of the release (default: next to the bundle)")
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST, help="the vendored folder (default: src/sentrytower/contracts)")
    args = parser.parse_args(argv)
    sums = args.sums or args.bundle.with_name("SHA256SUMS")
    try:
        version, digest, files = read_bundle(args.bundle, sums)
        chosen = select(files, version)
        args.dest.mkdir(parents=True, exist_ok=True)
        write(args.dest, chosen, version, args.bundle.name, digest)
    except (BundleError, OSError, tarfile.TarError, UnicodeDecodeError) as error:
        print(f"vendor_contracts: {error}", file=sys.stderr)
        return 1
    print(f"contracts {version} ({args.bundle.name}, sha256 {digest}): {len(chosen)} files in {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
