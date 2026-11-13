"""The National Compute data contracts, vendored from a released bundle.

SentryTower writes each finding of ``findings.json`` as a ``Finding`` of
these contracts (``schemas/finding/1.json``), so the CLI and the hosted
product share one finding format, one severity scale, one evidence ladder
and one SARIF mapping. ``nc_contracts`` holds the standard-library mappings
(severity, evidence, SARIF 2.1.0, CycloneDX VEX) and a TypedDict for each
entity.

Every file of this folder except this one comes from the bundle named in
``BUNDLE.sha256``, unchanged; ``VERSION`` is its version and
``SHA256SUMS`` the digest of each vendored file, which the test suite
checks. Do not edit them: vendor a new release with
``make vendor-contracts BUNDLE=path/to/contracts-<version>.tar.gz``
(``scripts/vendor_contracts.py``). The contracts are licensed Apache-2.0
OR MIT (``LICENSE-APACHE``, ``LICENSE-MIT``); ``NOTICE`` lists the
third-party OSV schema in ``schemas/vendor/``.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

#: The base URI of the contract schemas; a schema's ``$id`` is this base and its path in ``schemas/``.
SCHEMA_BASE = "https://nationalcompute.io/schemas/"
FINDING_SCHEMA_ID = SCHEMA_BASE + "finding/1.json"


def schema_documents() -> dict[str, Any]:
    """Each vendored schema by its URI, for a JSON Schema validator's registry."""
    documents: dict[str, Any] = {}

    def walk(folder: Any, prefix: str) -> None:
        for item in folder.iterdir():
            if item.is_dir():
                walk(item, f"{prefix}{item.name}/")
            elif item.name.endswith(".json"):
                documents[SCHEMA_BASE + prefix + item.name] = json.loads(item.read_text(encoding="utf-8"))

    walk(resources.files(__name__) / "schemas", "")
    return documents
