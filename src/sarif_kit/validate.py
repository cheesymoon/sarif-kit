"""Validate a SARIF log against the vendored SARIF 2.1.0 schema.

The schema (``schema/sarif-2.1.0.json``) is the OASIS draft-04 one, so validation runs
through :class:`jsonschema.Draft4Validator`. Passing it isn't the whole story: GitHub adds
rules of its own, which is why Step 2's real gate is an actual upload. This is just the
cheap check that runs first.
"""

from __future__ import annotations

import functools
import importlib.resources
import json

from jsonschema import Draft4Validator

_SCHEMA_RESOURCE = "sarif-2.1.0.json"


@functools.lru_cache(maxsize=1)
def load_schema() -> dict:
    """Load and cache the vendored SARIF 2.1.0 JSON schema."""
    files = importlib.resources.files("sarif_kit.schema")
    with files.joinpath(_SCHEMA_RESOURCE).open("r", encoding="utf-8") as fh:
        return json.load(fh)


@functools.lru_cache(maxsize=1)
def _validator() -> Draft4Validator:
    return Draft4Validator(load_schema())


def validation_errors(log: dict) -> list[str]:
    """Return human-readable schema errors, best-effort ordered; empty means valid."""
    errors = sorted(_validator().iter_errors(log), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors]


def is_valid(log: dict) -> bool:
    """Whether ``log`` satisfies the SARIF 2.1.0 schema."""
    return not validation_errors(log)


def assert_valid(log: dict) -> None:
    """Raise :class:`ValueError` listing every schema error, if any."""
    errors = validation_errors(log)
    if errors:
        raise ValueError("SARIF schema validation failed:\n" + "\n".join(f"  - {e}" for e in errors))
