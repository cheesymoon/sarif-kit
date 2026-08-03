"""Severity mapping helpers.

SARIF has two severity axes and GitHub reads both:

* ``level`` (``error`` / ``warning`` / ``note`` / ``none``): the result level, which sets
  the icon and the default filtering.
* ``security-severity``: a numeric string from ``"0.0"`` to ``"10.0"`` in a result's ``properties``.
  GitHub buckets it (critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0, low ≥ 0.1) and sorts
  security alerts by it. Only useful for security tools.

Each adapter picks its own mapping; the helpers here are just reasonable defaults to reuse.
"""

from __future__ import annotations

import math

from .models import VALID_LEVELS

# Maps common native severity words to a SARIF level. Adapters override as needed.
_LEVEL_TABLE = {
    "error": "error",
    "critical": "error",
    "high": "error",
    "fatal": "error",
    "severe": "error",
    "warning": "warning",
    "warn": "warning",
    "medium": "warning",
    "moderate": "warning",
    "note": "note",
    "info": "note",
    "information": "note",
    "informational": "note",
    "low": "note",
    "convention": "note",
    "refactor": "note",
    "hint": "note",
    "none": "none",
}


def level_from_severity(name: str, default: str = "warning") -> str:
    """Best-effort map of a native severity word to a SARIF level."""
    return _LEVEL_TABLE.get(str(name).strip().lower(), default)


def format_security_severity(score: float) -> str:
    """Format a 0.0 to 10.0 score as the string GitHub expects, clamped to range.

    Out-of-range numbers are clamped (robust against a tool reporting e.g. CVSS 11),
    but a non-finite value (NaN/inf) is a bug that would emit an invalid ``"nan"``, so
    it raises.
    """
    value = float(score)
    if not math.isfinite(value):
        raise ValueError(f"security_severity must be a finite number, got {score!r}")
    value = max(0.0, min(10.0, value))
    return f"{value:.1f}"


def security_severity_bucket(score: float) -> str:
    """The label GitHub assigns to a security-severity score (for docs/tests)."""
    value = float(score)
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value >= 0.1:
        return "low"
    return "none"


def normalize_level(level: str) -> str:
    """Validate a level, raising on anything not in the SARIF enum."""
    if level not in VALID_LEVELS:
        raise ValueError(f"invalid SARIF level {level!r}; expected one of {sorted(VALID_LEVELS)}")
    return level
