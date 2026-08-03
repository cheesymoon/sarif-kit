"""Convert native scanner/linter output into valid SARIF 2.1.0.

Adapters build :class:`Rule` and :class:`Result` objects and feed them to
:class:`SarifBuilder`, which emits a GitHub-ready SARIF log. :func:`validate.is_valid`
checks a log against the vendored official schema.
"""

from __future__ import annotations

from .builder import GITHUB_MAX_RESULTS, SarifBuilder, normalize_uri
from .models import Location, Result, Rule
from .severity import format_security_severity, level_from_severity, security_severity_bucket
from .validate import assert_valid, is_valid, validation_errors

__all__ = [
    "SarifBuilder",
    "GITHUB_MAX_RESULTS",
    "normalize_uri",
    "Location",
    "Result",
    "Rule",
    "level_from_severity",
    "format_security_severity",
    "security_severity_bucket",
    "is_valid",
    "assert_valid",
    "validation_errors",
]
