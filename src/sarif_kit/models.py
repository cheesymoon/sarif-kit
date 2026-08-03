"""Adapter-facing data model.

An adapter parses a tool's native output and produces a set of :class:`Rule`
definitions and :class:`Result` findings. The :class:`~sarif_kit.builder.SarifBuilder`
turns those into a valid SARIF 2.1.0 log. Adapters never touch raw SARIF JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: SARIF result levels. ``none`` means "not a problem" (e.g. suppressed/info-only).
VALID_LEVELS = frozenset({"error", "warning", "note", "none"})


@dataclass(frozen=True)
class Rule:
    """A rule (check) the tool can report. GitHub renders alert titles from these,
    not from individual results, so ``short_description`` and ``help_uri`` matter."""

    id: str
    name: str | None = None
    short_description: str | None = None
    full_description: str | None = None
    help_uri: str | None = None
    default_level: str = "warning"


@dataclass
class Location:
    """Where a finding is. ``uri`` should be repo-root-relative (the builder
    normalizes it). ``start_line`` is 1-based; omit it to point at the whole file."""

    uri: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


@dataclass
class Result:
    """One finding. ``level`` falls back to the rule's ``default_level`` if unset.
    ``security_severity`` (0.0 to 10.0, typically from CVSS) drives GitHub's severity
    sort for security rules; leave it ``None`` for non-security tools."""

    rule_id: str
    message: str
    location: Location
    level: str | None = None
    security_severity: float | None = None
    properties: dict = field(default_factory=dict)
