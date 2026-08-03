"""Assemble adapter output into a valid, GitHub-ready SARIF 2.1.0 log.

Adapters build Rule and Result objects and hand them here; they never write SARIF JSON
themselves. This is also where the GitHub-specific details live, the ones that decide
whether an upload merely validates or actually renders well in the UI:

* rule metadata: deduped ``rules[]`` with the ids, descriptions and helpUri GitHub builds
  alert titles from;
* ``partialFingerprints`` that stay stable across pushes so alerts don't churn (see
  :mod:`sarif_kit.fingerprint`);
* ``security-severity`` copied from ``Result.security_severity`` into result properties,
  which is what GitHub sorts security alerts by;
* repo-relative URIs, and a cap at GitHub's 5,000 results that keeps the most severe and
  leaves a visible notice rather than dropping findings quietly.

``build()`` doesn't mutate the builder, so calling it more than once is fine.
"""

from __future__ import annotations

import re

from .fingerprint import FINGERPRINT_KEY, base_fingerprint
from .models import Location, Result, Rule
from .severity import format_security_severity, normalize_level

SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

#: GitHub Code Scanning rejects uploads with more than this many results per run.
GITHUB_MAX_RESULTS = 5000

# A Windows drive prefix, after backslashes have been normalized to forward slashes.
_DRIVE = re.compile(r"^[A-Za-z]:/")

# Ranking for truncation: most severe kept first.
_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}

_TRUNCATION_RULE = Rule(
    id="sarif-kit/results-truncated",
    name="ResultsTruncated",
    short_description="Results truncated to fit GitHub's upload limit",
    default_level="warning",
)


def normalize_uri(uri: str, src_root: str | None = None) -> str:
    """Return a repo-root-relative, forward-slashed URI.

    Absolute paths break GitHub's file linking, so we strip a ``file://`` scheme and, when
    ``src_root`` is given, make paths under it relative to it. That includes Windows
    drive-letter paths even when the conversion runs on another OS, since output captured
    on a Windows runner is often converted on Linux. Adapters and the CLI should hand us
    repo-relative paths or a ``src_root``. An absolute path from outside the repo can't
    be made meaningfully relative, so it just loses its leading slash or drive prefix.
    """
    uri = uri.replace("\\", "/")
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
        # The canonical Windows file URI puts a slash before the drive: file:///C:/repo.
        if uri.startswith("/") and _DRIVE.match(uri[1:]):
            uri = uri[1:]
    if src_root and (uri.startswith("/") or _DRIVE.match(uri)):
        root = src_root.replace("\\", "/").rstrip("/") + "/"
        if uri.startswith(root):
            uri = uri[len(root):]
    uri = _DRIVE.sub("", uri.lstrip("/"))
    if uri.startswith("./"):
        uri = uri[2:]
    return uri


class SarifBuilder:
    """Collects rules and results for a single tool, then emits one SARIF ``run``."""

    def __init__(
        self,
        tool_name: str,
        *,
        tool_version: str | None = None,
        information_uri: str | None = None,
        src_root: str | None = None,
        max_results: int = GITHUB_MAX_RESULTS,
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.information_uri = information_uri
        self.src_root = src_root
        self.max_results = max_results
        self._rules: dict[str, Rule] = {}
        self._rule_order: list[str] = []
        self._results: list[Result] = []

    def add_rule(self, rule: Rule) -> None:
        """Register a rule. The first definition of a given id wins; repeats are ignored."""
        if rule.id not in self._rules:
            self._rules[rule.id] = rule
            self._rule_order.append(rule.id)

    def add_result(self, result: Result) -> None:
        self._results.append(result)

    def add_results(self, results) -> None:
        for result in results:
            self.add_result(result)

    # -- validation -------------------------------------------------------------

    def _effective_level(self, result: Result) -> str:
        rule = self._rules.get(result.rule_id)
        return result.level or (rule.default_level if rule else "warning")

    def _validate(self) -> None:
        """Fail fast on adapter mistakes that would yield invalid or bare SARIF."""
        unknown = sorted({r.rule_id for r in self._results if r.rule_id not in self._rules})
        if unknown:
            raise ValueError(
                "results reference unregistered rule id(s) "
                + ", ".join(map(repr, unknown))
                + "; call add_rule() for every rule so GitHub can render alert titles"
            )
        for rule in self._rules.values():
            normalize_level(rule.default_level)
        for result in self._results:
            normalize_level(self._effective_level(result))
            self._validate_region(result.location)
            if result.security_severity is not None:
                # Raises on non-finite; also ensures the truncation sort key is finite.
                format_security_severity(result.security_severity)

    @staticmethod
    def _validate_region(loc: Location) -> None:
        if loc.start_line is not None and loc.start_line < 1:
            raise ValueError(f"start_line must be >= 1 (SARIF is 1-based), got {loc.start_line}")
        for name in ("start_column", "end_line", "end_column"):
            value = getattr(loc, name)
            if value is not None and value < 1:
                raise ValueError(f"{name} must be >= 1, got {value}")

    # -- serialization ----------------------------------------------------------

    def _region(self, loc: Location) -> dict | None:
        if loc.start_line is None:
            return None  # without a line number, point at the whole file
        region: dict = {"startLine": loc.start_line}
        if loc.start_column is not None:
            region["startColumn"] = loc.start_column
        if loc.end_line is not None:
            region["endLine"] = loc.end_line
        if loc.end_column is not None:
            region["endColumn"] = loc.end_column
        if loc.snippet is not None:
            region["snippet"] = {"text": loc.snippet}
        return region

    def _result_object(self, result: Result, rule_index: dict[str, int], fp: str) -> dict:
        loc = result.location
        physical: dict = {"artifactLocation": {"uri": normalize_uri(loc.uri, self.src_root)}}
        region = self._region(loc)
        if region is not None:
            physical["region"] = region

        obj: dict = {
            "ruleId": result.rule_id,
            "level": self._effective_level(result),
            "message": {"text": result.message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {FINGERPRINT_KEY: fp},
        }
        if result.rule_id in rule_index:
            obj["ruleIndex"] = rule_index[result.rule_id]

        properties = dict(result.properties)
        if result.security_severity is not None:
            properties["security-severity"] = format_security_severity(result.security_severity)
        if properties:
            obj["properties"] = properties
        return obj

    def _rule_object(self, rule: Rule) -> dict:
        obj: dict = {"id": rule.id, "defaultConfiguration": {"level": rule.default_level}}
        if rule.name:
            obj["name"] = rule.name
        if rule.short_description:
            obj["shortDescription"] = {"text": rule.short_description}
        if rule.full_description:
            obj["fullDescription"] = {"text": rule.full_description}
        if rule.help_uri:
            obj["helpUri"] = rule.help_uri
        return obj

    def _truncate(self, results: list[Result]) -> tuple[list[Result], bool]:
        """Cap results at ``max_results``, keeping the most severe and leaving one slot
        for the truncation notice."""
        if len(results) <= self.max_results:
            return list(results), False

        def severity_key(item: tuple[int, Result]) -> tuple:
            i, r = item
            sec = r.security_severity if r.security_severity is not None else -1.0
            return (-sec, _LEVEL_RANK.get(self._effective_level(r), 9), i)

        ranked = [r for _, r in sorted(enumerate(results), key=severity_key)]
        dropped = len(results) - (self.max_results - 1)
        kept = ranked[: self.max_results - 1]
        kept.append(
            Result(
                rule_id=_TRUNCATION_RULE.id,
                message=(
                    f"sarif-kit kept the {self.max_results - 1} most severe result(s) and dropped "
                    f"{dropped} more to stay under GitHub's {self.max_results}-result upload limit."
                ),
                location=Location(uri=".", start_line=1),
                level="warning",
            )
        )
        return kept, True

    def _base(self, result: Result) -> str:
        context = result.location.snippet if result.location.snippet else result.message
        return base_fingerprint(normalize_uri(result.location.uri, self.src_root), result.rule_id, context)

    def _fingerprints(self, results: list[Result]) -> dict[int, str]:
        """Stable per-result fingerprints, keyed by ``id(result)``.

        The collision suffix comes from the finding's own (line, column, message), so it
        doesn't shift when adapters emit results in a different order. It's computed over
        the full result set before truncation, so dropping results doesn't renumber the
        survivors. One case it can't cover: if an earlier duplicate of the same finding
        disappears between runs, the remaining ones renumber. That's the price of leaving
        the line number out of the fingerprint, which is what stops churn when unrelated
        edits move code around."""
        groups: dict[str, list[Result]] = {}
        for r in results:
            groups.setdefault(self._base(r), []).append(r)

        fps: dict[int, str] = {}
        for base, members in groups.items():
            ordered = sorted(
                members,
                key=lambda r: (r.location.start_line or 0, r.location.start_column or 0, r.message),
            )
            for suffix, r in enumerate(ordered):
                fps[id(r)] = f"{base}:{suffix}"
        return fps

    def build(self) -> dict:
        """Produce the complete SARIF log as a JSON-serializable dict, without mutating the builder."""
        self._validate()
        fingerprints = self._fingerprints(self._results)  # over the full set, pre-truncation
        results, truncated = self._truncate(self._results)

        rule_order = list(self._rule_order)
        rules = dict(self._rules)
        if truncated:
            rule_order.append(_TRUNCATION_RULE.id)
            rules[_TRUNCATION_RULE.id] = _TRUNCATION_RULE
        rule_index = {rid: i for i, rid in enumerate(rule_order)}

        result_objs = [
            self._result_object(r, rule_index, fingerprints.get(id(r)) or f"{self._base(r)}:0")
            for r in results
        ]

        driver: dict = {
            "name": self.tool_name,
            "rules": [self._rule_object(rules[rid]) for rid in rule_order],
        }
        if self.tool_version:
            driver["version"] = self.tool_version
        if self.information_uri:
            driver["informationUri"] = self.information_uri

        return {
            "$schema": SCHEMA_URI,
            "version": SARIF_VERSION,
            "runs": [{"tool": {"driver": driver}, "results": result_objs}],
        }
