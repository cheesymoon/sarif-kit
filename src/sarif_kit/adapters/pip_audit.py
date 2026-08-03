"""pip-audit adapter, for the output of ``pip-audit -f json``.

Two things about that output shape the conversion. It names no source file, so results
point at the dependency manifest as a whole; a line number in a requirements file would
be guesswork. And it carries no CVSS score, so results get no ``security_severity`` and
every one of them is an ``error``: a known vulnerability in an installed dependency is
not a warning.

Each vulnerability id gets its own rule, because GitHub builds alert titles from rule
metadata rather than from individual results.
"""

from __future__ import annotations

import json
import re

from ..models import Location, Result, Rule

TOOL_NAME = "pip-audit"
INFORMATION_URI = "https://github.com/pypa/pip-audit"

#: OSV serves PYSEC, GHSA and CVE ids alike, so one template covers every id shape.
_ADVISORY_URI = "https://osv.dev/vulnerability/"

#: Cap for a rule's short description, which GitHub renders as the alert title.
_SUMMARY_LIMIT = 300

_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like pip-audit JSON."""
    if "dependencies" not in raw:
        return False
    try:
        payload = json.loads(raw)
    except ValueError:
        return False
    return isinstance(payload, dict) and isinstance(payload.get("dependencies"), list)


def convert(raw: str, dep_file: str = "requirements.txt") -> tuple[list[Rule], list[Result]]:
    """Parse pip-audit JSON into rules and results.

    ``dep_file`` is the manifest the findings point at. A run where every dependency is
    clean is a legitimate empty result, but input that isn't pip-audit JSON raises.
    Empty input raises too: pip-audit always writes a JSON document, even for a clean
    audit, so an empty file means the audit run itself failed and quietly converting it
    to zero findings would hide that.
    """
    if not raw.strip():
        raise ValueError("empty input; pip-audit always writes JSON, so the audit run itself probably failed")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"input is not valid JSON: {exc}") from exc
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
    if not isinstance(dependencies, list):
        raise ValueError("input has no 'dependencies' list; expected output of `pip-audit -f json`")

    rules: list[Rule] = []
    results: list[Result] = []
    rule_ids: set[str] = set()

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", "unknown"))
        version = str(dep.get("version", "unknown"))
        seen: set[str] = set()
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            # pip-audit can list the same advisory twice for one dependency when several
            # sources report it. The first entry wins.
            if not vuln_id or vuln_id in seen:
                continue
            seen.add(vuln_id)
            aliases = [str(a) for a in vuln.get("aliases") or []]
            fix_versions = [str(v) for v in vuln.get("fix_versions") or []]
            if vuln_id not in rule_ids:
                rule_ids.add(vuln_id)
                rules.append(
                    Rule(
                        id=vuln_id,
                        short_description=_summary(vuln.get("description")),
                        help_uri=_ADVISORY_URI + vuln_id,
                        default_level="error",
                    )
                )
            results.append(
                Result(
                    rule_id=vuln_id,
                    message=_message(name, version, vuln_id, aliases, fix_versions),
                    location=Location(uri=dep_file),
                )
            )

    return rules, results


def _summary(description: object) -> str | None:
    """The first sentence of an advisory description, for the alert title."""
    if not isinstance(description, str):
        return None
    # OSV descriptions are markdown with the newlines already flattened, so a leading
    # heading marker is left over as noise.
    text = " ".join(description.split()).lstrip("#").lstrip()
    if not text:
        return None
    end = _SENTENCE_END.search(text)
    if end:
        text = text[: end.start()]
    if len(text) > _SUMMARY_LIMIT:
        text = text[:_SUMMARY_LIMIT].rsplit(" ", 1)[0] + "..."
    return text


def _message(name: str, version: str, vuln_id: str, aliases: list[str], fix_versions: list[str]) -> str:
    text = f"{name} {version} is affected by {vuln_id}"
    if aliases:
        text += " (also known as " + ", ".join(aliases) + ")"
    if fix_versions:
        return text + ". Fixed in " + " or ".join(fix_versions) + "."
    return text + ". No fixed version is available."
