"""codespell adapter, for codespell's default output.

Every line reads ``file:line: typo ==> correction``. codespell has no rule ids and no
severity, so every finding lands at warning level: a typo is worth fixing but should not
fail a build. The output has no column either, so results point at the line.

Each distinct typo becomes its own rule. GitHub builds the alert-list titles from rule
metadata, so a single shared rule would make every alert read the same; with a rule per
typo the list shows "recieve should be receive" instead of "Possible misspelling" nine
times over.

The right-hand side is kept whole: codespell writes several comma-separated candidates,
sometimes with a trailing reason in parentheses, and picking one of them would be
guessing.
"""

from __future__ import annotations

import re

from ..models import Location, Result, Rule

TOOL_NAME = "codespell"
INFORMATION_URI = "https://github.com/codespell-project/codespell"

_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):\s+(?P<typo>.+?) ==> (?P<correction>.+)$")


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like codespell output."""
    return any(_LINE.match(line) for line in raw.splitlines())


def convert(raw: str) -> tuple[list[Rule], list[Result]]:
    """Parse codespell output into rules and results."""
    rules: list[Rule] = []
    results: list[Result] = []
    seen: set[str] = set()

    for line in raw.splitlines():
        match = _LINE.match(line)
        if match is None:
            continue
        typo = match["typo"]
        correction = match["correction"].strip()
        # The rule id is the lowercased typo, so the same word in different casing
        # groups under one rule.
        rule_id = typo.lower()
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append(
                Rule(
                    id=rule_id,
                    short_description=f'"{rule_id}" should be "{correction}"',
                    help_uri=INFORMATION_URI,
                    default_level="warning",
                )
            )
        results.append(
            Result(
                rule_id=rule_id,
                message=f'"{typo}" is a misspelling of "{correction}"',
                location=Location(uri=match["path"], start_line=int(match["line"])),
            )
        )

    if not results and raw.strip():
        raise ValueError("no findings parsed; expected codespell output")
    return rules, results
