"""codespell adapter, for codespell's default output.

Every line reads ``file:line: typo ==> correction``. codespell has no rule ids and no
severity, so all findings land on one ``misspelling`` rule at warning level: a typo is
worth fixing but should not fail a build. The output has no column either, so results
point at the line.

The right-hand side is kept whole: codespell writes several comma-separated candidates,
sometimes with a trailing reason in parentheses, and picking one of them would be
guessing.
"""

from __future__ import annotations

import re

from ..models import Location, Result, Rule

TOOL_NAME = "codespell"
INFORMATION_URI = "https://github.com/codespell-project/codespell"

#: The single rule every codespell finding reports under.
RULE_ID = "misspelling"

_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):\s+(?P<typo>.+?) ==> (?P<correction>.+)$")

_RULE = Rule(
    id=RULE_ID,
    short_description="Possible misspelling",
    help_uri=INFORMATION_URI,
    default_level="warning",
)


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like codespell output."""
    return any(_LINE.match(line) for line in raw.splitlines())


def convert(raw: str) -> tuple[list[Rule], list[Result]]:
    """Parse codespell output into rules and results."""
    results: list[Result] = []

    for line in raw.splitlines():
        match = _LINE.match(line)
        if match is None:
            continue
        typo = match["typo"]
        correction = match["correction"].strip()
        results.append(
            Result(
                rule_id=RULE_ID,
                message=f'"{typo}" is a misspelling of "{correction}"',
                location=Location(uri=match["path"], start_line=int(match["line"])),
            )
        )

    if not results:
        if raw.strip():
            raise ValueError("no findings parsed; expected codespell output")
        return [], []
    return [_RULE], results
