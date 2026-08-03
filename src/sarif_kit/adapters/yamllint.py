"""yamllint adapter, for the output of ``yamllint -f parsable``.

Every line reads ``file:line:col: [level] message (rule)``. The trailing parenthesized
token is the yamllint rule that fired; it becomes the SARIF rule id, so GitHub groups
alerts per rule instead of per message. Lines that don't match are skipped, which covers
the odd banner or progress line a wrapper script may add.
"""

from __future__ import annotations

import re

from ..models import Location, Result, Rule
from ..severity import level_from_severity

TOOL_NAME = "yamllint"
INFORMATION_URI = "https://yamllint.readthedocs.io/"

_RULE_DOC_URI = "https://yamllint.readthedocs.io/en/stable/rules.html#module-yamllint.rules."

# The message itself may contain parentheses ("line too long (127 > 80 characters)"),
# so the rule token is pinned to the end of the line.
_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):(?P<column>\d+): "
    r"\[(?P<level>\w+)\] (?P<message>.*?) \((?P<rule>[A-Za-z0-9_-]+)\)$"
)


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like yamllint's parsable format."""
    return any(_LINE.match(line) for line in raw.splitlines())


def convert(raw: str) -> tuple[list[Rule], list[Result]]:
    """Parse yamllint parsable output into rules and results."""
    rules: list[Rule] = []
    results: list[Result] = []
    seen: set[str] = set()

    for line in raw.splitlines():
        match = _LINE.match(line)
        if match is None:
            continue
        rule_id = match["rule"]
        message = match["message"]
        level = level_from_severity(match["level"])
        if rule_id not in seen:
            seen.add(rule_id)
            # The parsable format carries no rule description, so the first message the
            # rule produced stands in as the alert title.
            rules.append(
                Rule(
                    id=rule_id,
                    short_description=message,
                    help_uri=_RULE_DOC_URI + rule_id,
                    default_level=level,
                )
            )
        results.append(
            Result(
                rule_id=rule_id,
                message=message,
                location=Location(
                    uri=match["path"],
                    start_line=int(match["line"]),
                    start_column=int(match["column"]),
                ),
                level=level,
            )
        )

    if not results and raw.strip():
        raise ValueError("no findings parsed; expected output of `yamllint -f parsable`")
    return rules, results
