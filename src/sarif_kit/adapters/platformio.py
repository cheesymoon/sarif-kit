"""PlatformIO adapter, for the output of ``pio check --json-output``.

The output is a JSON array with one entry per (environment, tool) pair, each carrying the
defects that tool reported. Rule ids are namespaced as ``<tool>:<id>`` because a single
run can drive both cppcheck and clang-tidy, whose check ids are not from the same space.

Two properties of the real output shape the parsing. On a machine that doesn't have the
check tool yet, PlatformIO writes installation and git progress to stdout before the JSON,
so the array is the last line rather than the whole document. And environments that build
the same sources each report the same defect, so identical findings are deduplicated.

Defects carry no CVSS score, so results get no ``security_severity``; the CWE, when the
tool reports one, goes to the rule's help link and the result properties instead.
cppcheck writes CWE 0 for "no CWE", which is treated as absent.

Messages are clipped to 1024 characters. GitHub caps rule descriptions at that length,
and everything seen past it so far is cppcheck dumping its preprocessor configuration
into the text; the FastLED capture in the fixtures carries a 12 KB example.
"""

from __future__ import annotations

import json

from ..models import Location, Result, Rule
from ..severity import level_from_severity

TOOL_NAME = "platformio"
INFORMATION_URI = "https://docs.platformio.org/en/latest/core/userguide/cmd_check.html"

_CWE_URI = "https://cwe.mitre.org/data/definitions/"

#: Keys every entry of a `pio check --json-output` array has.
_ENTRY_KEYS = frozenset({"env", "tool", "succeeded", "defects"})

#: GitHub's limit on rule description text, applied to messages too.
_MAX_TEXT = 1024
_CLIP_MARK = "... (truncated)"


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like `pio check --json-output`."""
    try:
        payload = _load(raw)
    except ValueError:
        return False
    if not isinstance(payload, list) or not payload:
        return False
    return all(isinstance(entry, dict) and _ENTRY_KEYS <= entry.keys() for entry in payload)


def convert(raw: str) -> tuple[list[Rule], list[Result]]:
    """Parse `pio check --json-output` into rules and results.

    A project where every environment checks out clean is a legitimate empty result, and
    ``"succeeded": false`` alongside defects is what ``--fail-on-defect`` writes for a
    run that worked and found things, so both convert. But ``"succeeded": false`` with
    no defects means the check itself failed, and reporting zero findings would hide
    that.
    """
    payload = _load(raw)
    if not isinstance(payload, list):
        raise ValueError("input is not a JSON array; expected output of `pio check --json-output`")

    rules: list[Rule] = []
    results: list[Result] = []
    rule_ids: set[str] = set()
    seen: set[tuple] = set()

    for entry in payload:
        if not isinstance(entry, dict) or not _ENTRY_KEYS <= entry.keys():
            raise ValueError("entry is not a check result; expected output of `pio check --json-output`")
        tool = str(entry.get("tool", "unknown"))
        env = str(entry.get("env", "unknown"))
        defects = entry.get("defects") or []
        if not entry.get("succeeded") and not defects:
            raise ValueError(f"check run failed for environment {env!r} with tool {tool!r}")
        for defect in defects:
            if not isinstance(defect, dict):
                continue
            defect_id = str(defect.get("id") or "unknown")
            message = _clip(str(defect.get("message", "")))
            # DefectItem defaults the file to "unknown" when the tool names none.
            path = str(defect.get("file") or "unknown")
            line = _position(defect.get("line"))
            column = _position(defect.get("column"))
            key = (tool, defect_id, path, line, column, message)
            # Environments compiling the same sources report the same defect each.
            if key in seen:
                continue
            seen.add(key)

            severity = str(defect.get("severity", ""))
            level = level_from_severity(severity)
            cwe = _cwe(defect.get("cwe"))
            rule_id = f"{tool}:{defect_id}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                # The output carries no check description, so the first message the check
                # produced stands in as the alert title.
                rules.append(
                    Rule(
                        id=rule_id,
                        name=defect_id,
                        short_description=message,
                        full_description=f"{defect_id}, reported by {tool} via pio check at {severity} severity.",
                        help_uri=f"{_CWE_URI}{cwe}.html" if cwe else INFORMATION_URI,
                        default_level=level,
                    )
                )
            results.append(
                Result(
                    rule_id=rule_id,
                    message=message,
                    location=Location(uri=path, start_line=line, start_column=column),
                    level=level,
                    properties={"cwe": f"CWE-{cwe}"} if cwe else {},
                )
            )

    return rules, results


def _load(raw: str) -> object:
    """Parse the JSON document, tolerating whatever PlatformIO printed before it.

    A run that installs the check tool first writes tool-manager, download and git lines
    to stdout, so the array ends up as the last line instead of the whole document.
    """
    try:
        return json.loads(raw)
    except ValueError:
        pass
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty input; `pio check --json-output` writes JSON even for a clean project")
    try:
        return json.loads(lines[-1])
    except ValueError as exc:
        raise ValueError(f"input is not valid JSON: {exc}") from exc


def _clip(text: str) -> str:
    """``text``, cut to GitHub's 1024-character description limit."""
    if len(text) <= _MAX_TEXT:
        return text
    return text[: _MAX_TEXT - len(_CLIP_MARK)] + _CLIP_MARK


def _position(value: object) -> int | None:
    """A 1-based line or column, or ``None``. PlatformIO writes 0 for "unknown"."""
    try:
        number = int(str(value))
    except ValueError:
        return None
    return number if number > 0 else None


def _cwe(value: object) -> str | None:
    """The bare CWE number. Real output writes a string, but DefectItem allows an int.

    cppcheck reports 0 when a check has no CWE assigned; that is "none", not CWE-0.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text.upper().startswith("CWE-"):
        text = text[len("CWE-"):]
    return text if text and text != "0" else None
