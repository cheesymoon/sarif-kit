"""Golden-file test helper shared by the builder tests and (from Step 3) adapters.

``assert_matches_golden`` compares a built SARIF log to a committed golden JSON file.
Set ``UPDATE_GOLDEN=1`` to (re)write goldens after an intentional change, then review
the diff before committing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

GOLDEN_DIR = Path(__file__).parent / "golden"


def assert_matches_golden(log: dict, name: str) -> None:
    path = GOLDEN_DIR / name
    actual = json.dumps(log, indent=2, sort_keys=True) + "\n"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    assert path.exists(), f"golden {path} missing; regenerate with UPDATE_GOLDEN=1"
    expected = path.read_text(encoding="utf-8")
    assert actual == expected, f"SARIF output drifted from golden {name}; UPDATE_GOLDEN=1 to refresh"
