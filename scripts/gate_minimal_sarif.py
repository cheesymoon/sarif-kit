"""Emit the Step-2 gate SARIF: a minimal, schema-valid log pointing at a real file.

The upload-gate workflow uses this to check that GitHub Code Scanning actually accepts
the builder's output, since schema validation alone doesn't guarantee that. It points at
this repo's README so the alert
lands with a clickable file/line link you can look at in the Security tab.

Usage: python scripts/gate_minimal_sarif.py <output.sarif>
"""

from __future__ import annotations

import sys

from sarif_kit import Location, Result, Rule, SarifBuilder, assert_valid


def build() -> dict:
    b = SarifBuilder(
        "sarif-kit-gate",
        tool_version="0.0.1",
        information_uri="https://github.com/sarif-kit/sarif-kit",
    )
    b.add_rule(
        Rule(
            id="sarif-kit/gate-check",
            name="GateCheck",
            short_description="sarif-kit end-to-end upload gate",
            full_description="A synthetic finding used to verify GitHub Code Scanning accepts sarif-kit output.",
            help_uri="https://github.com/sarif-kit/sarif-kit#step-2-gate",
            default_level="warning",
        )
    )
    b.add_result(
        Result(
            rule_id="sarif-kit/gate-check",
            message="sarif-kit gate: if you can see this alert in the Security tab, the builder's output uploads cleanly.",
            location=Location(uri="README.md", start_line=1),
            security_severity=5.0,
        )
    )
    log = b.build()
    assert_valid(log)
    return log


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/gate_minimal_sarif.py <output.sarif>")
    import json

    with open(sys.argv[1], "w", encoding="utf-8") as fh:
        json.dump(build(), fh, indent=2)
    print(f"wrote gate SARIF to {sys.argv[1]}")


if __name__ == "__main__":
    main()
