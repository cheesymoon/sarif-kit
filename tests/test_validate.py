"""Schema-validation tests + the minimal-SARIF golden gate for Step 2."""

from __future__ import annotations

import pytest

from sarif_kit import Location, Result, Rule, SarifBuilder, assert_valid, is_valid, validation_errors
from sarif_kit.validate import load_schema

from .utils import assert_matches_golden


def _minimal_builder() -> SarifBuilder:
    b = SarifBuilder(
        "demo-tool",
        tool_version="1.2.3",
        information_uri="https://example.com/demo",
    )
    b.add_rule(
        Rule(
            id="R001",
            name="NoFoo",
            short_description="Foo is not allowed",
            full_description="Using foo is forbidden by policy.",
            help_uri="https://example.com/rules/R001",
            default_level="error",
        )
    )
    b.add_result(
        Result(
            rule_id="R001",
            message="Found foo",
            location=Location(uri="./src/app.py", start_line=10, start_column=5),
            security_severity=7.5,
        )
    )
    return b


def test_schema_loads():
    schema = load_schema()
    assert "Static Analysis Results" in schema["title"]


def test_minimal_sarif_is_schema_valid():
    log = _minimal_builder().build()
    assert validation_errors(log) == []
    assert is_valid(log)
    assert_valid(log)  # must not raise


def test_minimal_sarif_matches_golden():
    log = _minimal_builder().build()
    assert_matches_golden(log, "minimal.sarif.json")


def test_invalid_log_is_rejected():
    # version must be exactly "2.1.0"; a bad version fails the schema.
    bad = {"version": "9.9.9", "runs": []}
    assert not is_valid(bad)
    assert validation_errors(bad)
    with pytest.raises(ValueError):
        assert_valid(bad)


def test_empty_run_is_valid():
    # A run with zero results is legal SARIF (a clean scan).
    log = SarifBuilder("demo-tool").build()
    assert is_valid(log)
