"""Unit tests for the SARIF builder and its GitHub-specific behaviors."""

from __future__ import annotations

import pytest

from sarif_kit import Location, Result, Rule, SarifBuilder, normalize_uri
from sarif_kit.builder import GITHUB_MAX_RESULTS
from sarif_kit.fingerprint import FINGERPRINT_KEY


def _single_result_builder(**result_kw) -> SarifBuilder:
    b = SarifBuilder("demo-tool", tool_version="1.0.0")
    b.add_rule(Rule(id="R1", short_description="rule one", default_level="warning"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1), **result_kw))
    return b


def test_envelope_shape():
    log = _single_result_builder().build()
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "demo-tool"
    assert log["runs"][0]["tool"]["driver"]["version"] == "1.0.0"


def test_level_defaults_to_rule_level():
    log = _single_result_builder().build()
    assert log["runs"][0]["results"][0]["level"] == "warning"


def test_explicit_level_overrides_rule():
    log = _single_result_builder(level="error").build()
    assert log["runs"][0]["results"][0]["level"] == "error"


def test_rule_index_links_result_to_rule():
    log = _single_result_builder().build()
    result = log["runs"][0]["results"][0]
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_rule_dedup_keeps_first_definition():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="first"))
    b.add_rule(Rule(id="R1", short_description="second"))
    log = b.build()
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["shortDescription"]["text"] == "first"


def test_security_severity_formatted_as_string():
    log = _single_result_builder(security_severity=7.5).build()
    assert log["runs"][0]["results"][0]["properties"]["security-severity"] == "7.5"


def test_no_properties_when_empty():
    log = _single_result_builder().build()
    assert "properties" not in log["runs"][0]["results"][0]


def test_region_omitted_without_line():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py")))
    physical = b.build()["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in physical
    assert physical["artifactLocation"]["uri"] == "a.py"


def test_region_full_span():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(
        Result(
            rule_id="R1",
            message="m",
            location=Location(uri="a.py", start_line=3, start_column=2, end_line=3, end_column=8, snippet="foo"),
        )
    )
    region = b.build()["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 3, "startColumn": 2, "endLine": 3, "endColumn": 8, "snippet": {"text": "foo"}}


def test_fingerprint_stable_regardless_of_line():
    # The same file, rule and message on a different line must hash the same,
    # otherwise alerts churn whenever unrelated edits shift the code.
    def fp(line):
        b = SarifBuilder("t")
        b.add_rule(Rule(id="R1", short_description="r"))
        b.add_result(Result(rule_id="R1", message="same message", location=Location(uri="a.py", start_line=line)))
        return b.build()["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY]

    assert fp(10) == fp(99)


def test_fingerprint_collision_indexing():
    # Two identical findings get stable, distinct fingerprints (:0, :1).
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    for _ in range(2):
        b.add_result(Result(rule_id="R1", message="dup", location=Location(uri="a.py", start_line=1)))
    fps = [r["partialFingerprints"][FINGERPRINT_KEY] for r in b.build()["runs"][0]["results"]]
    assert fps[0].endswith(":0") and fps[1].endswith(":1")
    assert fps[0] != fps[1]


def test_snippet_disambiguates_fingerprint():
    def fp(snippet):
        b = SarifBuilder("t")
        b.add_rule(Rule(id="R1", short_description="r"))
        b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1, snippet=snippet)))
        return b.build()["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY]

    assert fp("x = 1") != fp("y = 2")


def test_truncation_notice_added_over_limit():
    b = SarifBuilder("t", max_results=3)
    b.add_rule(Rule(id="R1", short_description="r"))
    for i in range(5):
        b.add_result(Result(rule_id="R1", message=f"m{i}", location=Location(uri="a.py", start_line=i + 1)))
    results = b.build()["runs"][0]["results"]
    assert len(results) == 3
    assert results[-1]["ruleId"] == "sarif-kit/results-truncated"
    assert "dropped 3" in results[-1]["message"]["text"]


def test_truncation_keeps_most_severe():
    # A low-severity finding emitted first must not survive over a later critical one.
    # max_results=2 reserves 1 slot for the notice, so exactly 1 real result survives.
    b = SarifBuilder("t", max_results=2)
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="low", location=Location(uri="a.py", start_line=1), security_severity=1.0))
    b.add_result(Result(rule_id="R1", message="mid", location=Location(uri="a.py", start_line=2), security_severity=5.0))
    b.add_result(Result(rule_id="R1", message="crit", location=Location(uri="a.py", start_line=3), security_severity=9.5))
    results = b.build()["runs"][0]["results"]
    kept = [r["message"]["text"] for r in results if r["ruleId"] == "R1"]
    assert kept == ["crit"]  # only the most severe survived


def test_no_truncation_at_limit():
    b = SarifBuilder("t", max_results=GITHUB_MAX_RESULTS)
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1)))
    results = b.build()["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "R1"


def test_normalize_uri():
    assert normalize_uri("./src/a.py") == "src/a.py"
    assert normalize_uri("src\\a.py") == "src/a.py"
    assert normalize_uri("/abs/path.py") == "abs/path.py"
    assert normalize_uri("/repo/src/a.py", src_root="/repo") == "src/a.py"
    assert normalize_uri("file:///repo/src/a.py", src_root="/repo") == "src/a.py"


def test_normalize_uri_windows_paths():
    # Output captured on a Windows runner is often converted on Linux, so drive-letter
    # paths must relativize regardless of the host OS.
    assert normalize_uri("C:\\repo\\src\\a.py", src_root="C:\\repo") == "src/a.py"
    assert normalize_uri("C:/repo/src/a.py", src_root="C:/repo") == "src/a.py"
    # The canonical Windows file URI keeps a slash before the drive.
    assert normalize_uri("file:///C:/repo/src/a.py", src_root="C:/repo") == "src/a.py"
    # Outside the root, the drive prefix goes the same way a leading slash does.
    assert normalize_uri("D:\\elsewhere\\a.py", src_root="C:\\repo") == "elsewhere/a.py"
    assert normalize_uri("C:\\repo\\a.py") == "repo/a.py"


def test_unknown_rule_id_raises():
    b = SarifBuilder("t")
    b.add_result(Result(rule_id="ghost", message="m", location=Location(uri="a.py", start_line=1)))
    with pytest.raises(ValueError, match="unregistered rule"):
        b.build()


def test_invalid_level_raises():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1), level="info"))
    with pytest.raises(ValueError, match="invalid SARIF level"):
        b.build()


def test_invalid_rule_default_level_raises():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r", default_level="critical"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1)))
    with pytest.raises(ValueError, match="invalid SARIF level"):
        b.build()


def test_non_finite_security_severity_raises():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(
        Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=1), security_severity=float("nan"))
    )
    with pytest.raises(ValueError, match="finite"):
        b.build()


def test_zero_start_line_raises():
    b = SarifBuilder("t")
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="m", location=Location(uri="a.py", start_line=0)))
    with pytest.raises(ValueError, match="start_line"):
        b.build()


def test_severity_validated_even_when_result_would_be_truncated():
    # A non-finite severity must be caught even on a result that truncation would drop.
    b = SarifBuilder("t", max_results=2)
    b.add_rule(Rule(id="R1", short_description="r"))
    b.add_result(Result(rule_id="R1", message="ok", location=Location(uri="a.py", start_line=1), security_severity=9.0))
    b.add_result(Result(rule_id="R1", message="ok2", location=Location(uri="a.py", start_line=2), security_severity=8.0))
    b.add_result(
        Result(rule_id="R1", message="bad", location=Location(uri="a.py", start_line=3), security_severity=float("inf"))
    )
    with pytest.raises(ValueError, match="finite"):
        b.build()


def test_fingerprint_unaffected_by_truncation():
    # A surviving finding's fingerprint is the same whether or not a duplicate sibling
    # got truncated away (fingerprints are computed over the full pre-truncation set).
    def fp_of_line3(max_results):
        b = SarifBuilder("t", max_results=max_results)
        b.add_rule(Rule(id="R1", short_description="r"))
        # Three identical-context findings (same base) at lines 1,2,3, ascending severity
        # so truncation keeps the highest (line 3).
        for ln, sev in [(1, 1.0), (2, 2.0), (3, 9.0)]:
            b.add_result(Result(rule_id="R1", message="dup", location=Location(uri="a.py", start_line=ln), security_severity=sev))
        for r in b.build()["runs"][0]["results"]:
            region = r["locations"][0]["physicalLocation"].get("region", {})
            if region.get("startLine") == 3:
                return r["partialFingerprints"][FINGERPRINT_KEY]
        raise AssertionError("line 3 finding not found")

    assert fp_of_line3(max_results=GITHUB_MAX_RESULTS) == fp_of_line3(max_results=2)


def test_build_is_idempotent():
    b = SarifBuilder("t", max_results=1)
    b.add_rule(Rule(id="R1", short_description="r"))
    for i in range(3):
        b.add_result(Result(rule_id="R1", message=f"m{i}", location=Location(uri="a.py", start_line=i + 1)))
    assert b.build() == b.build()  # no state mutation across builds


def test_collision_suffix_independent_of_input_order():
    def fps(lines):
        b = SarifBuilder("t")
        b.add_rule(Rule(id="R1", short_description="r"))
        for ln in lines:
            b.add_result(Result(rule_id="R1", message="dup", location=Location(uri="a.py", start_line=ln)))
        out = b.build()["runs"][0]["results"]
        return {r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["partialFingerprints"][FINGERPRINT_KEY]
                for r in out}

    # The same findings emitted in a different order keep the same fingerprints.
    assert fps([1, 2, 3]) == fps([3, 1, 2])
