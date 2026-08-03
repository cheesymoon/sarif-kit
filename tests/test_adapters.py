"""Adapter tests: golden SARIF per captured fixture, plus parsing edge cases."""

from __future__ import annotations

import json

import pytest

from sarif_kit import SarifBuilder, assert_valid
from sarif_kit.adapters import ADAPTERS, get_adapter
from sarif_kit.adapters import codespell, pip_audit, yamllint

from .utils import assert_matches_golden, read_fixture

# (tool, fixture, golden) for every captured fixture.
CASES = [
    ("pip-audit", "pip-audit/native.json", "pip-audit.native.sarif.json"),
    ("pip-audit", "pip-audit/native.mixed.json", "pip-audit.mixed.sarif.json"),
    ("yamllint", "yamllint/native.parsable.txt", "yamllint.native.sarif.json"),
    ("yamllint", "yamllint/native.warnings.parsable.txt", "yamllint.warnings.sarif.json"),
    ("codespell", "codespell/native.txt", "codespell.native.sarif.json"),
    ("codespell", "codespell/native.multi.txt", "codespell.multi.sarif.json"),
]

# Which adapter each fixture belongs to; vulture has no adapter, so nothing claims it.
OWNERS = {
    "pip-audit/native.json": "pip-audit",
    "pip-audit/native.mixed.json": "pip-audit",
    "yamllint/native.parsable.txt": "yamllint",
    "yamllint/native.warnings.parsable.txt": "yamllint",
    "codespell/native.txt": "codespell",
    "codespell/native.multi.txt": "codespell",
    "vulture/native.txt": None,
}


def build(tool: str, raw: str) -> dict:
    adapter = get_adapter(tool)
    rules, results = adapter.convert(raw)
    builder = SarifBuilder(adapter.TOOL_NAME, information_uri=adapter.INFORMATION_URI)
    for rule in rules:
        builder.add_rule(rule)
    builder.add_results(results)
    return builder.build()


@pytest.mark.parametrize(("tool", "fixture", "golden"), CASES)
def test_fixture_converts_to_valid_sarif(tool, fixture, golden):
    log = build(tool, read_fixture(fixture))
    assert_valid(log)
    assert_matches_golden(log, golden)


@pytest.mark.parametrize("fixture", sorted(OWNERS))
@pytest.mark.parametrize("tool", sorted(ADAPTERS))
def test_detect_claims_only_its_own_fixtures(tool, fixture):
    assert get_adapter(tool).detect(read_fixture(fixture)) is (OWNERS[fixture] == tool)


@pytest.mark.parametrize("tool", sorted(ADAPTERS))
def test_garbage_input_raises(tool):
    with pytest.raises(ValueError):
        get_adapter(tool).convert("this is not any tool's output\n")


@pytest.mark.parametrize("tool", ["yamllint", "codespell"])
def test_empty_text_input_is_a_clean_run(tool):
    assert get_adapter(tool).convert("  \n\n") == ([], [])


def test_pip_audit_empty_input_raises():
    # pip-audit writes JSON even for a clean audit, so an empty file means the audit
    # itself failed. Converting it to zero findings would hide that.
    with pytest.raises(ValueError, match="empty input"):
        pip_audit.convert("  \n\n")


def test_get_adapter_rejects_unknown_tool():
    with pytest.raises(ValueError, match="unknown tool"):
        get_adapter("nosuchtool")


# -- pip-audit ------------------------------------------------------------------


def test_pip_audit_no_vulns_is_an_empty_success():
    raw = '{"dependencies": [{"name": "packaging", "version": "24.2", "vulns": []}], "fixes": []}'
    assert pip_audit.convert(raw) == ([], [])


def test_pip_audit_dedupes_repeated_vuln_id():
    # The mixed fixture lists PYSEC-2026-215 twice for idna; only the first survives.
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.mixed.json"))
    assert [r.id for r in rules] == ["PYSEC-2026-215"]
    assert len(results) == 1
    assert "idna 3.10" in results[0].message


def test_pip_audit_message_carries_the_details():
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.json"))
    first = results[0]
    assert first.message == (
        "jinja2 2.10 is affected by PYSEC-2021-66 (also known as SNYK-PYTHON-JINJA2-1012994, "
        "GHSA-g3rq-g295-4j3m, CVE-2020-28493). Fixed in 2.11.3."
    )
    assert rules[0].help_uri == "https://osv.dev/vulnerability/PYSEC-2021-66"


def test_pip_audit_every_finding_is_an_error_without_a_score():
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.json"))
    assert {r.default_level for r in rules} == {"error"}
    assert all(r.security_severity is None for r in results)


def test_pip_audit_points_at_the_manifest():
    _, results = pip_audit.convert(read_fixture("pip-audit/native.json"), dep_file="reqs/prod.txt")
    assert results[0].location.uri == "reqs/prod.txt"
    assert results[0].location.start_line is None


def test_pip_audit_summary_is_one_sentence():
    rules, _ = pip_audit.convert(read_fixture("pip-audit/native.json"))
    summaries = {r.id: r.short_description for r in rules}
    assert summaries["PYSEC-2019-217"] == "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape."
    assert all(len(s) <= 305 for s in summaries.values())


def test_pip_audit_truncates_an_endless_first_sentence():
    long_description = "word " * 200
    raw = json.dumps(
        {
            "dependencies": [
                {"name": "x", "version": "1.0", "vulns": [{"id": "CVE-1", "description": long_description}]}
            ]
        }
    )
    rules, _ = pip_audit.convert(raw)
    assert len(rules[0].short_description) <= 303
    assert rules[0].short_description.endswith("...")


def test_pip_audit_missing_fix_version_is_said_so():
    raw = '{"dependencies": [{"name": "x", "version": "1.0", "vulns": [{"id": "CVE-1", "description": "Bad."}]}]}'
    _, results = pip_audit.convert(raw)
    assert results[0].message == "x 1.0 is affected by CVE-1. No fixed version is available."


def test_pip_audit_rejects_json_that_is_not_pip_audit():
    with pytest.raises(ValueError, match="dependencies"):
        pip_audit.convert('{"results": []}')


# -- yamllint -------------------------------------------------------------------


def test_yamllint_keeps_line_and_column():
    _, results = yamllint.convert(read_fixture("yamllint/native.parsable.txt"))
    first = results[0]
    assert (first.location.uri, first.location.start_line, first.location.start_column) == (
        "fx/messy.yaml",
        2,
        7,
    )
    assert first.rule_id == "colons"
    assert first.message == "too many spaces after colon"


def test_yamllint_maps_levels():
    _, results = yamllint.convert(read_fixture("yamllint/native.warnings.parsable.txt"))
    assert [r.level for r in results] == ["warning", "warning", "warning", "error"]


def test_yamllint_rule_help_uri():
    rules, _ = yamllint.convert(read_fixture("yamllint/native.warnings.parsable.txt"))
    assert rules[0].help_uri == (
        "https://yamllint.readthedocs.io/en/stable/rules.html#module-yamllint.rules.document-start"
    )


def test_yamllint_message_keeps_its_own_parentheses():
    _, results = yamllint.convert("a.yaml:4:81: [error] line too long (127 > 80 characters) (line-length)")
    assert results[0].rule_id == "line-length"
    assert results[0].message == "line too long (127 > 80 characters)"


def test_yamllint_handles_awkward_paths():
    raw = "\n".join(
        [
            "dir with spaces/a b.yaml:1:1: [error] trailing spaces (trailing-spaces)",
            "odd:name.yaml:2:1: [error] trailing spaces (trailing-spaces)",
            "C:\\repo\\ci.yaml:3:1: [error] trailing spaces (trailing-spaces)",
        ]
    )
    _, results = yamllint.convert(raw)
    assert [r.location.uri for r in results] == [
        "dir with spaces/a b.yaml",
        "odd:name.yaml",
        "C:\\repo\\ci.yaml",
    ]


def test_yamllint_skips_blank_and_unparseable_lines():
    raw = "\n".join(
        [
            "",
            "yamllint 1.35.1",
            "a.yaml:1:1: [warning] missing document start \"---\" (document-start)",
            "   ",
            "not a finding at all",
        ]
    )
    _, results = yamllint.convert(raw)
    assert len(results) == 1


# -- codespell ------------------------------------------------------------------


def test_codespell_message_and_location():
    rules, results = codespell.convert(read_fixture("codespell/native.txt"))
    assert [r.id for r in rules] == ["misspelling"]
    assert results[0].message == '"Recieve" is a misspelling of "Receive"'
    assert results[0].location.uri == "fx/typos.py"
    assert results[0].location.start_line == 1
    assert results[0].location.start_column is None


def test_codespell_keeps_every_correction():
    _, results = codespell.convert(read_fixture("codespell/native.multi.txt"))
    messages = [r.message for r in results]
    assert '"procede" is a misspelling of "proceed, precede"' in messages


def test_codespell_keeps_a_trailing_reason():
    _, results = codespell.convert("a.txt:7: ba ==> by, be (disabled due to being a common word)")
    assert results[0].message == '"ba" is a misspelling of "by, be (disabled due to being a common word)"'


def test_codespell_defaults_to_warning():
    rules, _ = codespell.convert(read_fixture("codespell/native.txt"))
    assert rules[0].default_level == "warning"


def test_codespell_handles_awkward_paths():
    _, results = codespell.convert("dir with spaces/read me.txt:3: teh ==> the")
    assert results[0].location.uri == "dir with spaces/read me.txt"


def test_codespell_skips_blank_and_unparseable_lines():
    raw = "\n".join(["", "WARNING: Binary file skipped", "a.txt:2: teh ==> the", "  "])
    _, results = codespell.convert(raw)
    assert len(results) == 1
