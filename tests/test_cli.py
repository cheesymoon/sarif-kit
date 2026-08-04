"""Smoke tests for the convert, validate and merge subcommands."""

from __future__ import annotations

import io
import json

import pytest

from sarif_kit import assert_valid
from sarif_kit.builder import GITHUB_MAX_RUNS
from sarif_kit.cli import main

from .utils import FIXTURE_DIR, GOLDEN_DIR


def test_convert_writes_valid_sarif(tmp_path):
    out = tmp_path / "results.sarif"
    code = main(
        [
            "convert",
            "--tool",
            "yamllint",
            "-i",
            str(FIXTURE_DIR / "yamllint" / "native.parsable.txt"),
            "-o",
            str(out),
        ]
    )
    assert code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert_valid(log)
    assert log["runs"][0]["tool"]["driver"]["name"] == "yamllint"
    assert len(log["runs"][0]["results"]) == 4


def test_convert_honours_dep_file(tmp_path):
    out = tmp_path / "results.sarif"
    code = main(
        [
            "convert",
            "--tool",
            "pip-audit",
            "-i",
            str(FIXTURE_DIR / "pip-audit" / "native.mixed.json"),
            "-o",
            str(out),
            "--dep-file",
            "reqs/prod.txt",
        ]
    )
    assert code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    location = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "reqs/prod.txt"


def test_convert_reads_stdin_and_writes_stdout(monkeypatch, capsys):
    raw = (FIXTURE_DIR / "codespell" / "native.txt").read_text(encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    code = main(["convert", "--tool", "codespell", "-i", "-", "-o", "-"])
    assert code == 0
    log = json.loads(capsys.readouterr().out)
    assert_valid(log)
    assert log["runs"][0]["tool"]["driver"]["name"] == "codespell"


def test_dep_file_rejected_for_other_tools(tmp_path, capsys):
    code = main(
        [
            "convert",
            "--tool",
            "codespell",
            "-i",
            str(FIXTURE_DIR / "codespell" / "native.txt"),
            "-o",
            str(tmp_path / "out.sarif"),
            "--dep-file",
            "requirements.txt",
        ]
    )
    assert code == 2
    assert "--dep-file" in capsys.readouterr().err


def test_garbage_input_exits_two(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not pip-audit output", encoding="utf-8")
    code = main(["convert", "--tool", "pip-audit", "-i", str(bad), "-o", str(tmp_path / "out.sarif")])
    assert code == 2
    assert capsys.readouterr().err.startswith("sarif-kit: ")


def test_missing_input_exits_two(tmp_path, capsys):
    code = main(
        ["convert", "--tool", "yamllint", "-i", str(tmp_path / "nope.txt"), "-o", str(tmp_path / "out.sarif")]
    )
    assert code == 2
    assert capsys.readouterr().err.startswith("sarif-kit: ")


def test_auto_detects_the_tool(tmp_path):
    out = tmp_path / "results.sarif"
    code = main(["convert", "--auto", "-i", str(FIXTURE_DIR / "codespell" / "native.txt"), "-o", str(out)])
    assert code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert_valid(log)
    assert log["runs"][0]["tool"]["driver"]["name"] == "codespell"


def test_auto_with_no_match_exits_two(tmp_path, capsys):
    src = tmp_path / "mystery.txt"
    src.write_text("nothing any adapter recognizes\n", encoding="utf-8")
    code = main(["convert", "--auto", "-i", str(src), "-o", str(tmp_path / "out.sarif")])
    assert code == 2
    assert "--tool" in capsys.readouterr().err


def test_auto_with_ambiguous_input_exits_two(tmp_path, capsys):
    src = tmp_path / "mixed.txt"
    src.write_text(
        "a.yaml:1:1: [error] trailing spaces (trailing-spaces)\nb.py:2: teh ==> the\n",
        encoding="utf-8",
    )
    code = main(["convert", "--auto", "-i", str(src), "-o", str(tmp_path / "out.sarif")])
    assert code == 2
    err = capsys.readouterr().err
    assert "codespell" in err and "yamllint" in err and "--tool" in err


def test_fail_on_findings_with_findings(tmp_path):
    out = tmp_path / "out.sarif"
    code = main(
        [
            "convert",
            "--tool",
            "yamllint",
            "-i",
            str(FIXTURE_DIR / "yamllint" / "native.parsable.txt"),
            "-o",
            str(out),
            "--fail-on-findings",
        ]
    )
    assert code == 1
    assert_valid(json.loads(out.read_text(encoding="utf-8")))  # the log is still written


def test_fail_on_findings_with_a_clean_run(tmp_path):
    clean = tmp_path / "clean.json"
    clean.write_text('{"dependencies": [{"name": "packaging", "version": "24.2", "vulns": []}]}', encoding="utf-8")
    code = main(
        ["convert", "--auto", "-i", str(clean), "-o", str(tmp_path / "out.sarif"), "--fail-on-findings"]
    )
    assert code == 0


def test_tool_and_auto_together_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["convert", "--tool", "codespell", "--auto", "-i", "x", "-o", "y"])
    assert exc.value.code == 2


def test_tool_or_auto_is_required():
    with pytest.raises(SystemExit) as exc:
        main(["convert", "-i", "x", "-o", "y"])
    assert exc.value.code == 2


def test_validate_accepts_the_minimal_golden(capsys):
    assert main(["validate", str(GOLDEN_DIR / "minimal.sarif.json")]) == 0
    assert capsys.readouterr().err == ""


def test_validate_rejects_an_invalid_log(tmp_path, capsys):
    log = json.loads((GOLDEN_DIR / "minimal.sarif.json").read_text(encoding="utf-8"))
    del log["version"]
    bad = tmp_path / "bad.sarif"
    bad.write_text(json.dumps(log), encoding="utf-8")
    assert main(["validate", str(bad)]) == 1
    assert "version" in capsys.readouterr().err


def test_validate_rejects_non_json(tmp_path, capsys):
    bad = tmp_path / "bad.txt"
    bad.write_text("not json", encoding="utf-8")
    assert main(["validate", str(bad)]) == 2
    assert capsys.readouterr().err.startswith("sarif-kit: ")


def test_merge_keeps_one_run_per_input(tmp_path):
    out = tmp_path / "all.sarif"
    code = main(
        [
            "merge",
            "-o",
            str(out),
            str(GOLDEN_DIR / "yamllint.native.sarif.json"),
            str(GOLDEN_DIR / "codespell.native.sarif.json"),
        ]
    )
    assert code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert_valid(log)
    assert [run["tool"]["driver"]["name"] for run in log["runs"]] == ["yamllint", "codespell"]


def test_merge_rejects_a_non_sarif_input(tmp_path, capsys):
    bad = tmp_path / "notsarif.json"
    bad.write_text('{"version": "1.0"}', encoding="utf-8")
    code = main(["merge", "-o", str(tmp_path / "all.sarif"), str(GOLDEN_DIR / "minimal.sarif.json"), str(bad)])
    assert code == 2
    assert "notsarif.json" in capsys.readouterr().err


def test_merge_keeps_every_run_of_a_multi_run_input(tmp_path):
    both = json.loads((GOLDEN_DIR / "yamllint.native.sarif.json").read_text(encoding="utf-8"))
    both["runs"] = both["runs"] + json.loads(
        (GOLDEN_DIR / "codespell.native.sarif.json").read_text(encoding="utf-8")
    )["runs"]
    src = tmp_path / "pair.sarif"
    src.write_text(json.dumps(both), encoding="utf-8")
    out = tmp_path / "all.sarif"
    assert main(["merge", "-o", str(out), str(src), str(GOLDEN_DIR / "minimal.sarif.json")]) == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert len(log["runs"]) == 3


def test_merge_names_the_file_that_fails_the_schema(tmp_path, capsys):
    bad = tmp_path / "emptyrun.sarif"
    bad.write_text('{"version": "2.1.0", "runs": [{}]}', encoding="utf-8")
    code = main(["merge", "-o", str(tmp_path / "all.sarif"), str(GOLDEN_DIR / "minimal.sarif.json"), str(bad)])
    assert code == 2
    assert "emptyrun.sarif" in capsys.readouterr().err


def test_merge_writes_stdout(capsys):
    code = main(["merge", "-o", "-", str(GOLDEN_DIR / "minimal.sarif.json")])
    assert code == 0
    assert_valid(json.loads(capsys.readouterr().out))


def test_validate_reads_stdin(monkeypatch, capsys):
    raw = (GOLDEN_DIR / "minimal.sarif.json").read_text(encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    assert main(["validate", "-"]) == 0
    assert capsys.readouterr().err == ""


def test_convert_on_binary_input_exits_two(tmp_path, capsys):
    binary = tmp_path / "not-text.bin"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\xd8\xff")
    code = main(["convert", "--auto", "-i", str(binary), "-o", str(tmp_path / "out.sarif")])
    assert code == 2
    assert capsys.readouterr().err.startswith("sarif-kit: ")


def test_merge_refuses_more_runs_than_github_accepts(tmp_path, capsys):
    inputs = [str(GOLDEN_DIR / "minimal.sarif.json")] * (GITHUB_MAX_RUNS + 1)
    out = tmp_path / "all.sarif"
    code = main(["merge", "-o", str(out), *inputs])
    assert code == 2
    assert "21 runs" in capsys.readouterr().err
    assert not out.exists()


def test_merge_refuses_runs_that_would_share_a_category(tmp_path, capsys):
    out = tmp_path / "all.sarif"
    twice = str(GOLDEN_DIR / "yamllint.native.sarif.json")
    code = main(["merge", "-o", str(out), twice, twice])
    assert code == 2
    assert "yamllint" in capsys.readouterr().err
    assert not out.exists()


def test_merge_refuses_same_category_with_different_run_ids(tmp_path, capsys):
    # GitHub reads automationDetails.id as category/run-id, so these two runs share
    # the category "shared" despite having different ids.
    ids = ("shared/run-a", "shared/run-b")
    paths = []
    for name, run_id in zip(("a.sarif", "b.sarif"), ids):
        log = json.loads((GOLDEN_DIR / "yamllint.native.sarif.json").read_text(encoding="utf-8"))
        log["runs"][0]["automationDetails"] = {"id": run_id}
        path = tmp_path / name
        path.write_text(json.dumps(log), encoding="utf-8")
        paths.append(str(path))
    out = tmp_path / "all.sarif"
    assert main(["merge", "-o", str(out), *paths]) == 2
    assert "shared" in capsys.readouterr().err
    assert not out.exists()
