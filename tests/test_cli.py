"""Smoke tests for the convert subcommand."""

from __future__ import annotations

import io
import json

from sarif_kit import assert_valid
from sarif_kit.cli import main

from .utils import FIXTURE_DIR


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
