"""Keep man/sarif-kit.1 in sync with the argparse surface.

Fails when a subcommand or long option exists on the parser but is missing from
the man page source. The page can mention things the parser does not have yet;
the reverse is the bug this guards against.
"""

from __future__ import annotations

from pathlib import Path

from sarif_kit.cli import _parser

# Roff escapes hyphens as \-, so normalize before searching.
MAN_SOURCE = (
    (Path(__file__).parent.parent / "man" / "sarif-kit.1")
    .read_text(encoding="utf-8")
    .replace("\\-", "-")
)


def _subcommands() -> dict:
    for group in _parser()._subparsers._group_actions:
        if hasattr(group, "choices"):
            return group.choices
    raise AssertionError("no subparsers found on sarif_kit.cli._parser()")


def test_every_subcommand_is_in_the_man_page():
    for name in _subcommands():
        assert name in MAN_SOURCE, f"subcommand {name} missing from man page"


def test_every_long_option_is_in_the_man_page():
    for name, sub in _subcommands().items():
        for action in sub._actions:
            for opt in action.option_strings:
                if opt.startswith("--"):
                    assert opt in MAN_SOURCE, f"{name} option {opt} missing from man page"


def test_the_contract_that_matters_is_documented():
    for phrase in ("EXIT STATUS", "concatenated", "stdin", "stdout"):
        assert phrase in MAN_SOURCE, f"man page no longer documents {phrase}"
