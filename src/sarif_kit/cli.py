"""Command line entry point.

One subcommand so far, ``sarif-kit convert``: run one adapter over one file and write the
SARIF log. Anything that goes wrong prints a single line to stderr and exits 2.
"""

from __future__ import annotations

import argparse
import json
import sys

from .adapters import ADAPTERS, get_adapter
from .builder import SarifBuilder


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.dep_file is not None and args.tool != "pip-audit":
        return _fail(f"--dep-file applies to pip-audit only, not to {args.tool}")

    try:
        adapter = get_adapter(args.tool)
        extra = {"dep_file": args.dep_file} if args.dep_file else {}
        rules, results = adapter.convert(_read(args.input), **extra)
        builder = SarifBuilder(
            adapter.TOOL_NAME,
            information_uri=adapter.INFORMATION_URI,
            src_root=args.src_root,
        )
        for rule in rules:
            builder.add_rule(rule)
        builder.add_results(results)
        _write(args.output, json.dumps(builder.build(), indent=2) + "\n")
    except (OSError, ValueError) as exc:
        return _fail(str(exc))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarif-kit",
        description="Convert native scanner output into SARIF 2.1.0 for GitHub Code Scanning.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    convert = commands.add_parser("convert", help="convert one tool's output to SARIF")
    convert.add_argument(
        "--tool", required=True, choices=sorted(ADAPTERS), help="tool that produced the input"
    )
    convert.add_argument(
        "-i", "--input", required=True, metavar="PATH", help="native output to read, or - for stdin"
    )
    convert.add_argument(
        "-o", "--output", required=True, metavar="PATH", help="SARIF file to write, or - for stdout"
    )
    convert.add_argument(
        "--src-root", metavar="PATH", help="repository root, used to make absolute paths relative"
    )
    convert.add_argument(
        "--dep-file",
        metavar="PATH",
        help="manifest pip-audit findings point at (default requirements.txt)",
    )
    return parser


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _fail(message: str) -> int:
    print(f"sarif-kit: {message}", file=sys.stderr)
    return 2
