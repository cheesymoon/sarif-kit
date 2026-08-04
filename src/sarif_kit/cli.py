"""Command line entry point.

Three subcommands. ``convert`` runs one adapter over one file and writes the SARIF log,
``validate`` checks an existing log against the schema, and ``merge`` joins several logs
into one. Anything that goes wrong prints a single line to stderr and exits 2. Exit 1
belongs to commands that ran fine and have something to report: findings under
``convert --fail-on-findings``, a log that fails validation under ``validate``.
"""

from __future__ import annotations

import argparse
import json
import sys

from .adapters import ADAPTERS, detect_tool, get_adapter
from .builder import GITHUB_MAX_RUNS, SarifBuilder, merge_logs, sarif_log_error
from .validate import assert_valid, validation_errors

#: Converted, valid or merged.
EXIT_OK = 0
#: convert --fail-on-findings saw results, or validate saw schema errors.
EXIT_FINDINGS = 1
#: Conversion, usage or IO error. argparse exits with the same code on bad usage.
EXIT_ERROR = 2

_EXIT_CODE_HELP = """\
exit codes:
  0  success
  1  findings present (convert --fail-on-findings) or schema-invalid (validate)
  2  conversion, usage or IO error
"""


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {"convert": _convert, "validate": _validate, "merge": _merge}
    return handlers[args.command](args)


def _convert(args: argparse.Namespace) -> int:
    try:
        # A file that isn't UTF-8 text raises UnicodeDecodeError, a ValueError. It has to
        # come back as exit 2 like any other bad input, never as an uncaught traceback,
        # whose exit 1 would read as "findings present" in CI.
        raw = _read(args.input)
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    if args.auto:
        matches = detect_tool(raw)
        if not matches:
            return _fail("could not detect the tool from the input; pass --tool")
        if len(matches) > 1:
            return _fail(
                "input matches more than one tool ("
                + ", ".join(matches)
                + "); pass --tool to pick one"
            )
        tool = matches[0]
    else:
        tool = args.tool
    if args.dep_file is not None and tool != "pip-audit":
        return _fail(f"--dep-file applies to pip-audit only, not to {tool}")

    try:
        adapter = get_adapter(tool)
        extra = {"dep_file": args.dep_file} if args.dep_file else {}
        rules, results = adapter.convert(raw, **extra)
        builder = SarifBuilder(
            adapter.TOOL_NAME,
            information_uri=adapter.INFORMATION_URI,
            src_root=args.src_root,
        )
        for rule in rules:
            builder.add_rule(rule)
        builder.add_results(results)
        log = builder.build()
        _write(args.output, json.dumps(log, indent=2) + "\n")
    except (OSError, ValueError) as exc:
        return _fail(str(exc))
    if args.fail_on_findings and log["runs"][0]["results"]:
        return EXIT_FINDINGS
    return EXIT_OK


def _validate(args: argparse.Namespace) -> int:
    try:
        log = json.loads(_read(args.path))
    except OSError as exc:
        return _fail(str(exc))
    except ValueError as exc:
        return _fail(f"input is not JSON: {exc}")
    errors = validation_errors(log)
    for error in errors:
        print(error, file=sys.stderr)
    return EXIT_FINDINGS if errors else EXIT_OK


def _merge(args: argparse.Namespace) -> int:
    logs = []
    for path in args.inputs:
        try:
            log = json.loads(_read(path))
        except OSError as exc:
            return _fail(str(exc))
        except ValueError as exc:
            return _fail(f"{path}: input is not JSON: {exc}")
        error = sarif_log_error(log)
        if error:
            return _fail(f"{path}: {error}")
        # Checked here rather than after merging, so the message names the file at
        # fault instead of a run index in the combined log.
        try:
            assert_valid(log)
        except ValueError as exc:
            return _fail(f"{path}: {exc}")
        logs.append(log)

    runs = sum(len(log["runs"]) for log in logs)
    if runs > GITHUB_MAX_RUNS:
        return _fail(
            f"the merged log would hold {runs} runs, and GitHub rejects files with more "
            f"than {GITHUB_MAX_RUNS}; upload them as separate files instead"
        )
    try:
        _write(args.output, json.dumps(merge_logs(logs), indent=2) + "\n")
    except OSError as exc:
        return _fail(str(exc))
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarif-kit",
        description="Convert native scanner output into SARIF 2.1.0 for GitHub Code Scanning.",
        epilog=_EXIT_CODE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    convert = commands.add_parser(
        "convert",
        help="convert one tool's output to SARIF",
        epilog="example: sarif-kit convert --tool pip-audit -i audit.json -o results.sarif",
    )
    tool = convert.add_mutually_exclusive_group(required=True)
    tool.add_argument("--tool", choices=sorted(ADAPTERS), help="tool that produced the input")
    tool.add_argument("--auto", action="store_true", help="detect the tool from the input shape")
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
    convert.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit 1 if the converted log contains any results",
    )

    validate = commands.add_parser(
        "validate",
        help="check a SARIF file against the 2.1.0 schema",
        epilog="example: sarif-kit validate results.sarif",
    )
    validate.add_argument("path", metavar="PATH", help="SARIF file to check, or - for stdin")

    merge = commands.add_parser(
        "merge",
        help="merge SARIF files into one log, keeping every input's runs",
        epilog="example: sarif-kit merge -o combined.sarif pip-audit.sarif yamllint.sarif",
    )
    merge.add_argument(
        "-o", "--output", required=True, metavar="PATH", help="SARIF file to write, or - for stdout"
    )
    merge.add_argument("inputs", nargs="+", metavar="INPUT", help="SARIF files to merge")

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
    return EXIT_ERROR
