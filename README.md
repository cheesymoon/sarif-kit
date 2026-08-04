# sarif-kit

**Convert the native output of scanners and linters that never added SARIF support into valid SARIF 2.1.0 for GitHub Code Scanning.**

A lot of common tools still can't emit [SARIF](https://sarifweb.azurewebsites.net/), the
format GitHub Code Scanning reads: pip-audit, codespell, yamllint, and a long tail of
others. People have asked the maintainers for years and most of those requests are still
open. sarif-kit is the stopgap. Point it at a tool's existing JSON or text output and it
gives you SARIF you can pass straight to `github/codeql-action/upload-sarif`.

```bash
uvx sarif-kit convert --tool pip-audit -i audit.json -o results.sarif
```

## Quickstart

Capture the tool's native output, convert it, upload the result. With pip-audit:

```bash
pip-audit -r requirements.txt -f json > pip-audit.json || true
uvx sarif-kit convert --tool pip-audit -i pip-audit.json -o results.sarif --dep-file requirements.txt
```

If you would rather not name the tool, `--auto` detects it from the shape of the
input. When the input matches no known tool, or matches more than one, sarif-kit
stops and asks for `--tool` instead of picking one for you:

```bash
uvx sarif-kit convert --auto -i yamllint.txt -o results.sarif
```

Check any SARIF file against the vendored 2.1.0 schema, and combine several files
into one log before uploading:

```bash
uvx sarif-kit validate results.sarif
uvx sarif-kit merge -o combined.sarif pip-audit.sarif yamllint.sarif
```

Merging concatenates the runs of every input, and each run keeps its own tool
and rules. GitHub accepts at most 20 runs per uploaded file, so `merge` refuses
to write more than that rather than handing you a file the upload will reject.
Merge one file per tool: GitHub tells analyses apart by tool and category, so
two runs of the same tool belong in separate uploads with separate categories.

`-i` and `-o` accept `-` for stdin and stdout, and `validate` reads stdin the
same way. `--src-root` rewrites absolute paths relative to your repository root,
which is what makes the file links in an alert resolve. `--fail-on-findings`
makes `convert` exit 1 when the input contained findings, so a job can fail on
them without running a second command.

Exit codes, so CI can branch on them:

| code | meaning |
|---|---|
| 0 | success |
| 1 | findings present (`convert --fail-on-findings`) or schema-invalid (`validate`) |
| 2 | conversion, usage or IO error |

There is a man page in `man/sarif-kit.1`; pip and uvx installs do not put it on
MANPATH, so read it with `man -l man/sarif-kit.1`.

## Supported tools

One page per adapter, each with the exact capture command, the severity mapping, and a
copy-paste CI snippet:

- [pip-audit](docs/pip-audit.md): one alert per advisory, linked to osv.dev
- [yamllint](docs/yamllint.md): parsable output, line and column preserved
- [codespell](docs/codespell.md): typo and suggested correction per alert

More adapters are planned.

Here is a pip-audit finding as GitHub renders it, converted by sarif-kit and uploaded
through `upload-sarif`:

![A pip-audit finding rendered as a GitHub Code Scanning alert](docs/img/pip-audit-alert.jpg)

## Positioning: how sarif-kit is different

sarif-kit only goes one way: native tool output into SARIF. A few nearby tools sound like
they do the same thing but don't:

- microsoft/sarif-tools and the "SARIF Converter" Marketplace action go the other way,
  turning SARIF into CSV or HTML. sarif-kit produces the SARIF they read.
- MegaLinter and reviewdog want you to adopt their whole pipeline. sarif-kit is one
  converter you drop into the CI you already run.
- node-sarif-builder is a library for tool authors writing SARIF by hand. sarif-kit is a
  finished CLI and GitHub Action for people who just want a scanner's output uploaded,
  with the adapters and fingerprinting already handled.

Every adapter gets checked in GitHub's real Code Scanning UI, on top of schema
validation. If the alert doesn't show the right title, severity, and file/line link, it
isn't done.

## Status

Early days. `PLAN.md` has the roadmap and `NOTES.md` has the launch and ground-check notes.
Apache-2.0, Python 3.11+, managed with `uv`, SARIF 2.1.0 only.

The core is done: `src/sarif_kit/` has the SARIF builder, validation against the
vendored schema, stable fingerprinting, and severity mapping. The first three adapters
(pip-audit, yamllint, codespell) are in, and the CLI is complete: `convert` with
`--auto` detection, `validate`, `merge`, a man page, and exit codes CI can branch on.

## Development

```bash
uv sync
uv run pytest            # unit + golden + schema-validation tests
UPDATE_GOLDEN=1 uv run pytest   # refresh golden files after an intentional change
```

### Upload gate: does it actually upload

A schema-valid file still isn't guaranteed to upload; GitHub applies extra rules of its
own. This gate runs a real upload:

1. Push this repo to a GitHub repo with Code Scanning (a public repo gets it for free; a
   private one needs GitHub Advanced Security).
2. In the Actions tab, pick "Upload gate" and hit "Run workflow".
3. Under Security > Code scanning, the alert "sarif-kit end-to-end upload gate" should
   show up with a clickable `README.md:1` link.

The same workflow also runs each supported tool against its committed fixture input,
converts the fresh output with the real CLI, and uploads one SARIF per tool. Check that
every adapter's alerts show the right title, severity, and file/line link.

To build the gate SARIF locally: `uv run python scripts/gate_minimal_sarif.py gate.sarif`.
