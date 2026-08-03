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

The Step 2 core is done: `src/sarif_kit/` has the SARIF builder, validation against the
vendored schema, stable fingerprinting, and severity mapping. Adapters come in Step 3.

## Development

```bash
uv sync
uv run pytest            # unit + golden + schema-validation tests
UPDATE_GOLDEN=1 uv run pytest   # refresh golden files after an intentional change
```

### Step-2 gate: does it actually upload

A schema-valid file still isn't guaranteed to upload; GitHub applies extra rules of its
own. This gate runs a real upload:

1. Push this repo to a GitHub repo with Code Scanning (a public repo gets it for free; a
   private one needs GitHub Advanced Security).
2. In the Actions tab, pick "Upload gate" and hit "Run workflow".
3. Under Security > Code scanning, the alert "sarif-kit end-to-end upload gate" should
   show up with a clickable `README.md:1` link.

To build the gate SARIF locally: `uv run python scripts/gate_minimal_sarif.py gate.sarif`.
