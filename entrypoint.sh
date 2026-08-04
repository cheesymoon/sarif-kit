#!/bin/sh
# Entry point for the container action. Turns the action's inputs into one
# `sarif-kit convert` call.
#
# The inputs arrive as the environment variables named in action.yml rather than
# the INPUT_* ones GitHub sets on its own: a hyphenated input like src-root
# becomes INPUT_SRC-ROOT, which no shell can read as a variable.
set -eu

if [ "$SARIF_KIT_TOOL" = "auto" ]; then
    set -- --auto
else
    set -- --tool "$SARIF_KIT_TOOL"
fi

set -- "$@" -i "$SARIF_KIT_INPUT" -o "$SARIF_KIT_OUTPUT"

if [ -n "${SARIF_KIT_SRC_ROOT:-}" ]; then
    set -- "$@" --src-root "$SARIF_KIT_SRC_ROOT"
fi

if [ -n "${SARIF_KIT_DEP_FILE:-}" ]; then
    set -- "$@" --dep-file "$SARIF_KIT_DEP_FILE"
fi

if [ "${SARIF_KIT_FAIL_ON_FINDINGS:-false}" = "true" ]; then
    set -- "$@" --fail-on-findings
fi

exec sarif-kit convert "$@"
