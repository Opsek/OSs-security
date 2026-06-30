#!/usr/bin/env bash
# ==============================================================================
# OPSEK macOS test runner
#
# Runs the shell-level verification suite. There is no CI in this repo, so this
# is the gate: run it before shipping any change to the backup / restore path.
#
#   bash macos/tests/run.sh
#
# Exit status is non-zero if any test fails, so it can be wired into a hook or a
# documented `make verify`.
# ==============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0

echo "### OPSEK shell test suite"
echo

echo ">>> roundtrip_test.sh"
bash "$DIR/roundtrip_test.sh" || rc=1
echo

if [[ "$rc" -eq 0 ]]; then
    echo "### ALL SUITES GREEN"
else
    echo "### SUITE FAILURES (see above)"
fi
exit "$rc"
