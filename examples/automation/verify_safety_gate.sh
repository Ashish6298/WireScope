#!/usr/bin/env bash
# ==============================================================================
# WireScope Safety Gate Verification
#
# Verifies that non-interactive mode strictly enforces authorization gates
# and will never silently bypass scope limits on remote targets.
# ==============================================================================

set -euo pipefail

WIRESCOPE_BIN="${1:-${WIRESCOPE_BIN:-wirescope}}"
REMOTE_TARGET="192.168.1.100"

echo "=== Test 1: Remote target in non-interactive mode without confirmation ==="
set +e
"$WIRESCOPE_BIN" discover "$REMOTE_TARGET" --preview --non-interactive 2> error.log
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 2 ]; then
    echo "[SUCCESS] Safety gate held! WireScope exited with code 2 (invalid_input)."
    echo "Reported error: $(cat error.log)"
else
    echo "[FAILURE] Expected exit code 2 but got $EXIT_CODE"
    exit 1
fi

echo "=== Test 2: Remote target with explicit --confirm-authorized ==="
"$WIRESCOPE_BIN" discover "$REMOTE_TARGET" \
    --preview \
    --confirm-authorized \
    --non-interactive \
    --format json > plan.json

echo "[SUCCESS] Explicitly authorized plan generated without prompts!"
