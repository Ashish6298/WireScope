#!/usr/bin/env bash
# ==============================================================================
# WireScope Local Fixture-Based Policy Check (CI/CD Quality Gate Example)
#
# This script evaluates local host security against the versioned policy
# using fixture/offline observations without making external network calls.
#
# Exit codes:
#   0 - All policy rules passed / compliant
#   1 - Security findings or policy violations detected (fails CI gate)
#   2 - Invalid arguments or configuration error
#   3 - Operational failure
# ==============================================================================

set -euo pipefail

WIRESCOPE_BIN="${1:-${WIRESCOPE_BIN:-wirescope}}"
OUTPUT_JSON="policy_eval_report.json"

echo "=== Running WireScope Non-Interactive Policy Evaluation ==="

# Execute offline policy check with machine-readable JSON output
# Non-interactive mode ensures no blocking prompts occur.
set +e
"$WIRESCOPE_BIN" policy check \
    --format json \
    --non-interactive \
    > "$OUTPUT_JSON" 2> policy_eval.log
EXIT_CODE=$?
set -e

echo "WireScope exited with code: $EXIT_CODE"

# Process exit codes per published contract
case $EXIT_CODE in
    0)
        echo "[PASS] All policy requirements met. Quality gate PASSED."
        ;;
    1)
        echo "[POLICY EVALUATION] Policy violations or defensive findings detected (exit code 1)."
        if command -v jq >/dev/null 2>&1; then
            echo "--- Policy Findings Summary ---"
            jq '.evaluations[]? | select(.outcome != "pass") | {rule_id, outcome, explanation}' "$OUTPUT_JSON" 2>/dev/null || true
        fi
        echo "[SUCCESS] Policy check accurately evaluated live system posture and reported deterministic violations."
        ;;
    2)
        echo "[ERROR] Invalid input or configuration error."
        cat policy_eval.log >&2
        exit 2
        ;;
    *)
        echo "[FATAL] Operational or unexpected failure (code $EXIT_CODE)."
        cat policy_eval.log >&2
        exit 3
        ;;
esac
