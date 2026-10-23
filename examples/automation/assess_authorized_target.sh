#!/usr/bin/env bash
# ==============================================================================
# WireScope Assessment & Reporting Pipeline for Explicitly Authorized Targets
#
# Validates the versioned assessment report against the JSON schema,
# and exports a formatted GFM Markdown summary.
# ==============================================================================

set -euo pipefail

WIRESCOPE_BIN="${WIRESCOPE_BIN:-wirescope}"
REPORT_JSON="${1:-examples/assessment_report.json}"
REPORT_MD="assessment_summary.md"

echo "=== 1. Validating Versioned Report Against Schema ($REPORT_JSON) ==="
"$WIRESCOPE_BIN" report validate "$REPORT_JSON"
echo "[PASS] Report validated against versioned schema."

echo "=== 2. Exporting Markdown Report (Safe Atomic Write) ==="
"$WIRESCOPE_BIN" report markdown "$REPORT_JSON" \
    --output "$REPORT_MD" \
    --force \
    --non-interactive

echo "=== Pipeline Complete: Generated $REPORT_MD successfully ==="
