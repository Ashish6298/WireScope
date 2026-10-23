#!/usr/bin/env bash
# ==============================================================================
# WireScope Release Rehearsal Script (Bash / POSIX)
#
# Simulates full release artifact generation, packaging, and checksum verification
# ==============================================================================

set -euo pipefail

VERSION="${1:-0.1.0-rc1}"
ZIG="${2:-zig}"

echo "=== WireScope Release Rehearsal: v${VERSION} ==="

# 1. Build optimized ReleaseSafe binary
echo "1. Building optimized ReleaseSafe binary..."
${ZIG} build -Doptimize=ReleaseSafe

BINARY_PATH="zig-out/bin/wirescope"
if [ ! -f "${BINARY_PATH}" ]; then
  echo "Error: Binary not found at ${BINARY_PATH}"
  exit 1
fi

# 2. Smoke test executable
echo "2. Smoke testing binary..."
"${BINARY_PATH}" version
"${BINARY_PATH}" capabilities --format json > /dev/null
echo "   Smoke test passed!"

# 3. Create release package
echo "3. Creating release package..."
ARCHIVE_NAME="wirescope-v${VERSION}-linux-x86_64.tar.gz"
STAGE_DIR="rehearsal_dist"

rm -rf "${STAGE_DIR}" "${ARCHIVE_NAME}" "${ARCHIVE_NAME}.sha256"
mkdir -p "${STAGE_DIR}"

cp "${BINARY_PATH}" "${STAGE_DIR}/"
cp README.md LICENSE SECURITY.md "${STAGE_DIR}/"

tar -czf "${ARCHIVE_NAME}" -C "${STAGE_DIR}" .
echo "   Package created: ${ARCHIVE_NAME}"

# 4. Generate SHA-256 Checksum
echo "4. Computing SHA-256 Checksum..."
if command -v sha256sum > /dev/null 2>&1; then
  sha256sum "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
elif command -v shasum > /dev/null 2>&1; then
  shasum -a 256 "${ARCHIVE_NAME}" > "${ARCHIVE_NAME}.sha256"
fi
cat "${ARCHIVE_NAME}.sha256"

# 5. Verify Checksum
echo "5. Verifying Checksum integrity..."
if command -v sha256sum > /dev/null 2>&1; then
  sha256sum -c "${ARCHIVE_NAME}.sha256"
elif command -v shasum > /dev/null 2>&1; then
  shasum -a 256 -c "${ARCHIVE_NAME}.sha256"
fi
echo "   Checksum verified successfully!"

# 6. Cleanup
rm -rf "${STAGE_DIR}" "${ARCHIVE_NAME}" "${ARCHIVE_NAME}.sha256"

echo "=== Rehearsal Completed Successfully! All criteria passed. ==="
