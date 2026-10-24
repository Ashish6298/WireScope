#!/usr/bin/env bash
# ==============================================================================
# WireScope Global Installation Script (Linux / macOS)
# ==============================================================================

set -euo pipefail

echo "=== Installing WireScope Globally ==="

# Build optimized binary
echo "Building optimized release binary (ReleaseSafe)..."
zig build -Doptimize=ReleaseSafe

SOURCE_BIN="zig-out/bin/wirescope"
if [ ! -f "$SOURCE_BIN" ]; then
    echo "[ERROR] Built binary not found at $SOURCE_BIN"
    exit 1
fi

INSTALL_DIR="${1:-${HOME}/.local/bin}"
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_BIN" "$INSTALL_DIR/wirescope"
chmod +x "$INSTALL_DIR/wirescope"

echo "[SUCCESS] WireScope installed globally to: $INSTALL_DIR/wirescope"
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "Notice: Ensure '$INSTALL_DIR' is added to your PATH in ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
