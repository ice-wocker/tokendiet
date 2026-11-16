#!/usr/bin/env bash
# TokenDiet One-Line Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ice-wocker/tokendiet/main/install.sh | bash

set -e

INSTALL_DIR="${HOME}/.local/bin"
TARGET="${INSTALL_DIR}/tokendiet"
REPO_RAW_URL="https://raw.githubusercontent.com/ice-wocker/tokendiet/main/tokendiet.py"

mkdir -p "${INSTALL_DIR}"

echo "🧊 Downloading TokenDiet..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${REPO_RAW_URL}" -o "${TARGET}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${TARGET}" "${REPO_RAW_URL}"
else
    echo "Error: curl or wget is required."
    exit 1
fi

chmod +x "${TARGET}"

echo "✓ TokenDiet installed successfully to: ${TARGET}"

# Check PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        echo "Notice: ${INSTALL_DIR} is not in your PATH."
        echo "Add it by running:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

echo ""
echo "Try running:"
echo "  tokendiet --help"
