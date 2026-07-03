#!/usr/bin/env sh
set -e

# Prismor installer
# Usage: curl -sSL https://prismor.dev/install | sh

# The `prismor` distribution owns the console entry points (prismor, immunity,
# prismor). Installing the legacy `immunity-agent` shim instead makes pipx
# refuse ("No apps associated with package") and leaves nothing on PATH.
PACKAGE="prismor"

echo "Installing Prismor..."

install_pipx() {
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y pipx
    elif command -v brew >/dev/null 2>&1; then
        brew install pipx
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y pipx
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm python-pipx
    else
        echo "Error: Could not install pipx. Install it manually from https://pipx.pypa.io and re-run."
        exit 1
    fi
}

pipx_install() {
    pipx install "$PACKAGE"
    # Make sure pipx's bin dir (~/.local/bin) is on PATH for new shells.
    pipx ensurepath >/dev/null 2>&1 || true
}

try_pip_install() {
    local pip_cmd="$1"
    output=$($pip_cmd install "$PACKAGE" 2>&1)
    if echo "$output" | grep -q "externally-managed-environment"; then
        return 1
    fi
    echo "$output"
    return 0
}

# 1. pipx already available — preferred path
if command -v pipx >/dev/null 2>&1; then
    pipx_install
# 2. pip available — try it; fall back to pipx if externally managed
elif command -v pip >/dev/null 2>&1; then
    if ! try_pip_install pip; then
        echo "pip blocked by externally-managed environment. Installing pipx..."
        install_pipx
        pipx_install
    fi
# 3. pip3 available — same logic
elif command -v pip3 >/dev/null 2>&1; then
    if ! try_pip_install pip3; then
        echo "pip3 blocked by externally-managed environment. Installing pipx..."
        install_pipx
        pipx_install
    fi
else
    echo "Error: Python pip not found. Install Python from https://python.org and try again."
    exit 1
fi

echo ""
echo "Run 'prismor setup' to get started (open a new shell if the command is not found)."
