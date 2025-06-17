#!/usr/bin/env bash

set -e

echo "Bootstrapping Python environment..."

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not found. Please install Python 3."
    exit 1
fi

# Install Poetry if not present
if ! command -v poetry &> /dev/null; then
    echo "INFO: Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
    echo
    echo "INFO: If you cannot run 'poetry' after this script, add the following to your shell profile:"
    echo 'export PATH="$HOME/.local/bin:$PATH"'
    echo "Then restart your terminal or run: source ~/.bashrc or source ~/.zshrc"
else
    echo "INFO: Poetry is already installed."¬
fi

# Show Poetry version and check if it works
if poetry --version &> /dev/null; then
    poetry --version
else
    echo "ERROR: Poetry installation failed or is not in PATH."
    exit 1
fi

echo "INFO: Bootstrap completed successfully."
