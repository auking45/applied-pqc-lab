#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Local Documentation Setup & Server
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly VENV_DIR="${REPO_ROOT}/.venv"
readonly PYTHON_BIN="${VENV_DIR}/bin/python3"
readonly MKDOCS_BIN="${VENV_DIR}/bin/mkdocs"
readonly DEV_ADDR="127.0.0.1:8000"

check_prerequisites() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[-] Error: python3 is not installed or not found in PATH." >&2
        exit 1
    fi
}

setup_virtualenv() {
    if [ ! -d "${VENV_DIR}" ]; then
        echo "[+] Creating Python virtual environment in ${VENV_DIR}..."
        python3 -m venv "${VENV_DIR}"
    fi

    echo "[+] Updating pip..."
    "${PYTHON_BIN}" -m pip install --upgrade pip

    echo "[+] Installing dependencies from requirements.txt..."
    "${PYTHON_BIN}" -m pip install -r "${REPO_ROOT}/requirements.txt"

    if [ ! -f "${MKDOCS_BIN}" ]; then
        echo "[-] Error: mkdocs executable not found at ${MKDOCS_BIN}." >&2
        exit 1
    fi
}

start_server() {
    echo ""
    echo "======================================================"
    echo " 🚀 Starting MkDocs local live-reload server..."
    echo " 📖 Open in your browser: http://${DEV_ADDR}"
    echo " ⌨️  Press Ctrl+C to stop the server."
    echo "======================================================"
    echo ""

    exec "${MKDOCS_BIN}" serve --dev-addr "${DEV_ADDR}"
}

main() {
    cd "${REPO_ROOT}"

    echo "======================================================"
    echo " [Applied PQC Lab] Local Documentation Setup & Serve"
    echo "======================================================"

    check_prerequisites
    setup_virtualenv
    start_server
}

main "$@"
