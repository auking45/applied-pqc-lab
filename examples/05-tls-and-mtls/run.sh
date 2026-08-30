#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Chapter 05 (PQC TLS 1.3 / mTLS) Runner
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly YELLOW="\033[0;33m"
readonly NC="\033[0m"

readonly CERTS_DIR="/tmp/pqc_c05_certs"
readonly PORT="14433"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill -9 "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${CERTS_DIR}"
}
trap cleanup EXIT

start_pqc_server() {
    echo -e "${BLUE}[*] Launching OpenSSL 3.5 PQC TLS 1.3 mTLS Server on port ${PORT}...${NC}"
    rm -rf "${CERTS_DIR}"
    bash "${SCRIPT_DIR}/generate_certs.sh" "${CERTS_DIR}"

    openssl s_server -accept "${PORT}"         -cert "${CERTS_DIR}/server.crt" -key "${CERTS_DIR}/server.key"         -CAfile "${CERTS_DIR}/ca.crt"         -Verify 1 -groups mlkem768 -tls1_3 -www >/dev/null 2>&1 &
    SERVER_PID=$!
    sleep 1
}

run_cli_test() {
    echo -e "${BLUE}[1/4] Running OpenSSL 3.5 CLI mTLS Client Test...${NC}"
    local output
    output=$(echo "GET / HTTP/1.0" | openssl s_client -connect "127.0.0.1:${PORT}"         -cert "${CERTS_DIR}/client.crt" -key "${CERTS_DIR}/client.key"         -CAfile "${CERTS_DIR}/ca.crt"         -groups mlkem768 -tls1_3 -verify_return_error 2>&1)

    if ! echo "${output}" | grep -q "Verify return code: 0 (ok)"; then
        echo "CLI test failed: ${output}"
        exit 1
    fi
    echo -e "${GREEN}    [PASS] OpenSSL CLI PQC mTLS test passed!${NC}"
}

run_python_test() {
    echo -e "${BLUE}[2/4] Running Python 3 Test...${NC}"
    local py_bin="python3"
    if [[ -f "/opt/venv/bin/python3" ]]; then
        py_bin="/opt/venv/bin/python3"
    elif [[ -f "${SCRIPT_DIR}/../../.venv/bin/python3" ]]; then
        py_bin="${SCRIPT_DIR}/../../.venv/bin/python3"
    fi
    "${py_bin}" "${SCRIPT_DIR}/python/main.py" "${CERTS_DIR}" "${PORT}"
    echo -e "${GREEN}    [PASS] Python PQC mTLS test passed!${NC}"
}

run_cpp_test() {
    echo -e "${BLUE}[3/4] Building and Running C++20 Test...${NC}"
    local bdir="/tmp/pqc_c05_cpp_build"
    mkdir -p "${bdir}"
    cmake -B "${bdir}" -S "${SCRIPT_DIR}/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "${bdir}" -j"$(nproc)" >/dev/null
    "${bdir}/pqc_tls_client" "${CERTS_DIR}" "${PORT}"
    rm -rf "${bdir}"
    echo -e "${GREEN}    [PASS] C++20 PQC mTLS test passed!${NC}"
}

run_rust_test() {
    echo -e "${BLUE}[4/4] Building and Running Rust Test...${NC}"
    (cd "${SCRIPT_DIR}/rust" && cargo run --release --quiet -- "${CERTS_DIR}" "${PORT}")
    echo -e "${GREEN}    [PASS] Rust PQC mTLS test passed!${NC}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Chapter 05 Multi-Language Test Suite"
    echo "======================================================"

    if ! openssl list -kem-algorithms 2>/dev/null | grep -qi "ML-KEM"; then
        echo -e "${YELLOW}[!] Current OpenSSL does not support native ML-KEM.${NC}"
        exit 0
    fi

    start_pqc_server

    run_cli_test
    run_python_test
    if command -v g++ >/dev/null 2>&1 && command -v cmake >/dev/null 2>&1; then
        run_cpp_test
    fi
    if command -v cargo >/dev/null 2>&1; then
        run_rust_test
    fi

    echo ""
    echo -e "${GREEN} All Chapter 05 tests passed successfully!${NC}"
    echo "======================================================"
}

main "$@"
