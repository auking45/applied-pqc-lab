#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Chapter 03 (FIPS 203 ML-KEM & FIPS 204 ML-DSA) Runner
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly YELLOW="\033[0;33m"
readonly NC="\033[0m"

bin2hex() {
    if command -v xxd >/dev/null 2>&1; then
        xxd -p -c 64 "$1" | tr -d '\n'
    elif command -v hexdump >/dev/null 2>&1; then
        hexdump -ve '1/1 "%02x"' "$1"
    else
        python3 -c "import sys; sys.stdout.write(open(sys.argv[1], 'rb').read().hex())" "$1"
    fi
}

run_cli_test() {
    echo -e "${BLUE}[1/4] Running OpenSSL 3.5 CLI ML-KEM-768 & ML-DSA-65 Tests...${NC}"
    local workdir
    workdir="$(mktemp -d /tmp/pqc_c03_XXXXXX)"

    # --- 1. ML-KEM-768 Encap & Decap ---
    openssl genpkey -algorithm ML-KEM-768 -out "${workdir}/kem_priv.pem" 2>/dev/null
    openssl pkey -in "${workdir}/kem_priv.pem" -pubout -out "${workdir}/kem_pub.pem" 2>/dev/null
    openssl pkeyutl -encap -pubin -inkey "${workdir}/kem_pub.pem" -out "${workdir}/ct.bin" -secret "${workdir}/sender_secret.bin"
    openssl pkeyutl -decap -inkey "${workdir}/kem_priv.pem" -in "${workdir}/ct.bin" -secret "${workdir}/rec_secret.bin"
    diff -u "${workdir}/sender_secret.bin" "${workdir}/rec_secret.bin" >/dev/null

    # --- 2. ML-DSA-65 Sign & Verify ---
    openssl genpkey -algorithm ML-DSA-65 -out "${workdir}/dsa_priv.pem" 2>/dev/null
    openssl pkey -in "${workdir}/dsa_priv.pem" -pubout -out "${workdir}/dsa_pub.pem" 2>/dev/null
    echo "PQC Document Payload for Digital Signature" > "${workdir}/payload.txt"
    openssl pkeyutl -sign -inkey "${workdir}/dsa_priv.pem" -in "${workdir}/payload.txt" -out "${workdir}/sig.bin"
    openssl pkeyutl -verify -pubin -inkey "${workdir}/dsa_pub.pem" -sigfile "${workdir}/sig.bin" -in "${workdir}/payload.txt" >/dev/null

    rm -rf "${workdir}"
    echo -e "${GREEN}    [PASS] OpenSSL CLI ML-KEM-768 & ML-DSA-65 tests passed!${NC}"
}

run_python_test() {
    echo -e "${BLUE}[2/4] Running Python 3 Test...${NC}"
    local py_bin="python3"
    if [[ -f "/opt/venv/bin/python3" ]]; then
        py_bin="/opt/venv/bin/python3"
    elif [[ -f "${SCRIPT_DIR}/../../.venv/bin/python3" ]]; then
        py_bin="${SCRIPT_DIR}/../../.venv/bin/python3"
    fi
    "${py_bin}" "${SCRIPT_DIR}/python/main.py"
    echo -e "${GREEN}    [PASS] Python ML-KEM & ML-DSA test passed!${NC}"
}

run_cpp_test() {
    echo -e "${BLUE}[3/4] Building and Running C++20 Test...${NC}"
    local bdir="/tmp/pqc_c03_cpp_build"
    mkdir -p "${bdir}"
    cmake -B "${bdir}" -S "${SCRIPT_DIR}/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "${bdir}" -j"$(nproc)" >/dev/null
    "${bdir}/ml_kem_example"
    rm -rf "${bdir}"
    echo -e "${GREEN}    [PASS] C++20 ML-KEM & ML-DSA test passed!${NC}"
}

run_rust_test() {
    echo -e "${BLUE}[4/4] Building and Running Rust Test...${NC}"
    (cd "${SCRIPT_DIR}/rust" && cargo run --release --quiet)
    echo -e "${GREEN}    [PASS] Rust ML-KEM & ML-DSA test passed!${NC}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Chapter 03 Multi-Language Test Suite"
    echo "======================================================"

    if ! openssl list -kem-algorithms 2>/dev/null | grep -qi "ML-KEM"; then
        echo -e "${YELLOW}[!] Current OpenSSL does not support native ML-KEM.${NC}"
        exit 0
    fi

    run_cli_test
    run_python_test
    if command -v g++ >/dev/null 2>&1 && command -v cmake >/dev/null 2>&1; then
        run_cpp_test
    fi
    if command -v cargo >/dev/null 2>&1; then
        run_rust_test
    fi

    echo ""
    echo -e "${GREEN} All Chapter 03 tests passed successfully!${NC}"
    echo "======================================================"
}

main "$@"
