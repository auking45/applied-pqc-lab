#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Chapter 04 (PQC X.509 PKI & E2E Encryption) Runner
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

run_cli_pki_test() {
    echo -e "${BLUE}[1/4] Running OpenSSL 3.5 CLI PKI Issuance & Encap Test...${NC}"
    local pki_dir="/tmp/pqc_c04_pki"
    rm -rf "${pki_dir}"
    bash "${SCRIPT_DIR}/run_pki.sh" "${pki_dir}"

    # CLI Encap / Decap with certificate public key
    openssl x509 -in "${pki_dir}/receiver.crt" -pubkey -noout -out "${pki_dir}/extracted_pub.pem"
    openssl pkeyutl -encap -pubin -inkey "${pki_dir}/extracted_pub.pem" -out "${pki_dir}/ct.bin" -secret "${pki_dir}/s_secret.bin"
    openssl pkeyutl -decap -inkey "${pki_dir}/receiver.key" -in "${pki_dir}/ct.bin" -secret "${pki_dir}/r_secret.bin"
    diff -u "${pki_dir}/s_secret.bin" "${pki_dir}/r_secret.bin" >/dev/null

    echo -e "${GREEN}    [PASS] OpenSSL CLI PQC PKI issuance & KEM test passed!${NC}"
}

run_python_test() {
    echo -e "${BLUE}[2/4] Running Python 3 Test...${NC}"
    local pki_dir="/tmp/pqc_c04_pki"
    local py_bin="python3"
    if [[ -f "/opt/venv/bin/python3" ]]; then
        py_bin="/opt/venv/bin/python3"
    elif [[ -f "${SCRIPT_DIR}/../../.venv/bin/python3" ]]; then
        py_bin="${SCRIPT_DIR}/../../.venv/bin/python3"
    fi
    "${py_bin}" "${SCRIPT_DIR}/python/main.py" "${pki_dir}"
    echo -e "${GREEN}    [PASS] Python PQC PKI E2E test passed!${NC}"
}

run_cpp_test() {
    echo -e "${BLUE}[3/4] Building and Running C++20 Test...${NC}"
    local pki_dir="/tmp/pqc_c04_pki"
    local bdir="/tmp/pqc_c04_cpp_build"
    mkdir -p "${bdir}"
    cmake -B "${bdir}" -S "${SCRIPT_DIR}/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "${bdir}" -j"$(nproc)" >/dev/null
    "${bdir}/pqc_x509_example" "${pki_dir}"
    rm -rf "${bdir}"
    echo -e "${GREEN}    [PASS] C++20 PQC PKI E2E test passed!${NC}"
}

run_rust_test() {
    echo -e "${BLUE}[4/4] Building and Running Rust Test...${NC}"
    local pki_dir="/tmp/pqc_c04_pki"
    (cd "${SCRIPT_DIR}/rust" && cargo run --release --quiet -- "${pki_dir}")
    echo -e "${GREEN}    [PASS] Rust PQC PKI E2E test passed!${NC}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Chapter 04 Multi-Language Test Suite"
    echo "======================================================"

    if ! openssl list -kem-algorithms 2>/dev/null | grep -qi "ML-KEM"; then
        echo -e "${YELLOW}[!] Current OpenSSL does not support native ML-KEM.${NC}"
        exit 0
    fi

    run_cli_pki_test
    run_python_test
    if command -v g++ >/dev/null 2>&1 && command -v cmake >/dev/null 2>&1; then
        run_cpp_test
    fi
    if command -v cargo >/dev/null 2>&1; then
        run_rust_test
    fi

    # Cleanup temp PKI files
    rm -rf /tmp/pqc_c04_pki

    echo ""
    echo -e "${GREEN} All Chapter 04 tests passed successfully!${NC}"
    echo "======================================================"
}

main "$@"
