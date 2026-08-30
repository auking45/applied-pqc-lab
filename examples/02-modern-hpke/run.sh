#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Chapter 02 (RFC 9180 HPKE) Multi-Language Runner
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly NC="\033[0m"

run_cli_test() {
    echo -e "${BLUE}[1/4] Running OpenSSL 3.5 CLI ECDH (X25519) + HKDF + Symmetric Test...${NC}"
    local workdir
    workdir="$(mktemp -d /tmp/pqc_c02_XXXXXX)"

    # 1. Receiver X25519 keypair
    openssl genpkey -algorithm X25519 -out "${workdir}/rec_priv.pem" 2>/dev/null
    openssl pkey -in "${workdir}/rec_priv.pem" -pubout -out "${workdir}/rec_pub.pem" 2>/dev/null

    # 2. Sender Ephemeral Keypair & ECDH
    openssl genpkey -algorithm X25519 -out "${workdir}/ephem_priv.pem" 2>/dev/null
    openssl pkey -in "${workdir}/ephem_priv.pem" -pubout -out "${workdir}/ephem_pub.pem" 2>/dev/null

    # Derive shared secret (ECDH)
    openssl pkeyutl -derive -inkey "${workdir}/ephem_priv.pem" -peerkey "${workdir}/rec_pub.pem" -out "${workdir}/dh_shared.bin"

    # Derive 32-byte AES key via HKDF (OpenSSL 3.0+ kdf)
    local dh_hex
    dh_hex="$(xxd -p -c 64 "${workdir}/dh_shared.bin" | tr -d '\n')"
    openssl kdf -digest SHA256 -kdfopt "hexkey:${dh_hex}" -keylen 32 -binary -out "${workdir}/key.bin" HKDF

    # 3. Symmetric payload encrypt
    echo "RFC 9180 HPKE CLI Payload" > "${workdir}/plain.txt"
    local key_hex
    key_hex="$(xxd -p -c 64 "${workdir}/key.bin" | tr -d '\n')"
    openssl enc -aes-256-cbc -e -in "${workdir}/plain.txt" -out "${workdir}/cipher.bin" \
        -K "${key_hex}" -iv "00000000000000000000000000000001"

    # 4. Receiver ECDH & Decrypt
    openssl pkeyutl -derive -inkey "${workdir}/rec_priv.pem" -peerkey "${workdir}/ephem_pub.pem" -out "${workdir}/rec_dh.bin"
    local rec_dh_hex
    rec_dh_hex="$(xxd -p -c 64 "${workdir}/rec_dh.bin" | tr -d '\n')"
    openssl kdf -digest SHA256 -kdfopt "hexkey:${rec_dh_hex}" -keylen 32 -binary -out "${workdir}/rec_key.bin" HKDF

    local rec_key_hex
    rec_key_hex="$(xxd -p -c 64 "${workdir}/rec_key.bin" | tr -d '\n')"
    openssl enc -aes-256-cbc -d -in "${workdir}/cipher.bin" -out "${workdir}/decrypted.txt" \
        -K "${rec_key_hex}" -iv "00000000000000000000000000000001"

    diff -u "${workdir}/plain.txt" "${workdir}/decrypted.txt" >/dev/null
    rm -rf "${workdir}"
    echo -e "${GREEN}    [PASS] OpenSSL CLI HPKE DHKEM/HKDF test passed!${NC}"
}

run_python_test() {
    echo -e "${BLUE}[2/4] Running Python 3 (cryptography) Test...${NC}"
    if [[ -f "${SCRIPT_DIR}/../../.venv/bin/python3" ]]; then
        "${SCRIPT_DIR}/../../.venv/bin/python3" "${SCRIPT_DIR}/python/main.py"
    else
        python3 "${SCRIPT_DIR}/python/main.py"
    fi
    echo -e "${GREEN}    [PASS] Python HPKE Base Mode test passed!${NC}"
}

run_cpp_test() {
    echo -e "${BLUE}[3/4] Building and Running C++20 Test...${NC}"
    local bdir="/tmp/pqc_c02_cpp_build"
    mkdir -p "${bdir}"
    cmake -B "${bdir}" -S "${SCRIPT_DIR}/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "${bdir}" -j"$(nproc)" >/dev/null
    "${bdir}/modern_hpke"
    rm -rf "${bdir}"
    echo -e "${GREEN}    [PASS] C++20 HPKE Base Mode test passed!${NC}"
}

run_rust_test() {
    echo -e "${BLUE}[4/4] Building and Running Rust Test...${NC}"
    (cd "${SCRIPT_DIR}/rust" && cargo run --release --quiet)
    echo -e "${GREEN}    [PASS] Rust HPKE Base Mode test passed!${NC}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Chapter 02 Multi-Language Test Suite"
    echo "======================================================"

    run_cli_test
    run_python_test
    if command -v g++ >/dev/null 2>&1 && command -v cmake >/dev/null 2>&1; then
        run_cpp_test
    fi
    if command -v cargo >/dev/null 2>&1; then
        run_rust_test
    fi

    echo ""
    echo -e "${GREEN} All Chapter 02 tests passed successfully!${NC}"
    echo "======================================================"
}

main "$@"
