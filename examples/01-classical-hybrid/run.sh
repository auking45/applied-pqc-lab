#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Chapter 01 (Classical Hybrid) Multi-Language Runner
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly NC="\033[0m"

run_cli_test() {
    echo -e "${BLUE}[1/4] Running OpenSSL 3.5 CLI Key Wrapping & Symmetric Test...${NC}"
    local workdir
    workdir="$(mktemp -d /tmp/pqc_c01_XXXXXX)"

    # 1. Receiver RSA keypair
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${workdir}/priv.pem" 2>/dev/null
    openssl pkey -in "${workdir}/priv.pem" -pubout -out "${workdir}/pub.pem" 2>/dev/null

    # 2. Sender DEK & Wrap
    openssl rand 32 > "${workdir}/dek.bin"
    openssl rand -hex 16 > "${workdir}/iv.hex"
    openssl pkeyutl -encrypt -pubin -inkey "${workdir}/pub.pem" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
        -in "${workdir}/dek.bin" -out "${workdir}/wrapped.bin"

    # 3. Payload encrypt
    echo "Classical Hybrid CLI Verification" > "${workdir}/plain.txt"
    openssl enc -aes-256-cbc -e -in "${workdir}/plain.txt" -out "${workdir}/cipher.bin" \
        -K "$(xxd -p -c 64 "${workdir}/dek.bin" | tr -d '\n')" -iv "$(cat "${workdir}/iv.hex" | tr -d '\n')"

    # 4. Receiver Unwrap & Decrypt
    openssl pkeyutl -decrypt -inkey "${workdir}/priv.pem" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
        -in "${workdir}/wrapped.bin" -out "${workdir}/unwrapped.bin"

    openssl enc -aes-256-cbc -d -in "${workdir}/cipher.bin" -out "${workdir}/decrypted.txt" \
        -K "$(xxd -p -c 64 "${workdir}/unwrapped.bin" | tr -d '\n')" -iv "$(cat "${workdir}/iv.hex" | tr -d '\n')"

    diff -u "${workdir}/plain.txt" "${workdir}/decrypted.txt" >/dev/null
    rm -rf "${workdir}"
    echo -e "${GREEN}    [PASS] OpenSSL CLI Classical Hybrid test passed!${NC}"
}

run_python_test() {
    echo -e "${BLUE}[2/4] Running Python 3 (cryptography) Test...${NC}"
    if [[ -f "${SCRIPT_DIR}/../../.venv/bin/python3" ]]; then
        "${SCRIPT_DIR}/../../.venv/bin/python3" "${SCRIPT_DIR}/python/main.py"
    else
        python3 "${SCRIPT_DIR}/python/main.py"
    fi
    echo -e "${GREEN}    [PASS] Python Classical Hybrid test passed!${NC}"
}

run_cpp_test() {
    echo -e "${BLUE}[3/4] Building and Running C++20 Test...${NC}"
    local bdir="/tmp/pqc_c01_cpp_build"
    mkdir -p "${bdir}"
    cmake -B "${bdir}" -S "${SCRIPT_DIR}/cpp" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "${bdir}" -j"$(nproc)" >/dev/null
    "${bdir}/classical_hybrid"
    rm -rf "${bdir}"
    echo -e "${GREEN}    [PASS] C++20 Classical Hybrid test passed!${NC}"
}

run_rust_test() {
    echo -e "${BLUE}[4/4] Building and Running Rust Test...${NC}"
    (cd "${SCRIPT_DIR}/rust" && cargo run --release --quiet)
    echo -e "${GREEN}    [PASS] Rust Classical Hybrid test passed!${NC}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Chapter 01 Multi-Language Test Suite"
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
    echo -e "${GREEN} All Chapter 01 tests passed successfully!${NC}"
    echo "======================================================"
}

main "$@"
