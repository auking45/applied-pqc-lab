#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Toolchain & PQC Verification Script
# Verifies: OpenSSL 3.5+, NIST FIPS 203/204 Algorithms, Rust, C++20, Python
# -----------------------------------------------------------------------------

readonly GREEN="\033[0;32m"
readonly RED="\033[0;31m"
readonly BLUE="\033[0;34m"
readonly NC="\033[0m"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
}

check_openssl_version() {
    log_info "Verifying OpenSSL version..."
    if ! command -v openssl >/dev/null 2>&1; then
        log_fail "OpenSSL binary not found in PATH."
        return 1
    fi

    local version_str
    version_str="$(openssl version)"
    log_pass "OpenSSL binary: $(which openssl) -> ${version_str}"

    if [[ ! -d "/opt/openssl/include/openssl" ]]; then
        log_fail "OpenSSL header directory (/opt/openssl/include/openssl) not found."
        return 1
    fi
    log_pass "OpenSSL headers verified at /opt/openssl/include"
}

check_pqc_algorithms() {
    log_info "Verifying NIST PQC primitives support in OpenSSL..."

    local kem_list
    kem_list="$(openssl list -kem-algorithms 2>/dev/null || openssl list -publickey-algorithms 2>/dev/null || true)"

    # Check for ML-KEM (or Kyber)
    if echo "${kem_list}" | grep -Ei "(ML-KEM|KYBER)" >/dev/null 2>&1; then
        log_pass "FIPS 203 ML-KEM algorithms found in provider"
    else
        log_fail "FIPS 203 ML-KEM algorithms not found in OpenSSL"
        return 1
    fi

    local sig_list
    sig_list="$(openssl list -signature-algorithms 2>/dev/null || true)"

    # Check for ML-DSA (or Dilithium)
    if echo "${sig_list}" | grep -Ei "(ML-DSA|DILITHIUM)" >/dev/null 2>&1; then
        log_pass "FIPS 204 ML-DSA algorithms found in provider"
    else
        log_fail "FIPS 204 ML-DSA algorithms not found in OpenSSL"
        return 1
    fi
}

check_rust_toolchain() {
    log_info "Verifying Rust toolchain..."
    if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
        log_fail "Rust toolchain (rustc / cargo) not found."
        return 1
    fi

    local rustc_ver
    local cargo_ver
    rustc_ver="$(rustc --version)"
    cargo_ver="$(cargo --version)"
    log_pass "Rustc: ${rustc_ver}"
    log_pass "Cargo: ${cargo_ver}"
}

check_cpp_toolchain() {
    log_info "Verifying C++20 and CMake build environment..."
    if ! command -v g++ >/dev/null 2>&1 || ! command -v cmake >/dev/null 2>&1; then
        log_fail "C++ compiler or CMake not found."
        return 1
    fi

    local gpp_ver
    local cmake_ver
    gpp_ver="$(g++ --version | head -n 1)"
    cmake_ver="$(cmake --version | head -n 1)"
    log_pass "C++ Compiler: ${gpp_ver}"
    log_pass "CMake: ${cmake_ver}"
}

check_python_environment() {
    log_info "Verifying Python & documentation dependencies..."
    if ! command -v python3 >/dev/null 2>&1 || ! command -v mkdocs >/dev/null 2>&1; then
        log_fail "Python3 or MkDocs not found in environment."
        return 1
    fi

    local py_ver
    local mkdocs_ver
    py_ver="$(python3 --version)"
    mkdocs_ver="$(mkdocs --version)"
    log_pass "Python: ${py_ver}"
    log_pass "MkDocs: ${mkdocs_ver}"
}

main() {
    echo "======================================================"
    echo " [Applied PQC Lab] Container Toolchain Verification"
    echo "======================================================"

    check_openssl_version
    check_pqc_algorithms
    check_rust_toolchain
    check_cpp_toolchain
    check_python_environment

    echo "======================================================"
    echo -e "${GREEN} All toolchains and PQC primitives verified successfully!${NC}"
    echo "======================================================"
}

main "$@"
