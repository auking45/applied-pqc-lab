#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Multi-Chapter E2E Test Suite Runner
# Usage:
#   ./scripts/test_all.sh         # Run all chapter test suites
#   ./scripts/test_all.sh 01      # Run specific chapter (e.g. 01)
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly GREEN="\033[0;32m"
readonly BLUE="\033[0;34m"
readonly YELLOW="\033[0;33m"
readonly RED="\033[0;31m"
readonly BOLD="\033[1m"
readonly NC="\033[0m"

log_banner() {
    echo ""
    echo -e "${BOLD}======================================================${NC}"
    echo -e "${BOLD} $1${NC}"
    echo -e "${BOLD}======================================================${NC}"
}

run_chapter_test() {
    local chapter_dir="$1"
    local chapter_name="$(basename "${chapter_dir}")"
    local run_script="${chapter_dir}/run.sh"

    if [[ ! -f "${run_script}" ]]; then
        echo -e "${YELLOW}[SKIP] No run.sh found in ${chapter_name}${NC}"
        return 0
    fi

    log_banner "Running Test Suite: ${chapter_name}"
    local start_time
    start_time="$(date +%s)"

    if bash "${run_script}"; then
        local elapsed=$(( $(date +%s) - start_time ))
        echo -e "${GREEN}[PASS] ${chapter_name} completed successfully (${elapsed}s)${NC}"
        return 0
    else
        echo -e "${RED}[FAIL] ${chapter_name} failed!${NC}" >&2
        return 1
    fi
}

main() {
    cd "${REPO_ROOT}"

    local target_filter="${1:-all}"
    local passed_count=0
    local failed_count=0
    local failed_list=()

    log_banner "Applied PQC Lab - Master Test Runner"
    echo "Target Filter: ${target_filter}"

    local chapter_dirs=()
    if [[ "${target_filter}" == "all" ]]; then
        while IFS= read -r dir; do
            [[ -n "${dir}" ]] && chapter_dirs+=("${dir}")
        done < <(find "${REPO_ROOT}/examples" -mindepth 1 -maxdepth 1 -type d | sort)
    else
        while IFS= read -r dir; do
            [[ -n "${dir}" ]] && chapter_dirs+=("${dir}")
        done < <(find "${REPO_ROOT}/examples" -mindepth 1 -maxdepth 1 -type d -name "*${target_filter}*" | sort)
    fi

    if [[ ${#chapter_dirs[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[!] No matching chapter found in examples/ for query: '${target_filter}'${NC}"
        exit 1
    fi

    local total_start
    total_start="$(date +%s)"

    for cdir in "${chapter_dirs[@]}"; do
        if run_chapter_test "${cdir}"; then
            passed_count=$((passed_count + 1))
        else
            failed_count=$((failed_count + 1))
            failed_list+=("$(basename "${cdir}")")
        fi
    done

    local total_elapsed=$(( $(date +%s) - total_start ))

    log_banner "Test Execution Summary"
    echo -e "Total Chapters Tested : ${BOLD}$((passed_count + failed_count))${NC}"
    echo -e "Passed                : ${GREEN}${BOLD}${passed_count}${NC}"
    echo -e "Failed                : ${RED}${BOLD}${failed_count}${NC}"
    echo -e "Total Elapsed Time    : ${BOLD}${total_elapsed}s${NC}"

    if [[ ${failed_count} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Failed Chapters:${NC}"
        for f in "${failed_list[@]}"; do
            echo -e "  - ${RED}${f}${NC}"
        done
        exit 1
    else
        echo ""
        echo -e "${GREEN}${BOLD}🎉 All tests passed with zero errors!${NC}"
        exit 0
    fi
}

main "$@"
