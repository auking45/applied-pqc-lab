#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Applied PQC Lab - Docker Environment Automation Script
# -----------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DOCKER_CMD="docker"
DOCKER_COMPOSE_CMD=""

detect_compose() {
    if command -v docker >/dev/null 2>&1; then
        # Check if docker daemon is accessible without sudo
        if docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            DOCKER_COMPOSE_CMD="docker compose"
            DOCKER_CMD="docker"
        elif sudo docker compose version >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
            DOCKER_COMPOSE_CMD="sudo docker compose"
            DOCKER_CMD="sudo docker"
        elif command -v docker-compose >/dev/null 2>&1; then
            if docker-compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
                DOCKER_COMPOSE_CMD="docker-compose"
                DOCKER_CMD="docker"
            else
                DOCKER_COMPOSE_CMD="sudo docker-compose"
                DOCKER_CMD="sudo docker"
            fi
        else
            DOCKER_COMPOSE_CMD="docker compose"
            DOCKER_CMD="docker"
        fi
    elif command -v podman-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE_CMD="podman-compose"
        DOCKER_CMD="podman"
    fi
}

install_docker() {
    echo ""
    echo "======================================================"
    echo " [Applied PQC Lab] Automated Docker Engine Installation"
    echo "======================================================"

    echo "[+] Updating apt repositories and installing prerequisites..."
    sudo apt-get update -y
    sudo apt-get install -y ca-certificates curl gnupg lsb-release

    echo "[+] Configuring Docker official GPG key..."
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    echo "[+] Registering Docker APT repository..."
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    echo "[+] Installing Docker Engine, CLI, and Compose plugin..."
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    echo "[+] Adding current user (${USER}) to docker group..."
    sudo usermod -aG docker "${USER}" || true

    echo "[+] Starting Docker service..."
    if command -v systemctl >/dev/null 2>&1 && systemctl is-systemd-running >/dev/null 2>&1; then
        sudo systemctl enable --now docker || true
    else
        sudo service docker start || true
    fi

    echo ""
    echo "======================================================"
    echo " [OK] Docker Engine & Compose installed successfully!"
    echo "💡 Tip: Run 'newgrp docker' to apply group changes in current shell."
    echo "======================================================"
    echo ""
}

check_prerequisites() {
    detect_compose

    if [[ -z "${DOCKER_COMPOSE_CMD}" ]]; then
        echo "[-] Docker or Docker Compose is not installed on this system."

        if [[ -t 0 ]]; then
            read -r -p "[?] Would you like to install Docker Engine directly now? [y/N]: " reply
            case "${reply}" in
                [yY][eE][sS]|[yY])
                    install_docker
                    detect_compose
                    ;;
                *)
                    echo "[*] Installation cancelled."
                    exit 1
                    ;;
            esac
        else
            echo "💡 Run './scripts/run_docker.sh install' to install Docker automatically." >&2
            exit 1
        fi
    fi

    if [[ -z "${DOCKER_COMPOSE_CMD}" ]]; then
        echo "[-] Error: Failed to find or configure Docker Compose." >&2
        exit 1
    fi
}

cmd_pull() {
    echo "[+] Pulling prebuilt Applied PQC Lab container image from GHCR..."
    ${DOCKER_COMPOSE_CMD} pull lab "$@"
}

cmd_build() {
    echo "[+] Building Applied PQC Lab container image locally..."
    ${DOCKER_COMPOSE_CMD} build lab "$@"
}

cmd_verify() {
    echo "[+] Verifying toolchain and OpenSSL 3.5+ PQC primitives in container..."
    ${DOCKER_COMPOSE_CMD} run --rm lab ./docker/verify_toolchain.sh
}

cmd_shell() {
    echo "[+] Entering interactive PQC Lab container..."
    ${DOCKER_COMPOSE_CMD} run --rm lab /bin/bash
}

cmd_down() {
    echo "[+] Stopping running containers..."
    ${DOCKER_COMPOSE_CMD} down
}

print_usage() {
    cat <<EOF2
Usage: $(basename "$0") <command> [options]

Commands:
  pull           Pull prebuilt image from GitHub Container Registry (Fastest)
  shell          Enter the interactive PQC lab container (default)
  verify, test   Run toolchain and PQC algorithm verification in Docker
  build          Build the Docker lab container image locally from source
  down, clean    Stop running containers
  install        Install Docker Engine & Docker Compose on this system
  help           Show this help message

Examples:
  ./scripts/run_docker.sh pull      # 10s fast download from GHCR
  ./scripts/run_docker.sh verify    # Run E2E PQC verification
  ./scripts/run_docker.sh shell     # Enter interactive shell
  ./scripts/run_docker.sh build     # Local source rebuild
EOF2
}

main() {
    cd "${REPO_ROOT}"

    local action="${1:-shell}"
    if [[ $# -gt 0 ]]; then
        shift
    fi

    if [[ "${action}" == "install" ]]; then
        install_docker
        exit 0
    fi

    if [[ "${action}" == "help" || "${action}" == "-h" || "${action}" == "--help" ]]; then
        print_usage
        exit 0
    fi

    check_prerequisites

    case "${action}" in
        pull)
            cmd_pull "$@"
            ;;
        shell|run)
            cmd_shell "$@"
            ;;
        build)
            cmd_build "$@"
            ;;
        verify|test)
            cmd_verify "$@"
            ;;
        down|clean)
            cmd_down "$@"
            ;;
        *)
            echo "[-] Unknown command: ${action}" >&2
            echo ""
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
