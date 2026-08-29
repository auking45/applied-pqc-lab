# Applied PQC Lab (양자내성암호 엔지니어링 랩)

Practical Post-Quantum Cryptography (PQC) & HPKE engineering lab with OpenSSL 3.5+, X.509 PKI, and runnable Rust/C++ examples.

---

## 📌 Overview

**Applied PQC Lab**은 이론 위주의 암호학 설명을 넘어, 개발자가 직접 동작 원리를 시각적으로 이해하고 실제 코드로 검증할 수 있는 오픈소스 기술 문서 및 실습 랩입니다.

- **From Classical to Post-Quantum**: 고전 하이브리드 암호(RSA/ECIES + AES)부터 현대 RFC 9180 HPKE, 그리고 NIST 표준 PQC(ML-KEM, ML-DSA)로의 전환 과정을 단계별로 다룹니다.
- **Visual-First Architecture**: 복잡한 수식 대신 Mermaid 시퀀스 다이어그램 및 상태 흐름도를 중심으로 핵심 메커니즘을 설명합니다. (심층 수학 이론은 접이식 블록으로 격리)
- **Verified Implementations**: OpenSSL 3.5+ 네이티브 환경을 기반으로 한 Rust, C++, CLI 예제 코드를 제공하며, 모든 코드는 Docker 컨테이너 환경에서 E2E 테스트로 검증됩니다.
- **Bilingual Documentation**: 한국어 및 영문(i18n) 페이지를 완벽하게 분리 제공합니다.

---

## 🛠 Tech Stack

- **Documentation:** [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/), `mkdocs-static-i18n`, Mermaid.js, MathJax
- **Crypto Engine:** OpenSSL 3.5+ (Native NIST FIPS 203/204/205 support)
- **Languages:** Rust (2021 edition), C++20, Bash CLI
- **Test & Isolation:** Docker, Docker Compose
- **CI/CD:** GitHub Actions (Automated Test Verification & GitHub Pages Deployment)

---

## 📂 Project Structure

```text
applied-pqc-lab/
├── .github/
│   └── workflows/
│       └── ci.yml              # E2E 테스트 검증 및 GitHub Pages 배포 파이프라인
├── docker/
│   └── Dockerfile.lab          # OpenSSL 3.5+ & Rust/C++ 통합 테스트 컨테이너
├── docs/                       # 다국어 마크다운 문서 (한/영)
│   ├── index.en.md
│   ├── index.ko.md
│   ├── 01-classical-hybrid/
│   ├── 02-modern-hpke/
│   ├── 03-pqc-primitives/
│   ├── 04-pki-and-x509/
│   └── 05-tls-and-mtls/
├── examples/                   # Docker 내부에서 실행되는 실제 테스트 코드
│   ├── scripts/
│   │   └── run_pki.sh          # OpenSSL 3.5 CLI 기반 PKI 발급 스크립트
│   ├── cpp/
│   └── rust/
├── compose.yaml                # 로컬 원클릭 테스트 실행용 Compose 파일
├── mkdocs.yml                  # MkDocs 테마, i18n 및 다이어그램 설정
├── PROJECT_SPEC.md             # 프로젝트 마스터 명세 및 작업 로드맵
└── README.md
