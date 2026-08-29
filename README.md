# Applied PQC Lab (양자내성암호 엔지니어링 랩)

Practical Post-Quantum Cryptography (PQC) & HPKE engineering lab with OpenSSL 3.5+, X.509 PKI, and runnable Rust/C++ examples.

---

## 📌 Overview

**Applied PQC Lab**은 이론 위주의 설명을 넘어, 개발자가 직접 동작 원리를 시각적으로 이해하고 실제 코드로 검증할 수 있도록 구성된 오픈소스 기술 문서 및 실습 랩이다.

- **From Classical to Post-Quantum**: 고전 하이브리드 암호(RSA/ECIES + AES)부터 현대 RFC 9180 HPKE, NIST 표준 PQC(ML-KEM, ML-DSA)로의 전환 과정을 단계별로 다룬다.
- **Visual-First Architecture**: 복잡한 수식 대신 Mermaid 시퀀스 다이어그램 및 상태 흐름도를 중심으로 핵심 메커니즘을 설명한다. (심층 수학 이론은 접이식 블록으로 격리)
- **Verified Implementations**: OpenSSL 3.5+ 네이티브 환경 기반의 Rust, C++, CLI 예제 코드를 제공하며, 모든 코드는 Docker 컨테이너 환경에서 E2E 테스트로 검증된다.
- **Bilingual Documentation**: 한국어 및 영문(i18n) 문서를 독립된 디렉터리로 완벽히 분리 제공한다.

---

## 🛠 Tech Stack

- **Documentation:** [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/), `mkdocs-static-i18n`, Mermaid.js, MathJax
- **Crypto Engine:** OpenSSL 3.5+ (Native NIST FIPS 203/204/205 support)
- **Languages:** Rust (2021/2024 edition), C++20, Bash CLI
- **Test & Isolation:** Docker, Docker Compose
- **CI/CD:** GitHub Actions (Automated Test Verification & GitHub Pages Deployment)

---

## 📂 Project Structure

```text
applied-pqc-lab/
├── .github/
│   └── workflows/
│       ├── test.yml            # Docker 기반 PQC 툴체인 및 E2E 테스트 검증 파이프라인
│       └── docs.yml            # MkDocs 문서 빌드 무결성 검증 및 GitHub Pages 배포
├── .harness/                   # 아티클 스캐폴딩 및 작성 규격 린트 하네스 도구
│   ├── harness.py              # CLI 하네스 메인 도구 (new, lint, test)
│   └── templates/              # 표준 마크다운(한/영) 및 C++/Rust/CLI 템플릿
├── docker/
│   ├── Dockerfile.lab          # OpenSSL 3.5+ & Rust/C++ 통합 테스트 컨테이너
│   └── verify_toolchain.sh     # 컨테이너 내 툴체인/PQC 알고리즘 일괄 검증 스크립트
├── docs/                       # 다국어 마크다운 문서 (docs_structure: folder)
│   ├── ko/                     # 한국어 기술 문서
│   │   ├── index.md
│   │   ├── 01-classical-hybrid/
│   │   ├── 02-modern-hpke/
│   │   ├── 03-pqc-primitives/
│   │   ├── 04-pki-and-x509/
│   │   └── 05-tls-and-mtls/
│   ├── en/                     # English technical documentation
│   │   ├── index.md
│   │   ├── 01-classical-hybrid/
│   │   ├── 02-modern-hpke/
│   │   ├── 03-pqc-primitives/
│   │   ├── 04-pki-and-x509/
│   │   └── 05-tls-and-mtls/
│   ├── javascripts/            # MathJax & Mermaid 동적 렌더러
│   └── stylesheets/            # 커스텀 테마 스타일 (다크/라이트)
├── examples/                   # Docker 내부에서 실행되는 실제 테스트 코드
│   ├── scripts/
│   │   └── run_pki.sh          # OpenSSL 3.5 CLI 기반 PKI 발급 스크립트
│   ├── cpp/
│   └── rust/
├── scripts/
│   ├── run_docker.sh           # Docker 랩 환경 빌드/실행/검증 자동화 스크립트
│   └── serve_docs.sh           # 로컬 문서 뷰어 원클릭 실행 스크립트
├── compose.yaml                # 로컬 원클릭 테스트 실행용 Compose 파일
├── mkdocs.yml                  # MkDocs 테마, i18n 및 다이어그램 설정
├── requirements.txt            # 문서 빌드 의존성 목록
├── PROJECT_SPEC.md             # 프로젝트 마스터 명세 및 작업 로드맵
├── SKILL.md                    # 문서 및 코드 작성 표준 가이드라인
└── README.md
```

---

## 🚀 Quick Start

### 1. Docker 기반 암호학 랩 환경 실행 (완전 격리 / 권장)

저장소를 클론한 후 아래 원클릭 스크립트를 통해 Docker 환경을 빌드하고 검증할 수 있습니다:

```bash
# 1. 랩 컨테이너 빌드 (Docker 미설치 시 자동 설치 지원)
./scripts/run_docker.sh build

# 2. 툴체인 및 OpenSSL 3.5+ PQC(ML-KEM, ML-DSA) 환경 일괄 검증
./scripts/run_docker.sh verify

# 3. 대화형 랩 컨테이너 진입 (C++/Rust/OpenSSL CLI 실습)
./scripts/run_docker.sh shell
```

### 2. 로컬 문서 사이트 실행 (호스트)

```bash
# 로컬 문서 서버 실행 (자동 venv 생성 및 의존성 설치)
./scripts/serve_docs.sh
```

실행 후 브라우저에서 `http://127.0.0.1:8000`으로 접속하여 문서를 확인하실 수 있습니다.
