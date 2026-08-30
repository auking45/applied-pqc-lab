# [Project Specification] Applied Cryptography & PQC Engineering Lab

## 1. Project Overview & Objectives

- **Goal:** 고전 하이브리드 암호부터 RFC 9180 HPKE, NIST PQC(FIPS 203/204), X.509 PKI, TLS 1.3/mTLS까지 다루는 **다국어(한/영) 기술 문서 사이트(GitHub Pages)** 및 **실행 가능한 멀티 언어(Rust, C++, CLI) E2E 테스트 랩** 구축.
- **Key Principles:**
  - 호스트 환경 오염 없는 **Docker 기반 완전 격리 테스트 환경**.
  - 수식보다 **Mermaid 다이어그램과 인터랙티브 코드 탭** 우선 배치.
  - 문서 및 코드 품질의 일관성을 유지하기 위한 **Authoring Skill & Verification Harness 체계 도입**.
  - 단계별 원자적(Atomic) 커밋 및 동작 확인 기반의 점진적 빌드업.

---

## 2. Strict Rules for AI Agent (Antigravity)

1. **Step-by-Step Execution with User Approval:**
   - 한 번에 여러 태스크를 임의로 진행하지 말고, **지정된 1개의 Task만 수행**한 뒤 사용자에게 완료 보고 및 검증 요청을 해야 합니다.
   - 사용자가 테스트를 확인하고 승인(Approve)하기 전까지 다음 Task를 시작하지 않습니다.

2. **English Commit Messages Only (Conventional Commits):**
   - 모든 Git 커밋 메시지는 **반드시 영어로 작성**합니다.
   - `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:` 접두사를 준수하며, 작업 완료 시점에 사용자에게 권장 커밋 메시지를 제안합니다.

3. **Strict Docker-Based Execution:**
   - 모든 암호화 라이브러리 컴파일, PKI 인증서 생성, C++/Rust 코드 빌드 및 mTLS 통신 테스트는 **Docker 컨테이너 내부에서 실행**되도록 스크립트와 compose 서비스를 구성합니다.

4. **Every Commit Must Be Functional:**
   - 매 커밋마다 코드가 깨져 있거나(Broken) 빌드 에러가 없어야 합니다.
   - 문서 추가 시 마크다운 링크/다국어 설정이 정상 동작해야 하며, 코드 추가 시 즉시 Docker 테스트 스크립트로 검증되어야 합니다.

5. **Visual-First & Deep Dive Isolation (문서 작성 표준):**
   - 본문은 **Mermaid 시퀀스/플로우차트, 비교표, 3개 언어 탭(Rust/C++/CLI)** 위주로 직관적으로 구성합니다.
   - 복잡한 수식과 심층 수학 이론은 본문에 직접 노출하지 않고 **접이식 블록(`??? note "수학적 원리 깊게 보기"`)**으로 격리합니다.

6. **Roadmap Checklist Synchronization:**
   - Task가 완료되고 사용자의 승인을 받으면, 본 문서(`PROJECT_SPEC.md`)의 해당 Task 체크박스를 `[x]`로 업데이트합니다.

---

## 3. Step-by-Step Roadmap (Milestones)

### [Phase 1] Foundation, Docker, Harness & CI/CD Pipeline

- [x] **Task 1-1:** 프로젝트 기본 디렉터리 구조 생성 + Material for MkDocs 설정 (`mkdocs.yml`, 다국어 `mkdocs-static-i18n`, 다크/라이트 팔레트 토글, Mermaid/수식 확장 설정).
- [x] **Task 1-2:** OpenSSL 3.5+ 및 Rust/C++ 툴체인을 포함하는 재현 가능한 Dockerfile 및 `compose.yaml` 작성.
- [x] **Task 1-3:** GitHub Actions 워크플로우(`.github/workflows/ci.yml`) 작성 (Docker 기반 E2E 테스트 검증 -> MkDocs Pages 배포).
- [x] **Task 1-4:** 문서 작성 표준 가이드라인 명세 (`SKILL.md`) 작성:
  - 문체/어조 규칙 (한국어 "~다/한다" 평서체 및 간결한 엔지니어링 톤 명시).
  - Visual-First 원칙 (Mermaid 시퀀스/플로우차트 필수).
  - Deep-dive 수식/격자 이론 격리 규칙 (`??? note "수학적 원리 깊게 보기"`).
  - 3개 언어 탭(Rust, C++, OpenSSL CLI) 필수 규격 정의.
- [x] **Task 1-5:** 아티클 생성 및 테스트 자동화 하네스 도구 구축 (`.harness/`):
  - `.harness/harness.py`: 신규 주제 스캐폴딩(`new`), 문서 정적 검사(`lint`), Docker 테스트 자동 실행(`test`) CLI.
  - `.harness/templates/`: Jinja2 기반 마크다운(한/영) 및 테스트 코드 템플릿.
  - CI 워크플로우에 `harness.py lint` 게이트웨이 연동.

### [Phase 2] Classical Hybrid Encryption vs RFC 9180 HPKE

- [x] **Task 2-1:** [Doc & Code] 고전 대칭키 + 비대칭 Key Wrapping 방식의 구조와 한계 (문서 한/영 + 4개 언어 Python/Rust/C++/CLI 예제 및 Docker E2E 실행).
- [x] **Task 2-2:** [Doc & Code] RFC 9180 HPKE 아키텍처 (KEM/KDF/AEAD 프레임워크 흐름도 + 4개 언어 Python/Rust/C++/CLI Base 모드 동작 검증 코드).

### [Phase 3] NIST PQC Primitives & Security Guidelines

- [x] **Task 3-1:** [Doc & Code] FIPS 203 ML-KEM (구 Kyber) 원리 시각화 + 4개 언어 Python/Rust/C++/CLI 캡슐화 예제 (Docker 검증).
- [x] **Task 3-2:** [Doc & Code] FIPS 204 ML-DSA (구 Dilithium) 전자서명 흐름도 + 서명/검증 예제 (Docker 검증).
- [ ] **Task 3-3:** [Doc] 양자 위협 모델 및 보안 강도 권고 (NIST Cat 1/3/5, CNSA 2.0 매핑 및 AES-256 권고 이유).

### [Phase 4] PQC X.509 PKI & End-to-End Encryption

- [ ] **Task 4-1:** [Script & Doc] OpenSSL 3.5 네이티브 CLI 기반 PKI 발급 자동화 스크립트 (`run_pki.sh`: ML-DSA Root CA, ML-KEM 수신자 인증서 발급).
- [ ] **Task 4-2:** [Code & Test] 인증서 검증 -> ML-KEM 공개키 추출 -> HPKE AES-256-GCM 암/복호화 E2E 통합 테스트 (Rust & C++, Docker 검증).

### [Phase 5] PQC TLS 1.3 / mTLS Hands-on

- [ ] **Task 5-1:** [Doc & Script] PQC TLS 1.3 핸드셰이크 단계별 매핑 가이드.
- [ ] **Task 5-2:** [Test] OpenSSL `s_server` / `s_client` 기반 ML-DSA 및 ML-KEM mTLS 양방향 인증 자동화 테스트 스크립트 작성 및 Docker/CI 연동.
