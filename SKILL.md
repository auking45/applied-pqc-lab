# [Skill Specification] Applied PQC Lab Documentation & Engineering Standard

본 문서는 **Applied PQC Lab**의 모든 기술 문서(한국어/영어), Mermaid 아키텍처 다이어그램, 3개 언어(Rust, C++, CLI) 실습 코드 및 E2E 테스트 하네스를 작성할 때 준수해야 하는 **엔지니어링 표준 가이드라인(Authoring Standard)**을 정의한다.

---

## 1. Tone & Style Guidelines (문체 및 어조 표준)

### 🇰🇷 한국어 기술 문서 규격
1. **평서체("~다 / ~한다") 원칙**:
   - AI 특유의 존댓말("~습니다 / ~합니다")을 **절대 사용하지 않는다.**
   - 실무 엔지니어가 작성하는 기술 블로그, RFC 해설서, 공식 아키텍처 독스의 톤앤매너를 유지한다.
   - 문장 끝은 "~한다", "~다", "~이다", 또는 개조식 명사형 종결("~함", "~임", "~제공")을 사용한다.
2. **간결성 및 능동적 표현**:
   - 불필요한 미사여구나 감정적 표현, 장황한 도입부를 배제하고 기술적 사실과 엔지니어링 메커니즘을 명확하고 간결하게 서술한다.
3. **용어 표기 원칙**:
   - 전문 암호학 용어는 표준 표기를 준수하고 필요 시 영문 병기를 병행한다.
   - 예: 키 캡슐화 메커니즘(KEM), 공개키 암호(Public Key Cryptography), 인증 암호화(AEAD).

### 🇺🇸 영어 기술 문서 규격
1. **Concise & Active Voice**:
   - Write in direct, active voice with clear technical precision.
2. **Consistent Terminology**:
   - Adhere strictly to NIST FIPS 203/204/205 and RFC 9180 official nomenclature.

---

## 2. Visual-First Principle (시각화 우선 원칙)

1. **상단 다이어그램 의무 배치**:
   - 모든 기술 아티클의 개요(Overview) 하단에는 개념을 즉시 파악할 수 있는 **Mermaid 다이어그램(시퀀스 또는 플로우차트)**을 반드시 배치한다.
2. **다크/라이트 모드 고대비 호환성**:
   - Mermaid 노드 내부에 인라인 스타일(`style fill:#...`)로 색상을 하드코딩하지 않는다. (다크모드 텍스트 묻힘 방지)
   - `docs/javascripts/mermaid.js` 및 `docs/stylesheets/extra.css`의 테마 변수를 활용한다.
3. **특수문자 및 구문 규칙**:
   - Mermaid 라벨 내 특수문자 충돌을 방지하기 위해 텍스트는 반드시 큰따옴표(`"..."`)로 감싼다. (예: `-->|"공유 비밀 (Shared Secret)"|`)
   - `&` 대신 `and` 또는 `및`을 사용한다.

---

## 3. Deep-Dive Mathematical Isolation (수학 이론 격리 원칙)

1. **접이식 블록(`??? note`) 의무 사용**:
   - 격자(Lattice) 기반 암호의 다항식 환(Polynomial Ring) 연산, 복잡한 증명, 군론(Group Theory) 등 심층 수학 수식은 본문에 직접 노출하지 않는다.
   - 반드시 아래와 같은 접이식 블록으로 감싸 엔지니어링 실습의 가독성을 유지한다:

```markdown
??? note "수학적 원리 깊게 보기 (Mathematical Deep Dive)"

    심층적인 수학적 증명이나 격자(Lattice) 기반 암호의 다항식 환(Polynomial Ring) 연산 등 복잡한 수식은 이와 같이 접이식 블록으로 격리하여 제공한다.

    $$R_q = \mathbb{Z}_q[X] / (X^n + 1)$$
```

---

## 4. Multi-Language Code Tabs (3개 언어 탭 규격)

실습 코드를 제공할 때는 반드시 아래 3개 언어 탭을 모두 제공하여 개발자가 언어별 구현 차이를 직관적으로 비교할 수 있도록 한다:

1. **Rust Tab**: Rust 2021/2024 Edition, 관용적 에러 핸들링 및 타입 안전성 반영
2. **C++ Tab**: C++20 표준, RAII 및 OpenSSL 3.5 C API / Modern C++ 래핑
3. **OpenSSL CLI Tab**: OpenSSL 3.5+ CLI 기반 원클릭 실행 명령어

```markdown
=== "Rust"

    ```rust
    // Rust 2021/2024 Example
    ```

=== "C++"

    ```cpp
    // C++20 Example
    ```

=== "OpenSSL CLI"

    ```bash
    # OpenSSL 3.5 CLI Example
    ```
```

---

## 5. Docker-Based Verification (재현성 및 격리 원칙)

1. **Zero Host Pollution**:
   - 모든 예제 코드 컴파일, PKI 인증서 생성, mTLS 통신 테스트는 Docker 컨테이너(`Dockerfile.lab`) 내부에서 실행되도록 작성한다.
2. **Automated Verification**:
   - 모든 예제 코드는 `./scripts/run_docker.sh verify` 또는 CI 테스트 하네스에 의해 자동 검증될 수 있어야 한다.

---

## 6. Bilingual Structure Synchronization (다국어 1:1 동기화)

1. **폴더 구조 일치 (`docs_structure: folder`)**:
   - `docs/ko/`와 `docs/en/`은 동일한 파일 트리와 챕터명을 유지한다.
2. **동일한 기술적 깊이**:
   - 한국어와 영어 문서는 동일한 Mermaid 다이어그램, 코드 예제, 비교표 및 접이식 수식 블록을 공유한다.
