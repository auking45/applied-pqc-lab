# [Skill Specification] Applied PQC Lab Documentation & Engineering Standard

본 문서는 **Applied PQC Lab**의 모든 기술 문서(한국어/영어), Mermaid 아키텍처 다이어그램, 4개 언어(Python, Rust, C++, CLI) 실습 코드 및 E2E 테스트 하네스를 작성할 때 준수해야 하는 **엔지니어링 표준 가이드라인(Authoring Standard)**을 정의한다.

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

## 2. Visual-First & Intuitive Explanation Principle (시각화 및 쉬운 설명 원칙)

1. **상단 다이어그램 의무 배치**:
   - 모든 기술 아티클의 개요(Overview) 하단에는 개념을 즉시 파악할 수 있는 **Mermaid 다이어그램(시퀀스 또는 플로우차트)**을 반드시 배치한다.
2. **복잡한 수식 지양 및 직관적 메커니즘 중심 해설**:
   - 불필요하게 난해한 수학 증명이나 복잡한 LaTeX 수식 나열을 지양한다.
   - **실무 엔지니어링 관점에서의 데이터 흐름, 암호학적 비유, 동작 원리 및 비교표**를 중심으로 누구나 쉽게 이해할 수 있도록 설명한다.
3. **다크/라이트 모드 고대비 호환성**:
   - Mermaid 노드 내부에 인라인 스타일(`style fill:#...`)로 색상을 하드코딩하지 않는다.
   - `docs/javascripts/mermaid.js` 및 `docs/stylesheets/extra.css`의 테마 변수를 활용한다.

---

## 3. Multi-Language Code Tabs (4개 언어 탭 규격)

실습 코드를 제공할 때는 반드시 아래 **4개 언어 탭(Python, Rust, C++, OpenSSL CLI)**을 모두 제공하여 개발자가 언어별 구현 차이를 직관적으로 비교하고 학습할 수 있도록 한다:

1. **Python Tab**: Python 3.12 + `cryptography` 표준 라이브러리 기반 가장 읽기 쉽고 직관적인 구현
2. **Rust Tab**: Rust 2021/2024 Edition, 관용적 에러 핸들링 및 타입 안전성 반영
3. **C++ Tab**: C++20 표준, RAII 및 OpenSSL 3.5 C API 기반 현대적 구현
4. **OpenSSL CLI Tab**: OpenSSL 3.5+ CLI 기반 원클릭 실행 명령어

```markdown
=== "Python"

    ```python
    # Python 3 Example
    ```

=== "Rust"

    ```rust
    # Rust 2021/2024 Example
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

## 4. Chapter-Isolated Examples & Docker Verification (챕터별 독립 격리 원칙)

1. **챕터별 독립 디렉터리 구성**:
   - 모든 예제는 문서 챕터와 1:1로 매핑되는 독립 디렉터리로 구성된다:
   ```text
   examples/
   ├── 01-classical-hybrid/
   │   ├── python/main.py
   │   ├── rust/ (Cargo.toml + src/main.rs)
   │   ├── cpp/ (CMakeLists.txt + main.cpp)
   │   └── run.sh
   ├── 02-modern-hpke/
   └── ...
   ```
2. **Zero Host Pollution & 원클릭 재현성**:
   - 각 챕터 폴더의 `run.sh`를 통해 4개 언어 예제를 단독 검증할 수 있으며, `./scripts/run_docker.sh verify`를 통해 Docker 컨테이너 환경에서 전체 챕터가 일괄 자동 검증된다.

---

## 5. Bilingual Structure Synchronization (다국어 1:1 동기화)

1. **폴더 구조 일치 (`docs_structure: folder`)**:
   - `docs/ko/`와 `docs/en/`은 동일한 파일 트리와 챕터명을 유지한다.
2. **동일한 기술적 깊이**:
   - 한국어와 영어 문서는 동일한 Mermaid 다이어그램, 4개 언어 코드 예제 및 비교표를 공유한다.
