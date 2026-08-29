# 04. PQC X.509 PKI & End-to-End Encryption

## 📌 개요
양자내성 환경에서는 신원 증명과 인증서 서명에 **ML-DSA(FIPS 204)**가 사용되고, 기밀 통신을 위한 암호화 공개키 배포에는 **ML-KEM(FIPS 203)** 인증서가 활용된다. 본 장에서는 순수 PQC 기반의 X.509 Root CA, Intermediate CA 및 End-Entity 인증서 발급과 E2E 암호화 워크플로우를 다룬다.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as 송신자 (Alice)
    participant PKI as ML-DSA Root CA
    actor Bob as 수신자 (Bob)

    Note over Bob,PKI: 1. Bob의 ML-KEM 인증서 발급 (ML-DSA 서명)
    Alice->>Bob: 2. Bob의 ML-KEM X.509 인증서 요청
    Bob-->>Alice: 인증서 전달
    Note over Alice: 3. Root CA 공개키로 인증서 검증 및 ML-KEM 공개키 추출
    Note over Alice: 4. ML-KEM Encapsulate / 공유키 파생 / 메시지 암호화
    Alice->>Bob: 5. 캡슐화된 키(Encapped Key) 및 암호문 전송
    Note over Bob: 6. 개인키로 Decapsulate 및 메시지 복호화 완료
```

---

## 🔍 주요 다룰 내용 (Phase 4 예정)
- OpenSSL 3.5 CLI 기반 PKI 발급 자동화 스크립트 (`run_pki.sh`)
- ML-DSA CA 체인 및 ML-KEM 종단 인증서 생성
- Rust 및 C++ 기반 X.509 파싱 + HPKE 결합 E2E 테스트
