# 05. PQC TLS 1.3 / mTLS Hands-on

## 📌 개요
TLS 1.3 핸드셰이크에서 키 교환(Key Exchange)은 **ML-KEM**으로 수행되고, 서버/클라이언트 상호 인증(mTLS)을 위한 디지털 서명은 **ML-DSA**로 수행됩니다. 본 장에서는 OpenSSL 3.5 기반의 PQC TLS 1.3 연결 및 상호 인증(mTLS)을 직접 구성하고 검증합니다.

```mermaid
sequenceDiagram
    autonumber
    participant Client as TLS 클라이언트 (Client)
    participant Server as TLS 서버 (Server)

    Note over Client,Server: [TLS 1.3 Key Share: ML-KEM-768]
    Client->>Server: ClientHello (KeyShare: ML-KEM-768 public key)
    Server->>Client: ServerHello (KeyShare: ML-KEM-768 ciphertext)
    Note over Client,Server: [Shared Secret 도출 및 암호화 시작]
    Server->>Client: EncryptedExtensions, Certificate (ML-DSA), CertificateVerify, Finished
    Note over Client: 서버 ML-DSA 인증서 및 서명 검증
    Client->>Server: Certificate (Client ML-DSA), CertificateVerify, Finished (mTLS)
    Note over Server: 클라이언트 ML-DSA 인증서 및 서명 검증
    Note over Client,Server: [양자내성 보안 mTLS 세션 수립 완료]
```

---

## 🔍 주요 다룰 내용 (Phase 5 예정)
- PQC TLS 1.3 핸드셰이크 단계별 패킷 구조 및 암호 알고리즘 매핑
- OpenSSL 3.5 `s_server` / `s_client` 기반 ML-DSA + ML-KEM mTLS 양방향 테스트
- 자동화된 E2E 검증 테스트 하네스
