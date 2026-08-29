# 04. PQC X.509 PKI & End-to-End Encryption

## 📌 Overview
In a post-quantum public key infrastructure (PKI), **ML-DSA (FIPS 204)** is used for identity verification and digital certificate signing, while **ML-KEM (FIPS 203)** certificates distribute public keys for confidential communications. This section covers pure-PQC X.509 certificate authority hierarchies and E2E encrypted communication pipelines.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Sender (Alice)
    participant PKI as ML-DSA Root CA
    actor Bob as Receiver (Bob)

    Note over Bob,PKI: 1. Issue Bob's ML-KEM Certificate (Signed by ML-DSA)
    Alice->>Bob: 2. Request Bob's ML-KEM X.509 Certificate
    Bob-->>Alice: Return Certificate
    Note over Alice: 3. Verify Certificate via Root CA and Extract ML-KEM Public Key
    Note over Alice: 4. ML-KEM Encapsulate / Derive Shared Secret / Encrypt Payload
    Alice->>Bob: 5. Transmit Encapsulated Key and Ciphertext
    Note over Bob: 6. Decapsulate with Private Key and Decrypt Payload
```

---

## 🔍 Planned Topics (Phase 4)
- Automated PKI issuance scripts via OpenSSL 3.5 CLI (`run_pki.sh`)
- ML-DSA CA hierarchies and ML-KEM recipient certificate generation
- Rust and C++ X.509 parsing + HPKE E2E integration tests
