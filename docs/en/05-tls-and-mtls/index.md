# 05. PQC TLS 1.3 / mTLS Hands-on

## 📌 Overview
In a post-quantum TLS 1.3 handshake, key exchange is achieved via **ML-KEM**, while server and client authentication (mTLS) is secured via **ML-DSA** digital signatures. This section demonstrates native PQC TLS 1.3 connection establishment and mutual TLS verification using OpenSSL 3.5+.

```mermaid
sequenceDiagram
    autonumber
    participant Client as TLS Client
    participant Server as TLS Server

    Note over Client,Server: [TLS 1.3 Key Share: ML-KEM-768]
    Client->>Server: ClientHello (KeyShare: ML-KEM-768 public key)
    Server->>Client: ServerHello (KeyShare: ML-KEM-768 ciphertext)
    Note over Client,Server: [Derive Shared Secret and Start Encryption]
    Server->>Client: EncryptedExtensions, Certificate (ML-DSA), CertificateVerify, Finished
    Note over Client: Verify Server ML-DSA Certificate and Signature
    Client->>Server: Certificate (Client ML-DSA), CertificateVerify, Finished (mTLS)
    Note over Server: Verify Client ML-DSA Certificate and Signature
    Note over Client,Server: [Quantum-Safe mTLS Session Established]
```

---

## 🔍 Planned Topics (Phase 5)
- Detailed packet structures and cryptographic mappings in PQC TLS 1.3 handshakes
- OpenSSL 3.5 `s_server` / `s_client` automation for ML-DSA + ML-KEM mTLS
- Automated E2E verification test harness
