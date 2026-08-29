# 02. RFC 9180 HPKE (Hybrid Public Key Encryption)

## 📌 Overview
RFC 9180 HPKE (Hybrid Public Key Encryption) standardizes modern hybrid public-key encryption through a structured framework combining three cryptographic primitives: **KEM (Key Encapsulation Mechanism)**, **KDF (Key Derivation Function)**, and **AEAD (Authenticated Encryption with Associated Data)**.

```mermaid
flowchart LR
    subgraph HPKE["RFC 9180 HPKE Framework"]
        direction TB
        KEM["KEM<br>(DHKEM / ML-KEM)"] -->|"Shared Secret"| KDF["KDF<br>(HKDF-SHA256)"]
        KDF -->|"Encryption Key and Nonce"| AEAD["AEAD<br>(AES-256-GCM / ChaCha20)"]
    end
```

---

## 🔍 Planned Topics (Phase 2)
- 4 HPKE modes: Base, Auth, PSK, and AuthPSK
- KEM Encapsulation (`Encap`) and Decapsulation (`Decap`) sequences
- OpenSSL 3.5 native C++20 and Rust E2E examples
