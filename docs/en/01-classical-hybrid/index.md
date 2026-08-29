# 01. Classical Hybrid Encryption

## 📌 Overview
Classical hybrid encryption combines asymmetric cryptography (RSA, ECIES) to wrap an ephemeral symmetric key (Data Encryption Key, DEK) with fast authenticated symmetric encryption (AES-GCM, ChaCha20-Poly1305) for encrypting arbitrary payload data.

```mermaid
sequenceDiagram
    autonumber
    participant Sender as Sender
    participant Receiver as Receiver

    Note over Sender: 1. Generate ephemeral symmetric key (DEK)
    Note over Sender: 2. Encrypt DEK with Receiver's Public Key (Key Encapsulation)
    Note over Sender: 3. Encrypt payload with DEK (AES-GCM)
    Sender->>Receiver: Send Encrypted DEK + Ciphertext + IV and Tag
    Note over Receiver: 4. Decrypt DEK with Receiver's Private Key
    Note over Receiver: 5. Decrypt payload with DEK
```

---

## 🔍 Planned Topics (Phase 2)
- Mechanisms of RSA-OAEP and ECIES key wrapping
- Differences from modern KEM architectures and inherent limitations
- Runnable comparison code in Rust and C++
