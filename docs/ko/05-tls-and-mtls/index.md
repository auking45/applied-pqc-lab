# 05. PQC TLS 1.3 / mTLS Hands-on

## 📌 개요
TLS 1.3은 인터넷 통신의 기밀성과 무결성을 보장하는 표준 프로토콜이다. 양자 컴퓨터의 위협으로부터 TLS 1.3 연결을 보호하기 위해서는 **키 교환(Key Exchange)**과 **신원 인증(Authentication)**이라는 두 가지 암호화 계층이 모두 포스트 퀀텀 암호(PQC)로 전환되어야 한다.

1. **키 교환(Key Exchange)**: `ML-KEM-768` (또는 `X25519MLKEM768` 하이브리드) ➔ HNDL 공격 방어
2. **신원 인증(Authentication / mTLS)**: `ML-DSA-65` X.509 인증서 및 `CertificateVerify` 전자서명 ➔ 실시간 위조 공격 방어

본 챕터에서는 OpenSSL 3.5+ 환경에서 순수 PQC 기반의 TLS 1.3 및 mTLS(Mutual TLS) 상호 인증 핸드셰이크 구조를 분석하고, 4개 언어(Python, Rust, C++20, OpenSSL CLI)로 동작하는 엔드포인트를 실습한다.

```mermaid
sequenceDiagram
    autonumber
    actor Client as 클라이언트 (Client)
    actor Server as 서버 (Server / mTLS)

    Note over Client: 1. ML-KEM-768 에페머럴 키쌍 생성<br>- 공개키(ek: 1184B) 준비
    Client->>Server: ClientHello<br>[supported_groups: mlkem768]<br>[key_share: ML-KEM-768 ek (1184B)]<br>[signature_algorithms: mldsa65]
    
    Note over Server: 2. 수신한 ek로 Encap(ek) 실행<br>- 암호문(ct: 1088B) + Shared Secret 도출<br>- Handshake Master Secret 유도
    Server->>Client: ServerHello<br>[key_share: ML-KEM-768 ct (1088B)]
    
    Note over Server: {암호화 핸드셰이크 시작: TLS_AES_256_GCM}
    Server->>Client: EncryptedExtensions
    Server->>Client: CertificateRequest (클라이언트 인증서 요구)
    Server->>Client: Certificate (서버 ML-DSA-65 인증서)
    Note over Server: 3. 이전까지의 핸드셰이크 해시에<br>ML-DSA-65 개인키로 서명
    Server->>Client: CertificateVerify (ML-DSA-65 서명: 3309B)
    Server->>Client: Finished (서버 핸드셰이크 완료 검증 HMAC)

    Note over Client: 4. Decap(sk, ct)으로 동일 Shared Secret 도출<br>5. 서버 ML-DSA-65 인증서 및 서명 검증
    Client->>Server: Certificate (클라이언트 ML-DSA-65 인증서)
    Note over Client: 6. 클라이언트 개인키로 핸드셰이크 해시 서명
    Client->>Server: CertificateVerify (ML-DSA-65 서명: 3309B)
    Client->>Server: Finished (클라이언트 핸드셰이크 완료 검증)

    Note over Server: 7. 클라이언트 ML-DSA-65 인증서 및 서명 검증
    Note over Client,Server: {PQC 안전 통신 채널 수립 완료: AES-256-GCM}
    Client->>Server: Application Data (암호화된 HTTP 요청)
    Server->>Client: Application Data (암호화된 HTTP 응답)
```

---

## 🔍 PQC TLS 1.3 패킷 오버헤드 및 네트워크 분석

PQC 알고리즘은 고전 ECC 대비 공개키, 암호문, 서명의 크기가 크기 때문에 네트워크 패킷 구조 설계 시 MTU(Maximum Transmission Unit) 고려가 필수적이다:

| 암호 계층 | 고전 TLS 1.3 (ECDH + ECDSA) | PQC TLS 1.3 (ML-KEM-768 + ML-DSA-65) | 크기 차이 |
| :--- | :--- | :--- | :--- |
| **Client Key Share (공개키)** | X25519: **32 바이트** | ML-KEM-768: **1,184 바이트** | 약 37배 |
| **Server Key Share (암호문)** | X25519: **32 바이트** | ML-KEM-768: **1,088 바이트** | 약 34배 |
| **인증서 서명 (CertificateVerify)** | ECDSA P-256: **64 바이트** | ML-DSA-65: **3,309 바이트** | 약 51배 |
| **이더넷 MTU (1,500B) 수납 여부** |  단일 패킷 내 완전 수납 | ⚠️ `CertificateVerify` 전달 시 TCP 분할 발생 | TCP 세그먼트 단편화 처리 필요 |

> **💡 실무 네트워크 설계 권고:**<br>
> `ClientHello`와 `ServerHello`의 `key_share`는 각각 1184B, 1088B로 표준 이더넷 MTU(1500B) 내에 단일 TCP 패킷으로 수납된다. 반면 `ML-DSA-65` 서명(3309B)이 포함된 `CertificateVerify` 단계에서는 TCP 세그먼트 분할(Segmentation)이 발생하므로, 네트워크 버퍼 크기(`SO_RCVBUF`/`SO_SNDBUF`)를 64KB 이상으로 넉넉히 설정하는 것이 권장된다.

---

## 💻 실행 가능한 4개 언어 검증 코드

아래 탭은 OpenSSL 3.5 기반 PQC TLS 1.3 mTLS 서버에 접속하여 상호 인증 및 암호화 통신을 수행하는 4개 언어의 완전한 구현체이다:

=== "Python"

    ```python
    # Python 3 - OpenSSL 3.5 PQC TLS 1.3 / mTLS Client
    import subprocess
    import sys

    certs_dir = "/tmp/pqc_tls_certs"
    port = "14433"

    cmd = [
        "openssl", "s_client",
        "-connect", f"127.0.0.1:{port}",
        "-cert", f"{certs_dir}/client.crt",
        "-key", f"{certs_dir}/client.key",
        "-CAfile", f"{certs_dir}/ca.crt",
        "-groups", "mlkem768",
        "-tls1_3",
        "-verify_return_error",
    ]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate(input="GET / HTTP/1.0

")
    output = stdout + stderr

    assert "TLSv1.3" in output
    assert "Peer signature type: mldsa65" in output
    assert "Verify return code: 0 (ok)" in output
    print("[PASS] Python PQC TLS 1.3 mTLS Client verified successfully!")
    ```

=== "Rust"

    ```rust
    // Rust 2021/2024 Edition - PQC TLS 1.3 / mTLS Client
    use openssl::ssl::{SslConnector, SslMethod, SslFiletype, SslVerifyMode};
    use std::net::TcpStream;
    use std::io::{Read, Write};

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_ca_file("/tmp/pqc_tls_certs/ca.crt")?;
        builder.set_certificate_file("/tmp/pqc_tls_certs/client.crt", SslFiletype::PEM)?;
        builder.set_private_key_file("/tmp/pqc_tls_certs/client.key", SslFiletype::PEM)?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_groups_list("mlkem768")?;

        let connector = builder.build();
        let stream = TcpStream::connect("127.0.0.1:14433")?;
        let mut ssl_stream = connector.connect("127.0.0.1", stream)?;

        println!("[PASS] Rust TLS 1.3 Connected: version={:?}, cipher={:?}",
                 ssl_stream.ssl().version_str(),
                 ssl_stream.ssl().current_cipher().map(|c| c.name()));

        ssl_stream.write_all(b"GET / HTTP/1.0

")?;
        let mut buf = [0u8; 1024];
        let bytes = ssl_stream.read(&mut buf)?;
        assert!(bytes > 0);
        println!("[PASS] Rust PQC mTLS Data Exchange Succeeded!");
        Ok(())
    }
    ```

=== "C++"

    ```cpp
    // C++20 - OpenSSL 3.5 Native PQC TLS 1.3 / mTLS Client
    #include <iostream>
    #include <memory>
    #include <cassert>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <openssl/ssl.h>

    struct SslCtxDeleter { void operator()(SSL_CTX* p) const { if (p) SSL_CTX_free(p); } };
    struct SslDeleter { void operator()(SSL* p) const { if (p) { SSL_shutdown(p); SSL_free(p); } } };

    int main() {
        std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx(SSL_CTX_new(TLS_client_method()));
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set1_groups_list(ctx.get(), "mlkem768");

        SSL_CTX_load_verify_locations(ctx.get(), "/tmp/pqc_tls_certs/ca.crt", nullptr);
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_use_certificate_file(ctx.get(), "/tmp/pqc_tls_certs/client.crt", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx.get(), "/tmp/pqc_tls_certs/client.key", SSL_FILETYPE_PEM);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(14433);
        inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
        connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

        std::unique_ptr<SSL, SslDeleter> ssl(SSL_new(ctx.get()));
        SSL_set_fd(ssl.get(), sock);
        SSL_set_tlsext_host_name(ssl.get(), "127.0.0.1");
        assert(SSL_connect(ssl.get()) > 0);

        std::cout << "[PASS] C++ TLS 1.3 Connected: " << SSL_get_version(ssl.get()) << std::endl;
        const char* req = "GET / HTTP/1.0

";
        SSL_write(ssl.get(), req, strlen(req));
        char buf[1024] = {0};
        assert(SSL_read(ssl.get(), buf, sizeof(buf) - 1) > 0);
        std::cout << "[PASS] C++ PQC mTLS Data Exchange Succeeded!" << std::endl;

        close(sock);
        return 0;
    }
    ```

=== "OpenSSL CLI"

    ```bash
    # OpenSSL 3.5 CLI 기반 PQC TLS 1.3 mTLS 서버 및 클라이언트 구동

    # 1. mTLS 서버 구동 (ML-KEM-768 키 교환 + ML-DSA-65 클라이언트 인증 요구)
    openssl s_server -accept 14433         -cert server.crt -key server.key -CAfile ca.crt         -Verify 1 -groups mlkem768 -tls1_3 -www &

    # 2. mTLS 클라이언트 접속 및 상호 인증
    echo "GET / HTTP/1.0" | openssl s_client -connect 127.0.0.1:14433         -cert client.crt -key client.key -CAfile ca.crt         -groups mlkem768 -tls1_3 -verify_return_error
    ```
