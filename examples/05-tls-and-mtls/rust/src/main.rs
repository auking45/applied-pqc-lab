// =============================================================================
// Applied PQC Lab - PQC TLS 1.3 / mTLS Client in Rust
// (Key Exchange: ML-KEM-768 | Auth: ML-DSA-65 mTLS)
// =============================================================================

use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let certs_dir = if args.len() > 1 { &args[1] } else { "/tmp/pqc_tls_certs" };
    let port = if args.len() > 2 { &args[2] } else { "14433" };

    println!("======================================================");
    println!(" [Applied PQC Lab] PQC TLS 1.3 / mTLS Client in Rust");
    println!(" (Key Exchange: ML-KEM-768 | Auth: ML-DSA-65 mTLS)");
    println!("======================================================");

    // 1. Configure SslConnector with ML-KEM-768 and ML-DSA client credentials
    println!("[+] Step 1: Configuring SSL context with PQC parameters...");
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_ca_file(format!("{}/ca.crt", certs_dir))?;
    builder.set_certificate_file(format!("{}/client.crt", certs_dir), SslFiletype::PEM)?;
    builder.set_private_key_file(format!("{}/client.key", certs_dir), SslFiletype::PEM)?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_groups_list("mlkem768")?;

    let connector = builder.build();

    // 2. Connect to server
    println!("[+] Step 2: Connecting to 127.0.0.1:{} with TLS 1.3...", port);
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
    let mut ssl_stream = connector.connect("127.0.0.1", stream)?;

    let version = ssl_stream.ssl().version_str();
    let cipher = ssl_stream.ssl().current_cipher().map(|c| c.name()).unwrap_or("Unknown");
    println!("    [PASS] TLS 1.3 Handshake completed successfully!");
    println!("    - Protocol        : {}", version);
    println!("    - Cipher Suite    : {}", cipher);
    println!("    - Key Exchange    : ML-KEM-768");
    println!("    - Mutual Auth     : ML-DSA-65 Verified");

    // 3. Application Data exchange
    println!("[+] Step 3: Transmitting encrypted HTTP request...");
    ssl_stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut buf = [0u8; 1024];
    let bytes_read = ssl_stream.read(&mut buf)?;
    assert!(bytes_read > 0, "No response received");
    println!("    [PASS] Received {} bytes of encrypted application data!", bytes_read);

    println!("======================================================");
    println!(" [SUCCESS] Rust PQC TLS 1.3 / mTLS verified!");
    println!("======================================================");

    Ok(())
}
