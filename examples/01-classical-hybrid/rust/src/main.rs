// =============================================================================
// Applied PQC Lab - Classical Hybrid Encryption in Rust (2021/2024 Edition)
// RSA-3072 OAEP Key Wrapping + AES-256-GCM Authenticated Encryption
// =============================================================================

use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("======================================================");
    println!(" [Applied PQC Lab] Rust Classical Hybrid Encryption");
    println!(" (RSA-3072 OAEP + AES-256-GCM)");
    println!("======================================================");

    // 1. 수신자 RSA-3072 키쌍 생성
    println!("[+] Step 1: Generating Receiver's RSA-3072 keypair...");
    let rsa_keypair = Rsa::generate(3072)?;
    let receiver_pkey = PKey::from_rsa(rsa_keypair)?;

    // 2. 송신자: 256비트 임시 DEK 및 96비트 IV 생성
    println!("[+] Step 2: Sender generating ephemeral 256-bit DEK & 96-bit IV...");
    let mut dek = [0u8; 32];
    let mut iv = [0u8; 12];
    rand_bytes(&mut dek)?;
    rand_bytes(&mut iv)?;

    // 3. 송신자: 수신자 공개키로 DEK 래핑 (RSA-OAEP-SHA256)
    println!("[+] Step 3: Sender wrapping DEK with Receiver's RSA Public Key...");
    let mut encrypter = openssl::encrypt::Encrypter::new(&receiver_pkey)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
    encrypter.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;

    let mut wrapped_dek = vec![0u8; encrypter.encrypt_len(&dek)?];
    let wrapped_len = encrypter.encrypt(&dek, &mut wrapped_dek)?;
    wrapped_dek.truncate(wrapped_len);
    println!("    Wrapped DEK size: {} bytes", wrapped_dek.len());

    // 4. 송신자: DEK로 메시지 암호화 (AES-256-GCM)
    let original_message = b"Hello, Post-Quantum World! Rust Classical Hybrid Verified.";
    println!("[+] Step 4: Sender encrypting payload with AES-256-GCM...");
    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(cipher, &dek, Some(&iv), &[], original_message, &mut tag)?;
    println!("    Ciphertext size: {} bytes, Tag: {} bytes", ciphertext.len(), tag.len());

    // 5. 수신자: 개인키로 DEK 언래핑
    println!("[+] Step 5: Receiver unwrapping DEK with RSA Private Key...");
    let mut decrypter = openssl::encrypt::Decrypter::new(&receiver_pkey)?;
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
    decrypter.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())?;

    let mut unwrapped_dek = vec![0u8; decrypter.decrypt_len(&wrapped_dek)?];
    let unwrapped_len = decrypter.decrypt(&wrapped_dek, &mut unwrapped_dek)?;
    unwrapped_dek.truncate(unwrapped_len);

    assert_eq!(dek.as_slice(), unwrapped_dek.as_slice(), "DEK mismatch!");
    println!("    [PASS] Unwrapped DEK matches original DEK!");

    // 6. 수신자: DEK로 복호화 및 인증 태그 검증
    println!("[+] Step 6: Receiver decrypting payload with unwrapped DEK...");
    let decrypted_bytes = decrypt_aead(cipher, &unwrapped_dek, Some(&iv), &[], &ciphertext, &tag)?;
    let decrypted_msg = String::from_utf8(decrypted_bytes)?;

    println!("======================================================");
    println!(" [PASS] Decrypted message: \"{}\"", decrypted_msg);
    println!(" [SUCCESS] Rust Classical Hybrid Encryption verified!");
    println!("======================================================");

    Ok(())
}
