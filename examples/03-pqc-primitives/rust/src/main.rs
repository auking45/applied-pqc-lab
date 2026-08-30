// =============================================================================
// Applied PQC Lab - NIST FIPS 203 ML-KEM-768 in Rust (2021/2024 Edition)
// Native OpenSSL 3.5+ EVP Encap / Decap + AES-256-GCM
// =============================================================================

use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use openssl_sys::*;
use std::ffi::CString;
use std::ptr;

struct EvpKey(*mut EVP_PKEY);
impl Drop for EvpKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_PKEY_free(self.0) };
        }
    }
}

fn generate_mlkem_keypair(alg_name: &str) -> Result<EvpKey, String> {
    unsafe {
        let name_c = CString::new(alg_name).map_err(|e| e.to_string())?;
        let kctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name_c.as_ptr(), ptr::null_mut());
        if kctx.is_null() || EVP_PKEY_keygen_init(kctx) <= 0 {
            return Err("EVP_PKEY_keygen_init failed".into());
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_keygen(kctx, &mut pkey) <= 0 {
            EVP_PKEY_CTX_free(kctx);
            return Err("EVP_PKEY_keygen failed".into());
        }
        EVP_PKEY_CTX_free(kctx);
        Ok(EvpKey(pkey))
    }
}

fn mlkem_encapsulate(pkey: &EvpKey) -> Result<(Vec<u8>, Vec<u8>), String> {
    unsafe {
        let ectx = EVP_PKEY_CTX_new(pkey.0, ptr::null_mut());
        if ectx.is_null() || EVP_PKEY_encapsulate_init(ectx, ptr::null_mut()) <= 0 {
            return Err("EVP_PKEY_encapsulate_init failed".into());
        }

        let mut ct_len: usize = 0;
        let mut secret_len: usize = 0;
        EVP_PKEY_encapsulate(ectx, ptr::null_mut(), &mut ct_len, ptr::null_mut(), &mut secret_len);

        let mut ct = vec![0u8; ct_len];
        let mut secret = vec![0u8; secret_len];
        if EVP_PKEY_encapsulate(ectx, ct.as_mut_ptr(), &mut ct_len, secret.as_mut_ptr(), &mut secret_len) <= 0 {
            EVP_PKEY_CTX_free(ectx);
            return Err("EVP_PKEY_encapsulate failed".into());
        }

        EVP_PKEY_CTX_free(ectx);
        Ok((ct, secret))
    }
}

fn mlkem_decapsulate(pkey: &EvpKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let dctx = EVP_PKEY_CTX_new(pkey.0, ptr::null_mut());
        if dctx.is_null() || EVP_PKEY_decapsulate_init(dctx, ptr::null_mut()) <= 0 {
            return Err("EVP_PKEY_decapsulate_init failed".into());
        }

        let mut secret_len: usize = 0;
        EVP_PKEY_decapsulate(dctx, ptr::null_mut(), &mut secret_len, ciphertext.as_ptr(), ciphertext.len());

        let mut secret = vec![0u8; secret_len];
        if EVP_PKEY_decapsulate(dctx, secret.as_mut_ptr(), &mut secret_len, ciphertext.as_ptr(), ciphertext.len()) <= 0 {
            EVP_PKEY_CTX_free(dctx);
            return Err("EVP_PKEY_decapsulate failed".into());
        }

        EVP_PKEY_CTX_free(dctx);
        Ok(secret)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("======================================================");
    println!(" [Applied PQC Lab] NIST FIPS 203 ML-KEM-768 in Rust");
    println!(" Native OpenSSL 3.5+ EVP Encap / Decap");
    println!("======================================================");

    // Step 1: Generate Receiver's ML-KEM-768 keypair
    println!("[+] Step 1: Generating Receiver's ML-KEM-768 keypair...");
    let rec_key = generate_mlkem_keypair("ML-KEM-768")?;

    // Step 2: Sender executes Encap(pkR)
    println!("[+] Step 2: Sender executing Encap(pkR)...");
    let (ciphertext, sender_secret) = mlkem_encapsulate(&rec_key)?;
    println!("    Encapsulated Ciphertext size: {} bytes (Expect 1088)", ciphertext.len());
    println!("    Derived Shared Secret size  : {} bytes (32 bytes / 256 bits)", sender_secret.len());

    // Step 3: Sender encrypts payload with AES-256-GCM
    println!("[+] Step 3: Sender encrypting payload with AES-256-GCM...");
    let plaintext = b"Top Secret Payload protected by NIST FIPS 203 Post-Quantum Cryptography.";
    let aad = b"PQC-Session-Metadata-FIPS203";
    let nonce = [0x42u8; 12];
    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; 16];
    let encrypted = encrypt_aead(cipher, &sender_secret, Some(&nonce), aad, plaintext, &mut tag)?;
    println!("    Encrypted Payload size: {} bytes, Tag: 16 bytes", encrypted.len());

    // Step 4: Receiver executes Decap(skR, ct)
    println!("[+] Step 4: Receiver executing Decap(skR, ct)...");
    let receiver_secret = mlkem_decapsulate(&rec_key, &ciphertext)?;

    assert_eq!(sender_secret, receiver_secret, "Decapsulated secret mismatch!");
    println!("    [PASS] Decapsulated secret matches sender secret 100%!");

    // Step 5: Receiver decrypts payload
    println!("[+] Step 5: Receiver decrypting payload and verifying AAD...");
    let decrypted_bytes = decrypt_aead(cipher, &receiver_secret, Some(&nonce), aad, &encrypted, &tag)?;
    let decrypted_msg = String::from_utf8(decrypted_bytes)?;

    println!("======================================================");
    println!(" [PASS] Decrypted message: \"{}\"", decrypted_msg);
    println!(" [SUCCESS] NIST FIPS 203 ML-KEM-768 verified in Rust!");
    println!("======================================================");

    Ok(())
}
