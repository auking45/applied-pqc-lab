// =============================================================================
// Applied PQC Lab - NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA in Rust
// Native OpenSSL 3.5+ EVP Encap/Decap & DigestSign/DigestVerify
// =============================================================================

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

fn generate_pqc_keypair(alg_name: &str) -> Result<EvpKey, String> {
    unsafe {
        let name_c = CString::new(alg_name).map_err(|e| e.to_string())?;
        let kctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name_c.as_ptr(), ptr::null_mut());
        if kctx.is_null() || EVP_PKEY_keygen_init(kctx) <= 0 {
            return Err(format!("EVP_PKEY_keygen_init failed for {}", alg_name));
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_keygen(kctx, &mut pkey) <= 0 {
            EVP_PKEY_CTX_free(kctx);
            return Err(format!("EVP_PKEY_keygen failed for {}", alg_name));
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
        let mut ct_len = 0usize;
        let mut secret_len = 0usize;
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
        let mut secret_len = 0usize;
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

fn mldsa_sign(pkey: &EvpKey, message: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mctx = EVP_MD_CTX_new();
        if mctx.is_null() || EVP_DigestSignInit(mctx, ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey.0) <= 0 {
            return Err("EVP_DigestSignInit failed".into());
        }
        let mut sig_len = 0usize;
        EVP_DigestSign(mctx, ptr::null_mut(), &mut sig_len, message.as_ptr(), message.len());

        let mut sig = vec![0u8; sig_len];
        if EVP_DigestSign(mctx, sig.as_mut_ptr(), &mut sig_len, message.as_ptr(), message.len()) <= 0 {
            EVP_MD_CTX_free(mctx);
            return Err("EVP_DigestSign failed".into());
        }
        EVP_MD_CTX_free(mctx);
        Ok(sig)
    }
}

fn mldsa_verify(pkey: &EvpKey, message: &[u8], signature: &[u8]) -> bool {
    unsafe {
        let vmctx = EVP_MD_CTX_new();
        if vmctx.is_null() || EVP_DigestVerifyInit(vmctx, ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey.0) <= 0 {
            return false;
        }
        let vret = EVP_DigestVerify(vmctx, signature.as_ptr(), signature.len(), message.as_ptr(), message.len());
        EVP_MD_CTX_free(vmctx);
        vret > 0
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("======================================================");
    println!(" [Applied PQC Lab] NIST PQC Primitives in Rust");
    println!(" FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 (OpenSSL 3.5)");
    println!("======================================================");

    // 1. FIPS 203 ML-KEM-768
    println!("\n--- [Part 1] FIPS 203 ML-KEM-768 Key Encapsulation ---");
    let rec_kem = generate_pqc_keypair("ML-KEM-768")?;
    let (ciphertext, sender_secret) = mlkem_encapsulate(&rec_kem)?;
    println!("[+] Sender Encap: ct={}B, secret={}B", ciphertext.len(), sender_secret.len());

    let receiver_secret = mlkem_decapsulate(&rec_kem, &ciphertext)?;
    assert_eq!(sender_secret, receiver_secret);
    println!("[+] Receiver Decap: [PASS] Derived matching 32B shared secret!");

    // 2. FIPS 204 ML-DSA-65
    println!("\n--- [Part 2] FIPS 204 ML-DSA-65 Digital Signature ---");
    let signer_dsa = generate_pqc_keypair("ML-DSA-65")?;
    let message = b"Critical Legal Contract signed with Quantum-Resistant FIPS 204 ML-DSA.";

    let signature = mldsa_sign(&signer_dsa, message)?;
    println!("[+] ML-DSA-65 Signature generated: size = {} bytes (Expect 3309)", signature.len());

    let is_valid = mldsa_verify(&signer_dsa, message, &signature);
    assert!(is_valid, "ML-DSA signature verification failed!");
    println!("    [PASS] Signature verified successfully!");

    println!("======================================================");
    println!(" [SUCCESS] FIPS 203 ML-KEM & FIPS 204 ML-DSA verified in Rust!");
    println!("======================================================");

    Ok(())
}
