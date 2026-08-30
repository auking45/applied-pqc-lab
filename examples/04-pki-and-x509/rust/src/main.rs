// =============================================================================
// Applied PQC Lab - PQC X.509 PKI End-to-End Encryption in Rust
// (ML-DSA-65 Root CA + ML-KEM-768 Leaf Cert + AES-256-GCM)
// =============================================================================

use foreign_types::ForeignType;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use openssl::x509::{store::X509StoreBuilder, X509StoreContext, X509};
use openssl_sys::*;
use std::env;
use std::fs;
use std::ptr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let pki_dir = if args.len() > 1 { &args[1] } else { "/tmp/pqc_pki_out" };

    println!("======================================================");
    println!(" [Applied PQC Lab] PQC X.509 PKI End-to-End in Rust");
    println!(" (ML-DSA-65 Root CA + ML-KEM-768 Leaf + AES-256-GCM)");
    println!("======================================================");

    // 1. Load Root CA and Leaf Certificates
    println!("[+] Step 1: Loading Root CA (ML-DSA-65) and Receiver Cert (ML-KEM-768)...");
    let ca_pem = fs::read(format!("{}/ca.crt", pki_dir))?;
    let ca_cert = X509::from_pem(&ca_pem)?;

    let leaf_pem = fs::read(format!("{}/receiver.crt", pki_dir))?;
    let leaf_cert = X509::from_pem(&leaf_pem)?;

    // 2. Sender verifies Certificate Chain
    println!("[+] Step 2: Sender verifying Receiver X.509 Certificate Chain...");
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(ca_cert)?;
    let store = store_builder.build();
    let mut ctx = X509StoreContext::new()?;
    let chain = Stack::new()?;
    let is_valid = ctx.init(&store, &leaf_cert, &chain, |c| c.verify_cert())?;
    assert!(is_valid, "Certificate verification failed!");
    println!("    [PASS] X.509 Certificate Chain signed by ML-DSA-65 Root CA verified!");

    // 3. Sender extracts ML-KEM-768 public key and performs Encap
    println!("[+] Step 3: Extracting ML-KEM-768 public key from verified certificate...");
    let pubkey = leaf_cert.public_key()?;
    let pkey_ptr = pubkey.as_ptr();

    println!("[+] Step 4: Sender executing ML-KEM-768 Encap(pkR)...");
    let (ciphertext, sender_secret) = unsafe {
        let ectx = EVP_PKEY_CTX_new(pkey_ptr, ptr::null_mut());
        assert!(!ectx.is_null());
        assert!(EVP_PKEY_encapsulate_init(ectx, ptr::null_mut()) > 0);
        let mut ct_len = 0usize;
        let mut secret_len = 0usize;
        EVP_PKEY_encapsulate(ectx, ptr::null_mut(), &mut ct_len, ptr::null_mut(), &mut secret_len);
        let mut ct = vec![0u8; ct_len];
        let mut secret = vec![0u8; secret_len];
        assert!(EVP_PKEY_encapsulate(ectx, ct.as_mut_ptr(), &mut ct_len, secret.as_mut_ptr(), &mut secret_len) > 0);
        EVP_PKEY_CTX_free(ectx);
        (ct, secret)
    };
    println!("    Encapsulated Ciphertext size: {} bytes (Expect 1088)", ciphertext.len());
    println!("    Sender Shared Secret size   : {} bytes (32 bytes)", sender_secret.len());

    // 4. Sender encrypts payload with AES-256-GCM
    println!("[+] Step 5: Sender encrypting confidential payload with AES-256-GCM...");
    let plaintext = b"Authenticated End-to-End PQC Message delivered via X.509 PKI.";
    let nonce = [0x42u8; 12];
    let aad = b"PQC-PKI-v1-Auth";
    let mut tag = [0u8; 16];
    let ct_payload = encrypt_aead(Cipher::aes_256_gcm(), &sender_secret, Some(&nonce), aad, plaintext, &mut tag)?;

    // 5. Receiver loads private key and performs Decap
    println!("[+] Step 6: Receiver decapsulating shared secret with private key...");
    let rec_priv_pem = fs::read(format!("{}/receiver.key", pki_dir))?;
    let rec_priv = PKey::private_key_from_pem(&rec_priv_pem)?;

    let receiver_secret = unsafe {
        let dctx = EVP_PKEY_CTX_new(rec_priv.as_ptr(), ptr::null_mut());
        assert!(!dctx.is_null());
        assert!(EVP_PKEY_decapsulate_init(dctx, ptr::null_mut()) > 0);
        let mut secret = vec![0u8; sender_secret.len()];
        let mut secret_len = sender_secret.len();
        assert!(EVP_PKEY_decapsulate(dctx, secret.as_mut_ptr(), &mut secret_len, ciphertext.as_ptr(), ciphertext.len()) > 0);
        EVP_PKEY_CTX_free(dctx);
        secret
    };

    assert_eq!(sender_secret, receiver_secret);
    println!("    [PASS] Decapsulated shared secret matches sender secret 100%!");

    // 6. Receiver decrypts payload
    println!("[+] Step 7: Receiver decrypting payload and verifying AAD...");
    let decrypted = decrypt_aead(Cipher::aes_256_gcm(), &receiver_secret, Some(&nonce), aad, &ct_payload, &tag)?;
    assert_eq!(decrypted, plaintext);

    println!("======================================================");
    println!(" [PASS] Decrypted message: \"{}\"", String::from_utf8_lossy(&decrypted));
    println!(" [SUCCESS] Rust PQC X.509 PKI End-to-End verified!");
    println!("======================================================");

    Ok(())
}
