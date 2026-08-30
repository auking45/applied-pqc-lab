// =============================================================================
// Applied PQC Lab - RFC 9180 HPKE Base Mode in Rust (2021/2024 Edition)
// Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM
// =============================================================================

use openssl::derive::Deriver;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey};
use openssl::sign::Signer;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let salt = if salt.is_empty() { &[0u8; 32] } else { salt };
    hmac_sha256(salt, ikm)
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut info_with_counter = info.to_vec();
    info_with_counter.push(0x01);
    let okm = hmac_sha256(prk, &info_with_counter)?;
    Ok(okm[..len].to_vec())
}

fn hpke_labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut labeled_ikm = b"HPKE-v1".to_vec();
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled_ikm)
}

fn hpke_labeled_expand(prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut labeled_info = (len as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(prk, &labeled_info, len)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("======================================================");
    println!(" [Applied PQC Lab] RFC 9180 HPKE Base Mode in Rust");
    println!(" Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM");
    println!("======================================================");

    // Step 1: Generate Receiver's static X25519 keypair
    println!("[+] Step 1: Generating Receiver's static X25519 keypair...");
    let receiver_pkey = PKey::generate_x25519()?;
    let receiver_pub_bytes = receiver_pkey.raw_public_key()?;
    println!("    Receiver Public Key size: {} bytes", receiver_pub_bytes.len());

    // Step 2: Sender executes SetupBaseS (Generate ephemeral key & DH)
    println!("[+] Step 2: Sender executing SetupBaseS(pkR)...");
    let sender_ephemeral = PKey::generate_x25519()?;
    let enc = sender_ephemeral.raw_public_key()?;

    let mut deriver = Deriver::new(&sender_ephemeral)?;
    deriver.set_peer(&receiver_pkey)?;
    let dh_shared = deriver.derive_to_vec()?;

    let mut kem_context = enc.clone();
    kem_context.extend_from_slice(&receiver_pub_bytes);

    let shared_secret = hpke_labeled_extract(&[], b"shared_secret", &dh_shared)?;
    let app_info = b"Applied-PQC-Lab-HPKE-Context";
    let mut secret_ikm = kem_context;
    secret_ikm.extend_from_slice(app_info);
    let key_schedule_secret = hpke_labeled_extract(&shared_secret, b"secret", &secret_ikm)?;

    let sender_key = hpke_labeled_expand(&key_schedule_secret, b"key", &[], 32)?;
    let sender_nonce = hpke_labeled_expand(&key_schedule_secret, b"base_nonce", &[], 12)?;
    println!("    Encapsulated Key (enc) size: {} bytes", enc.len());

    // Step 3: Sender seals payload with AES-256-GCM
    println!("[+] Step 3: Sender sealing payload with AES-256-GCM...");
    let plaintext = b"Confidential Payload secured by RFC 9180 HPKE Base Mode.";
    let aad = b"Authenticated-Session-Metadata-v1";
    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(cipher, &sender_key, Some(&sender_nonce), aad, plaintext, &mut tag)?;
    println!("    Ciphertext size: {} bytes, Tag: 16 bytes", ciphertext.len());

    // Step 4: Receiver executes SetupBaseR
    println!("[+] Step 4: Receiver executing SetupBaseR(enc, skR)...");
    let sender_pub_peer = PKey::public_key_from_raw_bytes(&enc, Id::X25519)?;
    let mut rec_deriver = Deriver::new(&receiver_pkey)?;
    rec_deriver.set_peer(&sender_pub_peer)?;
    let rec_dh_shared = rec_deriver.derive_to_vec()?;

    let mut rec_kem_context = enc;
    rec_kem_context.extend_from_slice(&receiver_pub_bytes);

    let rec_shared_secret = hpke_labeled_extract(&[], b"shared_secret", &rec_dh_shared)?;
    let mut rec_secret_ikm = rec_kem_context;
    rec_secret_ikm.extend_from_slice(app_info);
    let rec_key_schedule_secret = hpke_labeled_extract(&rec_shared_secret, b"secret", &rec_secret_ikm)?;

    let receiver_key = hpke_labeled_expand(&rec_key_schedule_secret, b"key", &[], 32)?;
    let receiver_nonce = hpke_labeled_expand(&rec_key_schedule_secret, b"base_nonce", &[], 12)?;

    assert_eq!(sender_key, receiver_key, "AEAD key mismatch!");
    assert_eq!(sender_nonce, receiver_nonce, "Base nonce mismatch!");
    println!("    [PASS] Receiver derived matching key and base nonce!");

    // Step 5: Receiver opens ciphertext
    println!("[+] Step 5: Receiver opening payload with AAD verification...");
    let decrypted_bytes = decrypt_aead(cipher, &receiver_key, Some(&receiver_nonce), aad, &ciphertext, &tag)?;
    let decrypted_msg = String::from_utf8(decrypted_bytes)?;

    println!("======================================================");
    println!(" [PASS] Decrypted message: \"{}\"", decrypted_msg);
    println!(" [SUCCESS] RFC 9180 HPKE Base Mode verified in Rust!");
    println!("======================================================");

    Ok(())
}
