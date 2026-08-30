#!/usr/bin/env python3
"""
Applied PQC Lab - PQC X.509 PKI End-to-End Encryption in Python
OpenSSL 3.5+ libcrypto X.509 Chain Verification + ML-KEM-768 + AES-256-GCM (Zero Pip Dependencies)
"""

import ctypes
import os
import sys
from ctypes import c_void_p, c_char_p, c_size_t, c_int, POINTER, byref, create_string_buffer


def load_libcrypto():
    candidates = [
        "/opt/openssl/lib/libcrypto.so",
        "/opt/openssl/lib64/libcrypto.so",
        "libcrypto.so",
    ]
    for p in candidates:
        try:
            return ctypes.CDLL(p)
        except OSError:
            continue
    raise RuntimeError("OpenSSL 3.5+ libcrypto.so not found!")


libcrypto = load_libcrypto()

# BIO & PEM
libcrypto.BIO_new_file.restype = c_void_p
libcrypto.BIO_new_file.argtypes = [c_char_p, c_char_p]
libcrypto.BIO_free.argtypes = [c_void_p]
libcrypto.PEM_read_bio_X509.restype = c_void_p
libcrypto.PEM_read_bio_X509.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.PEM_read_bio_PrivateKey.restype = c_void_p
libcrypto.PEM_read_bio_PrivateKey.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.X509_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_free.argtypes = [c_void_p]

# X.509 Store & Verification
libcrypto.X509_STORE_new.restype = c_void_p
libcrypto.X509_STORE_free.argtypes = [c_void_p]
libcrypto.X509_STORE_add_cert.argtypes = [c_void_p, c_void_p]
libcrypto.X509_STORE_CTX_new.restype = c_void_p
libcrypto.X509_STORE_CTX_free.argtypes = [c_void_p]
libcrypto.X509_STORE_CTX_init.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.X509_verify_cert.argtypes = [c_void_p]
libcrypto.X509_get0_pubkey.restype = c_void_p
libcrypto.X509_get0_pubkey.argtypes = [c_void_p]

# EVP Encap/Decap
libcrypto.EVP_PKEY_CTX_new.restype = c_void_p
libcrypto.EVP_PKEY_CTX_new.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_CTX_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_encapsulate_init.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_encapsulate.argtypes = [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, POINTER(c_size_t)]
libcrypto.EVP_PKEY_decapsulate_init.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_decapsulate.argtypes = [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t]

# AES-256-GCM
libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p
libcrypto.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
libcrypto.EVP_aes_256_gcm.restype = c_void_p
libcrypto.EVP_EncryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]
libcrypto.EVP_EncryptUpdate.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]
libcrypto.EVP_EncryptFinal_ex.argtypes = [c_void_p, c_char_p, POINTER(c_int)]
libcrypto.EVP_DecryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
libcrypto.EVP_DecryptUpdate.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]
libcrypto.EVP_DecryptFinal_ex.argtypes = [c_void_p, c_char_p, POINTER(c_int)]

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""):
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    try:
        libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), None, None, None)
        libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None)
        libcrypto.EVP_EncryptInit_ex(ctx, None, None, key, nonce)
        outlen = c_int(0)
        if aad:
            libcrypto.EVP_EncryptUpdate(ctx, None, byref(outlen), aad, len(aad))
        ct_buf = create_string_buffer(len(plaintext) + 16)
        libcrypto.EVP_EncryptUpdate(ctx, ct_buf, byref(outlen), plaintext, len(plaintext))
        total_len = outlen.value
        final_buf = create_string_buffer(16)
        final_len = c_int(0)
        libcrypto.EVP_EncryptFinal_ex(ctx, final_buf, byref(final_len))
        tag = create_string_buffer(16)
        libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)
        return ct_buf.raw[:total_len], tag.raw[:16]
    finally:
        libcrypto.EVP_CIPHER_CTX_free(ctx)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    try:
        libcrypto.EVP_DecryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), None, None, None)
        libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None)
        libcrypto.EVP_DecryptInit_ex(ctx, None, None, key, nonce)
        outlen = c_int(0)
        if aad:
            libcrypto.EVP_DecryptUpdate(ctx, None, byref(outlen), aad, len(aad))
        pt_buf = create_string_buffer(len(ciphertext) + 16)
        libcrypto.EVP_DecryptUpdate(ctx, pt_buf, byref(outlen), ciphertext, len(ciphertext))
        total_len = outlen.value
        libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        final_buf = create_string_buffer(16)
        final_len = c_int(0)
        ret = libcrypto.EVP_DecryptFinal_ex(ctx, final_buf, byref(final_len))
        if ret <= 0:
            raise ValueError("AES-GCM Authentication Failed!")
        return pt_buf.raw[:total_len]
    finally:
        libcrypto.EVP_CIPHER_CTX_free(ctx)


def main():
    pki_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pqc_pki_out"
    ca_crt_path = f"{pki_dir}/ca.crt".encode("utf-8")
    leaf_crt_path = f"{pki_dir}/receiver.crt".encode("utf-8")
    receiver_key_path = f"{pki_dir}/receiver.key".encode("utf-8")

    print("======================================================")
    print(" [Applied PQC Lab] PQC X.509 PKI End-to-End in Python")
    print(" (ML-DSA-65 Root CA + ML-KEM-768 Leaf + AES-256-GCM)")
    print("======================================================")

    # 1. Load Root CA and Leaf Certificates
    print("[+] Step 1: Loading Root CA (ML-DSA-65) and Receiver Cert (ML-KEM-768)...")
    bio_ca = libcrypto.BIO_new_file(ca_crt_path, b"r")
    ca_cert = libcrypto.PEM_read_bio_X509(bio_ca, None, None, None)
    libcrypto.BIO_free(bio_ca)
    assert ca_cert, "Failed to load ca.crt"

    bio_leaf = libcrypto.BIO_new_file(leaf_crt_path, b"r")
    leaf_cert = libcrypto.PEM_read_bio_X509(bio_leaf, None, None, None)
    libcrypto.BIO_free(bio_leaf)
    assert leaf_cert, "Failed to load receiver.crt"

    # 2. Sender verifies Certificate Chain
    print("[+] Step 2: Sender verifying Receiver X.509 Certificate Chain...")
    store = libcrypto.X509_STORE_new()
    libcrypto.X509_STORE_add_cert(store, ca_cert)
    vctx = libcrypto.X509_STORE_CTX_new()
    libcrypto.X509_STORE_CTX_init(vctx, store, leaf_cert, None)
    is_valid = libcrypto.X509_verify_cert(vctx)
    assert is_valid == 1, "Certificate verification failed!"
    print("    [PASS] X.509 Certificate Chain signed by ML-DSA-65 Root CA verified!")
    libcrypto.X509_STORE_CTX_free(vctx)
    libcrypto.X509_STORE_free(store)

    # 3. Sender extracts ML-KEM-768 public key from verified cert and encapsulates
    print("[+] Step 3: Extracting ML-KEM-768 public key from verified certificate...")
    extracted_pubkey = libcrypto.X509_get0_pubkey(leaf_cert)
    assert extracted_pubkey, "Failed to extract public key"

    print("[+] Step 4: Sender executing ML-KEM-768 Encap(pkR)...")
    ectx = libcrypto.EVP_PKEY_CTX_new(extracted_pubkey, None)
    libcrypto.EVP_PKEY_encapsulate_init(ectx, None)
    ct_len = c_size_t(0)
    secret_len = c_size_t(0)
    libcrypto.EVP_PKEY_encapsulate(ectx, None, byref(ct_len), None, byref(secret_len))

    ct_buf = create_string_buffer(ct_len.value)
    sender_secret = create_string_buffer(secret_len.value)
    libcrypto.EVP_PKEY_encapsulate(ectx, ct_buf, byref(ct_len), sender_secret, byref(secret_len))
    libcrypto.EVP_PKEY_CTX_free(ectx)
    print(f"    Encapsulated Ciphertext size: {ct_len.value} bytes (Expect 1088)")
    print(f"    Sender Shared Secret size   : {secret_len.value} bytes (32 bytes)")

    # 4. Sender encrypts payload with AES-256-GCM using derived secret
    print("[+] Step 5: Sender encrypting confidential payload with AES-256-GCM...")
    plaintext = b"Authenticated End-to-End PQC Message delivered via X.509 PKI."
    nonce = os.urandom(12)
    aad = b"PQC-PKI-v1-Auth"
    ciphertext_payload, tag = aes_gcm_encrypt(sender_secret.raw[:secret_len.value], nonce, plaintext, aad)

    # 5. Receiver loads private key and performs Decap
    print("[+] Step 6: Receiver decapsulating shared secret with private key...")
    bio_priv = libcrypto.BIO_new_file(receiver_key_path, b"r")
    rec_priv = libcrypto.PEM_read_bio_PrivateKey(bio_priv, None, None, None)
    libcrypto.BIO_free(bio_priv)
    assert rec_priv, "Failed to load receiver.key"

    dctx = libcrypto.EVP_PKEY_CTX_new(rec_priv, None)
    libcrypto.EVP_PKEY_decapsulate_init(dctx, None)
    receiver_secret = create_string_buffer(secret_len.value)
    dec_len = c_size_t(secret_len.value)
    libcrypto.EVP_PKEY_decapsulate(dctx, receiver_secret, byref(dec_len), ct_buf, ct_len.value)
    libcrypto.EVP_PKEY_CTX_free(dctx)

    assert sender_secret.raw[:secret_len.value] == receiver_secret.raw[:secret_len.value]
    print("    [PASS] Decapsulated shared secret matches sender secret 100%!")

    # 6. Receiver decrypts payload
    print("[+] Step 7: Receiver decrypting payload and verifying AAD...")
    decrypted_msg = aes_gcm_decrypt(receiver_secret.raw[:secret_len.value], nonce, ciphertext_payload, tag, aad)
    assert decrypted_msg == plaintext

    print("======================================================")
    print(f" [PASS] Decrypted message: \"{decrypted_msg.decode('utf-8')}\"")
    print(" [SUCCESS] Python PQC X.509 PKI End-to-End verified!")
    print("======================================================")

    libcrypto.EVP_PKEY_free(rec_priv)
    libcrypto.X509_free(leaf_cert)
    libcrypto.X509_free(ca_cert)


if __name__ == "__main__":
    main()
