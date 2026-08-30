#!/usr/bin/env python3
"""
Applied PQC Lab - NIST FIPS 203 ML-KEM-768 in Python
Native OpenSSL 3.5+ libcrypto EVP Encap / Decap + AES-256-GCM (Zero Pip Dependencies)
"""

import ctypes
import os
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

# Configure EVP Prototypes
libcrypto.EVP_PKEY_CTX_new_from_name.restype = c_void_p
libcrypto.EVP_PKEY_CTX_new_from_name.argtypes = [c_void_p, c_char_p, c_char_p]
libcrypto.EVP_PKEY_keygen_init.argtypes = [c_void_p]
libcrypto.EVP_PKEY_keygen.argtypes = [c_void_p, POINTER(c_void_p)]
libcrypto.EVP_PKEY_CTX_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_CTX_new.restype = c_void_p
libcrypto.EVP_PKEY_CTX_new.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_encapsulate_init.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_encapsulate.argtypes = [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, POINTER(c_size_t)]
libcrypto.EVP_PKEY_decapsulate_init.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_decapsulate.argtypes = [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t]

# AES-GCM Prototypes
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


def generate_mlkem_keypair(algorithm_name: bytes = b"ML-KEM-768"):
    kctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, algorithm_name, None)
    if not kctx or libcrypto.EVP_PKEY_keygen_init(kctx) <= 0:
        raise RuntimeError("EVP_PKEY_keygen_init failed for ML-KEM")
    pkey = c_void_p()
    if libcrypto.EVP_PKEY_keygen(kctx, byref(pkey)) <= 0:
        raise RuntimeError("EVP_PKEY_keygen failed for ML-KEM")
    libcrypto.EVP_PKEY_CTX_free(kctx)
    return pkey


def mlkem_encapsulate(pkey: c_void_p):
    ectx = libcrypto.EVP_PKEY_CTX_new(pkey, None)
    if not ectx or libcrypto.EVP_PKEY_encapsulate_init(ectx, None) <= 0:
        raise RuntimeError("EVP_PKEY_encapsulate_init failed")

    ct_len = c_size_t(0)
    secret_len = c_size_t(0)
    libcrypto.EVP_PKEY_encapsulate(ectx, None, byref(ct_len), None, byref(secret_len))

    ct_buf = create_string_buffer(ct_len.value)
    secret_buf = create_string_buffer(secret_len.value)
    if libcrypto.EVP_PKEY_encapsulate(ectx, ct_buf, byref(ct_len), secret_buf, byref(secret_len)) <= 0:
        raise RuntimeError("EVP_PKEY_encapsulate failed")

    libcrypto.EVP_PKEY_CTX_free(ectx)
    return ct_buf.raw[:ct_len.value], secret_buf.raw[:secret_len.value]


def mlkem_decapsulate(pkey: c_void_p, ciphertext: bytes):
    dctx = libcrypto.EVP_PKEY_CTX_new(pkey, None)
    if not dctx or libcrypto.EVP_PKEY_decapsulate_init(dctx, None) <= 0:
        raise RuntimeError("EVP_PKEY_decapsulate_init failed")

    secret_len = c_size_t(0)
    libcrypto.EVP_PKEY_decapsulate(dctx, None, byref(secret_len), ciphertext, len(ciphertext))

    secret_buf = create_string_buffer(secret_len.value)
    if libcrypto.EVP_PKEY_decapsulate(dctx, secret_buf, byref(secret_len), ciphertext, len(ciphertext)) <= 0:
        raise RuntimeError("EVP_PKEY_decapsulate failed")

    libcrypto.EVP_PKEY_CTX_free(dctx)
    return secret_buf.raw[:secret_len.value]


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
            raise ValueError("AES-GCM Authentication Tag Verification Failed!")
        return pt_buf.raw[:total_len]
    finally:
        libcrypto.EVP_CIPHER_CTX_free(ctx)


def main():
    print("======================================================")
    print(" [Applied PQC Lab] NIST FIPS 203 ML-KEM-768 in Python")
    print(" Native OpenSSL 3.5+ libcrypto EVP Encap / Decap")
    print("======================================================")

    # 1. Receiver generates ML-KEM-768 keypair
    print("[+] Step 1: Generating Receiver's ML-KEM-768 keypair...")
    rec_pkey = generate_mlkem_keypair(b"ML-KEM-768")

    # 2. Sender encapsulates shared secret
    print("[+] Step 2: Sender executing Encap(pkR)...")
    ciphertext, sender_secret = mlkem_encapsulate(rec_pkey)
    print(f"    Encapsulated Ciphertext size: {len(ciphertext)} bytes (Expect 1088 bytes)")
    print(f"    Derived Shared Secret size  : {len(sender_secret)} bytes (32 bytes / 256 bits)")

    # 3. Sender encrypts confidential payload with AES-256-GCM
    print("[+] Step 3: Sender encrypting payload with AES-256-GCM using derived secret...")
    plaintext = b"Top Secret Payload protected by NIST FIPS 203 Post-Quantum Cryptography."
    nonce = os.urandom(12)
    aad = b"PQC-Session-Metadata-FIPS203"
    ct_payload, tag = aes_gcm_encrypt(sender_secret, nonce, plaintext, aad)
    print(f"    Encrypted Payload size: {len(ct_payload)} bytes, Tag size: {len(tag)} bytes")

    # 4. Receiver decapsulates shared secret
    print("[+] Step 4: Receiver executing Decap(skR, ct)...")
    receiver_secret = mlkem_decapsulate(rec_pkey, ciphertext)

    assert receiver_secret == sender_secret, "Decapsulated secret mismatch!"
    print("    [PASS] Decapsulated secret matches sender secret 100%!")

    # 5. Receiver decrypts payload
    print("[+] Step 5: Receiver decrypting payload and verifying AAD...")
    decrypted_msg = aes_gcm_decrypt(receiver_secret, nonce, ct_payload, tag, aad)

    assert decrypted_msg == plaintext, "Plaintext payload mismatch!"
    print("======================================================")
    print(f" [PASS] Decrypted message: \"{decrypted_msg.decode('utf-8')}\"")
    print(" [SUCCESS] NIST FIPS 203 ML-KEM-768 verified in Python!")
    print("======================================================")

    libcrypto.EVP_PKEY_free(rec_pkey)


if __name__ == "__main__":
    main()
