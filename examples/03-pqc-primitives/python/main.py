#!/usr/bin/env python3
"""
Applied PQC Lab - NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA in Python
Native OpenSSL 3.5+ libcrypto EVP APIs (Zero Pip Dependencies)
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

# EVP Key & KEM Prototypes
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

# EVP DigestSign / DigestVerify Prototypes (for ML-DSA)
libcrypto.EVP_MD_CTX_new.restype = c_void_p
libcrypto.EVP_MD_CTX_free.argtypes = [c_void_p]
libcrypto.EVP_DigestSignInit.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.EVP_DigestSign.argtypes = [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t]
libcrypto.EVP_DigestVerifyInit.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.EVP_DigestVerify.argtypes = [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t]

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


# =============================================================================
# 1. FIPS 203 ML-KEM Functions
# =============================================================================
def generate_pqc_keypair(algorithm_name: bytes):
    kctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, algorithm_name, None)
    if not kctx or libcrypto.EVP_PKEY_keygen_init(kctx) <= 0:
        raise RuntimeError(f"EVP_PKEY_keygen_init failed for {algorithm_name.decode()}")
    pkey = c_void_p()
    if libcrypto.EVP_PKEY_keygen(kctx, byref(pkey)) <= 0:
        raise RuntimeError(f"EVP_PKEY_keygen failed for {algorithm_name.decode()}")
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


# =============================================================================
# 2. FIPS 204 ML-DSA Functions
# =============================================================================
def mldsa_sign(pkey: c_void_p, message: bytes) -> bytes:
    mctx = libcrypto.EVP_MD_CTX_new()
    if not mctx or libcrypto.EVP_DigestSignInit(mctx, None, None, None, pkey) <= 0:
        raise RuntimeError("EVP_DigestSignInit failed")
    sig_len = c_size_t(0)
    libcrypto.EVP_DigestSign(mctx, None, byref(sig_len), message, len(message))
    sig_buf = create_string_buffer(sig_len.value)
    if libcrypto.EVP_DigestSign(mctx, sig_buf, byref(sig_len), message, len(message)) <= 0:
        raise RuntimeError("EVP_DigestSign failed")
    libcrypto.EVP_MD_CTX_free(mctx)
    return sig_buf.raw[:sig_len.value]


def mldsa_verify(pkey: c_void_p, message: bytes, signature: bytes) -> bool:
    vmctx = libcrypto.EVP_MD_CTX_new()
    if not vmctx or libcrypto.EVP_DigestVerifyInit(vmctx, None, None, None, pkey) <= 0:
        raise RuntimeError("EVP_DigestVerifyInit failed")
    ret = libcrypto.EVP_DigestVerify(vmctx, signature, len(signature), message, len(message))
    libcrypto.EVP_MD_CTX_free(vmctx)
    return ret > 0


def main():
    print("======================================================")
    print(" [Applied PQC Lab] NIST PQC Primitives in Python")
    print(" FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 (OpenSSL 3.5)")
    print("======================================================")

    # -------------------------------------------------------------------------
    # Part 1: FIPS 203 ML-KEM-768 Encap / Decap
    # -------------------------------------------------------------------------
    print("\n--- [Part 1] FIPS 203 ML-KEM-768 Key Encapsulation ---")
    rec_kem_pkey = generate_pqc_keypair(b"ML-KEM-768")
    ciphertext, sender_secret = mlkem_encapsulate(rec_kem_pkey)
    print(f"[+] Sender Encap: Ciphertext size = {len(ciphertext)}B, Secret = {len(sender_secret)}B")

    receiver_secret = mlkem_decapsulate(rec_kem_pkey, ciphertext)
    assert receiver_secret == sender_secret, "KEM secret mismatch!"
    print(f"[+] Receiver Decap: [PASS] Derived matching 32-byte shared secret!")
    libcrypto.EVP_PKEY_free(rec_kem_pkey)

    # -------------------------------------------------------------------------
    # Part 2: FIPS 204 ML-DSA-65 Digital Signature & Verification
    # -------------------------------------------------------------------------
    print("\n--- [Part 2] FIPS 204 ML-DSA-65 Digital Signature ---")
    signer_dsa_pkey = generate_pqc_keypair(b"ML-DSA-65")
    message = b"Critical Legal Contract signed with Quantum-Resistant FIPS 204 ML-DSA."

    print(f"[+] Signer generating signature for payload ({len(message)} bytes)...")
    signature = mldsa_sign(signer_dsa_pkey, message)
    print(f"[+] ML-DSA-65 Signature generated: size = {len(signature)} bytes (Expect 3309)")

    print("[+] Verifier validating ML-DSA signature against payload...")
    is_valid = mldsa_verify(signer_dsa_pkey, message, signature)
    assert is_valid, "ML-DSA signature verification failed!"
    print("    [PASS] Signature verified successfully!")

    print("======================================================")
    print(" [SUCCESS] FIPS 203 ML-KEM & FIPS 204 ML-DSA verified in Python!")
    print("======================================================")

    libcrypto.EVP_PKEY_free(signer_dsa_pkey)


if __name__ == "__main__":
    main()
