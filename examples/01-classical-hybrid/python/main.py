#!/usr/bin/env python3
"""
Applied PQC Lab - Classical Hybrid Encryption in Python
RSA-3072 OAEP Key Wrapping + AES-256-GCM Authenticated Encryption
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    print("======================================================")
    print(" [Applied PQC Lab] Python Classical Hybrid Encryption")
    print(" (RSA-3072 OAEP + AES-256-GCM)")
    print("======================================================")

    # 1. 수신자 RSA-3072 키쌍 생성
    print("[+] Step 1: Generating Receiver's RSA-3072 keypair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    # 2. 송신자: 256비트 임시 대칭키(DEK) 및 96비트 IV(Nonce) 생성
    print("[+] Step 2: Sender generating ephemeral 256-bit DEK & Nonce...")
    dek = os.urandom(32)  # 256-bit AES Key
    nonce = os.urandom(12)  # 96-bit AES-GCM Nonce

    # 3. 송신자: 수신자 공개키로 DEK 래핑 (RSA-OAEP-SHA256)
    print("[+] Step 3: Sender wrapping DEK with Receiver's RSA Public Key (RSA-OAEP)...")
    wrapped_dek = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print(f"    Wrapped DEK size: {len(wrapped_dek)} bytes (RSA modulus size)")

    # 4. 송신자: DEK로 대용량 페이로드 암호화 (AES-256-GCM)
    original_message = b"Hello, Post-Quantum World! Python Classical Hybrid Verified."
    print("[+] Step 4: Sender encrypting payload with AES-256-GCM...")
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, original_message, associated_data=None)
    print(f"    Ciphertext size: {len(ciphertext)} bytes (includes 16-byte authentication tag)")

    # 5. 수신자: 개인키로 DEK 언래핑
    print("[+] Step 5: Receiver unwrapping DEK with RSA Private Key...")
    unwrapped_dek = private_key.decrypt(
        wrapped_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    assert unwrapped_dek == dek, "DEK mismatch!"
    print("    [PASS] Unwrapped DEK exactly matches original DEK!")

    # 6. 수신자: DEK로 페이로드 복호화 및 무결성 검증
    print("[+] Step 6: Receiver decrypting payload and verifying auth tag...")
    receiver_aesgcm = AESGCM(unwrapped_dek)
    decrypted_msg = receiver_aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    assert decrypted_msg == original_message, "Plaintext mismatch!"
    print("======================================================")
    print(f" [PASS] Decrypted message: \"{decrypted_msg.decode('utf-8')}\"")
    print(" [SUCCESS] Python Classical Hybrid Encryption verified!")
    print("======================================================")


if __name__ == "__main__":
    main()
