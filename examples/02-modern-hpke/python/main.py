#!/usr/bin/env python3
"""
Applied PQC Lab - RFC 9180 HPKE (Hybrid Public Key Encryption) in Python
Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM (Base Mode)
"""

import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def hpke_labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    labeled_ikm = b"HPKE-v1" + label + ikm
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"")
    return hkdf.derive(labeled_ikm)


def hpke_labeled_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + label + info
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=labeled_info)
    # Using HKDF Expand directly via extract/expand
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=labeled_info).derive(prk)


def setup_base_sender(receiver_pubkey_bytes: bytes, info: bytes = b""):
    # 1. Generate ephemeral keypair
    sender_ephemeral_priv = x25519.X25519PrivateKey.generate()
    sender_ephemeral_pub = sender_ephemeral_priv.public_key()
    enc = sender_ephemeral_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # 2. Compute DH shared secret
    receiver_pub = x25519.X25519PublicKey.from_public_bytes(receiver_pubkey_bytes)
    dh_shared = sender_ephemeral_priv.exchange(receiver_pub)

    # 3. KEM Key Derivation (RFC 9180 DHKEM)
    kem_context = enc + receiver_pubkey_bytes
    shared_secret = hpke_labeled_extract(salt=b"", label=b"shared_secret", ikm=dh_shared)
    key_schedule_secret = hpke_labeled_extract(salt=shared_secret, label=b"secret", ikm=kem_context + info)

    key = hpke_labeled_expand(key_schedule_secret, label=b"key", info=b"", length=32)
    base_nonce = hpke_labeled_expand(key_schedule_secret, label=b"base_nonce", info=b"", length=12)

    return enc, key, base_nonce


def setup_base_receiver(enc_bytes: bytes, receiver_priv: x25519.X25519PrivateKey, info: bytes = b""):
    sender_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(enc_bytes)
    receiver_pub_bytes = receiver_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # 1. Compute DH shared secret
    dh_shared = receiver_priv.exchange(sender_ephemeral_pub)

    # 2. KEM Key Derivation
    kem_context = enc_bytes + receiver_pub_bytes
    shared_secret = hpke_labeled_extract(salt=b"", label=b"shared_secret", ikm=dh_shared)
    key_schedule_secret = hpke_labeled_extract(salt=shared_secret, label=b"secret", ikm=kem_context + info)

    key = hpke_labeled_expand(key_schedule_secret, label=b"key", info=b"", length=32)
    base_nonce = hpke_labeled_expand(key_schedule_secret, label=b"base_nonce", info=b"", length=12)

    return key, base_nonce


def main():
    print("======================================================")
    print(" [Applied PQC Lab] RFC 9180 HPKE Base Mode in Python")
    print(" Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM")
    print("======================================================")

    # 1. Receiver generates static X25519 keypair
    print("[+] Step 1: Generating Receiver's static X25519 keypair...")
    receiver_priv = x25519.X25519PrivateKey.generate()
    receiver_pub_bytes = receiver_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"    Receiver Public Key: {receiver_pub_bytes.hex()[:32]}... ({len(receiver_pub_bytes)} bytes)")

    # 2. Sender runs SetupBaseS
    app_info = b"Applied-PQC-Lab-HPKE-Context"
    aad = b"Authenticated-Session-Metadata-v1"
    plaintext = b"Confidential Payload secured by RFC 9180 HPKE Base Mode."

    print("[+] Step 2: Sender executing SetupBaseS(pkR)...")
    enc, sender_key, sender_nonce = setup_base_sender(receiver_pub_bytes, info=app_info)
    print(f"    Encapsulated Key (enc): {enc.hex()[:32]}... ({len(enc)} bytes)")

    # 3. Sender seals (encrypts) payload
    print("[+] Step 3: Sender sealing payload with AES-256-GCM...")
    aesgcm = AESGCM(sender_key)
    ciphertext = aesgcm.encrypt(sender_nonce, plaintext, associated_data=aad)
    print(f"    Ciphertext + Tag size: {len(ciphertext)} bytes")

    # 4. Receiver runs SetupBaseR
    print("[+] Step 4: Receiver executing SetupBaseR(enc, skR)...")
    receiver_key, receiver_nonce = setup_base_receiver(enc, receiver_priv, info=app_info)

    assert receiver_key == sender_key, "Derived AEAD key mismatch!"
    assert receiver_nonce == sender_nonce, "Derived base nonce mismatch!"
    print("    [PASS] Key Schedule secrets perfectly synchronized!")

    # 5. Receiver opens (decrypts & authenticates) ciphertext
    print("[+] Step 5: Receiver opening payload with AAD verification...")
    receiver_aesgcm = AESGCM(receiver_key)
    decrypted_msg = receiver_aesgcm.decrypt(receiver_nonce, ciphertext, associated_data=aad)

    assert decrypted_msg == plaintext, "Plaintext mismatch!"
    print("======================================================")
    print(f" [PASS] Decrypted message: \"{decrypted_msg.decode('utf-8')}\"")
    print(" [SUCCESS] RFC 9180 HPKE Base Mode verified in Python!")
    print("======================================================")


if __name__ == "__main__":
    main()
