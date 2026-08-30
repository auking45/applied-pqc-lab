// =============================================================================
// Applied PQC Lab - NIST FIPS 203 ML-KEM-768 in C++20
// Native OpenSSL 3.5+ EVP Encap / Decap + AES-256-GCM
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/rand.h>

struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); } };

using ScopedPKEY = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using ScopedPKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

ScopedPKEY generate_mlkem_keypair(const std::string& alg_name = "ML-KEM-768") {
    ScopedPKEY_CTX kctx(EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr));
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen_init failed for " + alg_name);
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &pkey) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen failed for " + alg_name);
    }
    return ScopedPKEY(pkey);
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> mlkem_encapsulate(EVP_PKEY* pkey) {
    ScopedPKEY_CTX ectx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ectx || EVP_PKEY_encapsulate_init(ectx.get(), nullptr) <= 0) {
        throw std::runtime_error("EVP_PKEY_encapsulate_init failed");
    }
    size_t ct_len = 0, secret_len = 0;
    if (EVP_PKEY_encapsulate(ectx.get(), nullptr, &ct_len, nullptr, &secret_len) <= 0) {
        throw std::runtime_error("EVP_PKEY_encapsulate get sizes failed");
    }
    std::vector<uint8_t> ct(ct_len);
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_encapsulate(ectx.get(), ct.data(), &ct_len, secret.data(), &secret_len) <= 0) {
        throw std::runtime_error("EVP_PKEY_encapsulate execution failed");
    }
    return {ct, secret};
}

std::vector<uint8_t> mlkem_decapsulate(EVP_PKEY* pkey, const std::vector<uint8_t>& ct) {
    ScopedPKEY_CTX dctx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!dctx || EVP_PKEY_decapsulate_init(dctx.get(), nullptr) <= 0) {
        throw std::runtime_error("EVP_PKEY_decapsulate_init failed");
    }
    size_t secret_len = 0;
    if (EVP_PKEY_decapsulate(dctx.get(), nullptr, &secret_len, ct.data(), ct.size()) <= 0) {
        throw std::runtime_error("EVP_PKEY_decapsulate get size failed");
    }
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_decapsulate(dctx.get(), secret.data(), &secret_len, ct.data(), ct.size()) <= 0) {
        throw std::runtime_error("EVP_PKEY_decapsulate execution failed");
    }
    return secret;
}

int main() {
    std::cout << "======================================================\n";
    std::cout << " [Applied PQC Lab] NIST FIPS 203 ML-KEM-768 in C++20\n";
    std::cout << " Native OpenSSL 3.5+ EVP Encap / Decap\n";
    std::cout << "======================================================\n";

    try {
        // Step 1: Generate ML-KEM-768 Keypair
        std::cout << "[+] Step 1: Generating Receiver's ML-KEM-768 keypair...\n";
        auto rec_pkey = generate_mlkem_keypair("ML-KEM-768");

        // Step 2: Sender Encap(pkR)
        std::cout << "[+] Step 2: Sender executing Encap(pkR)...\n";
        auto [ciphertext, sender_secret] = mlkem_encapsulate(rec_pkey.get());
        std::cout << "    Encapsulated Ciphertext size: " << ciphertext.size() << " bytes (Expect 1088)\n";
        std::cout << "    Derived Shared Secret size  : " << sender_secret.size() << " bytes (32 bytes)\n";

        // Step 3: Sender Encrypts with AES-256-GCM
        std::string plaintext = "Top Secret Payload protected by NIST FIPS 203 Post-Quantum Cryptography.";
        std::string aad = "PQC-Session-Metadata-FIPS203";
        std::vector<uint8_t> nonce(12, 0x55);

        std::cout << "[+] Step 3: Sender encrypting payload with AES-256-GCM...\n";
        ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, sender_secret.data(), nonce.data());

        int outlen = 0;
        EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

        std::vector<uint8_t> encrypted_payload(plaintext.size() + 16);
        EVP_EncryptUpdate(ctx.get(), encrypted_payload.data(), &outlen, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        int ct_len = outlen;
        EVP_EncryptFinal_ex(ctx.get(), encrypted_payload.data() + outlen, &outlen);
        ct_len += outlen;
        encrypted_payload.resize(ct_len);

        std::vector<uint8_t> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        // Step 4: Receiver Decap(skR, ct)
        std::cout << "[+] Step 4: Receiver executing Decap(skR, ct)...\n";
        auto rec_secret = mlkem_decapsulate(rec_pkey.get(), ciphertext);
        if (rec_secret != sender_secret) {
            throw std::runtime_error("Decapsulated secret mismatch!");
        }
        std::cout << "    [PASS] Decapsulated secret matches sender secret 100%!\n";

        // Step 5: Receiver Decrypts Payload
        std::cout << "[+] Step 5: Receiver decrypting payload and verifying AAD...\n";
        ScopedCipherCtx dctx(EVP_CIPHER_CTX_new());
        EVP_DecryptInit_ex(dctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(dctx.get(), nullptr, nullptr, rec_secret.data(), nonce.data());
        EVP_DecryptUpdate(dctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

        std::vector<uint8_t> decrypted(encrypted_payload.size());
        EVP_DecryptUpdate(dctx.get(), decrypted.data(), &outlen, encrypted_payload.data(), encrypted_payload.size());
        int pt_len = outlen;

        EVP_CIPHER_CTX_ctrl(dctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        if (EVP_DecryptFinal_ex(dctx.get(), decrypted.data() + outlen, &outlen) <= 0) {
            throw std::runtime_error("AEAD Tag verification failed!");
        }
        pt_len += outlen;
        decrypted.resize(pt_len);

        std::string decrypted_str(decrypted.begin(), decrypted.end());
        std::cout << "======================================================\n";
        std::cout << " [PASS] Decrypted message: \"" << decrypted_str << "\"\n";
        std::cout << " [SUCCESS] NIST FIPS 203 ML-KEM-768 verified in C++20!\n";
        std::cout << "======================================================\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
}
