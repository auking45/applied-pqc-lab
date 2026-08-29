// =============================================================================
// Applied PQC Lab - Classical Hybrid Encryption in C++20
// RSA-3072 OAEP Key Wrapping + AES-256-GCM Authenticated Encryption
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };

using ScopedPKEY = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using ScopedPKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

ScopedPKEY generate_rsa_keypair(int bits = 3072) {
    ScopedPKEY_CTX ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) throw std::runtime_error("RSA keygen init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) throw std::runtime_error("RSA bits set failed");
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) throw std::runtime_error("RSA keygen failed");
    return ScopedPKEY(pkey);
}

std::vector<uint8_t> rsa_oaep_wrap_key(EVP_PKEY* pubkey, const std::vector<uint8_t>& dek) {
    ScopedPKEY_CTX ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pubkey, nullptr));
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) throw std::runtime_error("RSA encrypt init failed");
    EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());

    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, dek.data(), dek.size());
    std::vector<uint8_t> wrapped(outlen);
    EVP_PKEY_encrypt(ctx.get(), wrapped.data(), &outlen, dek.data(), dek.size());
    wrapped.resize(outlen);
    return wrapped;
}

std::vector<uint8_t> rsa_oaep_unwrap_key(EVP_PKEY* privkey, const std::vector<uint8_t>& wrapped_dek) {
    ScopedPKEY_CTX ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, privkey, nullptr));
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) throw std::runtime_error("RSA decrypt init failed");
    EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256());

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, wrapped_dek.data(), wrapped_dek.size());
    std::vector<uint8_t> dek(outlen);
    EVP_PKEY_decrypt(ctx.get(), dek.data(), &outlen, wrapped_dek.data(), wrapped_dek.size());
    dek.resize(outlen);
    return dek;
}

struct EncryptedPayload {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
};

EncryptedPayload aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::string& plaintext) {
    EncryptedPayload result;
    result.iv.resize(12);
    RAND_bytes(result.iv.data(), 12);

    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.iv.data());

    result.ciphertext.resize(plaintext.size() + 16);
    int outlen = 0;
    EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &outlen,
                      reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    int total_len = outlen;
    EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + outlen, &outlen);
    total_len += outlen;
    result.ciphertext.resize(total_len);

    result.tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, result.tag.data());
    return result;
}

std::string aes_gcm_decrypt(const std::vector<uint8_t>& key, const EncryptedPayload& payload) {
    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, payload.iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), payload.iv.data());

    std::vector<uint8_t> plaintext(payload.ciphertext.size());
    int outlen = 0;
    EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, payload.ciphertext.data(), payload.ciphertext.size());
    int total_len = outlen;

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, payload.tag.size(), const_cast<uint8_t*>(payload.tag.data()));
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) <= 0) {
        throw std::runtime_error("AES-GCM authentication tag verification failed!");
    }
    total_len += outlen;
    plaintext.resize(total_len);
    return std::string(plaintext.begin(), plaintext.end());
}

int main() {
    std::cout << "======================================================\n";
    std::cout << " [Applied PQC Lab] C++20 Classical Hybrid Encryption\n";
    std::cout << " (RSA-3072 OAEP + AES-256-GCM)\n";
    std::cout << "======================================================\n";

    try {
        std::cout << "[+] Step 1: Generating Receiver RSA-3072 keypair...\n";
        auto keypair = generate_rsa_keypair(3072);

        std::cout << "[+] Step 2: Sender generating ephemeral 256-bit DEK...\n";
        std::vector<uint8_t> dek(32);
        RAND_bytes(dek.data(), 32);

        std::cout << "[+] Step 3: Sender wrapping DEK with RSA-OAEP-SHA256...\n";
        auto wrapped_dek = rsa_oaep_wrap_key(keypair.get(), dek);

        std::string original_msg = "Hello, Post-Quantum World! C++20 Classical Hybrid Verified.";
        std::cout << "[+] Step 4: Sender encrypting message with AES-256-GCM...\n";
        auto payload = aes_gcm_encrypt(dek, original_msg);

        std::cout << "[+] Step 5: Receiver unwrapping DEK with RSA Private Key...\n";
        auto unwrapped_dek = rsa_oaep_unwrap_key(keypair.get(), wrapped_dek);
        if (unwrapped_dek != dek) throw std::runtime_error("DEK mismatch!");

        std::cout << "[+] Step 6: Receiver decrypting payload with unwrapped DEK...\n";
        std::string decrypted_msg = aes_gcm_decrypt(unwrapped_dek, payload);

        if (decrypted_msg == original_msg) {
            std::cout << "======================================================\n";
            std::cout << " [PASS] Decrypted message: \"" << decrypted_msg << "\"\n";
            std::cout << " [SUCCESS] C++20 Classical Hybrid Encryption verified!\n";
            std::cout << "======================================================\n";
            return 0;
        }
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
}
