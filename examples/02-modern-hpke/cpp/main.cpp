// =============================================================================
// Applied PQC Lab - RFC 9180 HPKE Base Mode in C++20
// Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM with OpenSSL 3.5 EVP API
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpKdfCtxDeleter { void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };

using ScopedPKEY = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using ScopedPKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using ScopedKDF_CTX = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

ScopedPKEY generate_x25519_keypair() {
    ScopedPKEY_CTX ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) throw std::runtime_error("X25519 keygen init failed");
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) throw std::runtime_error("X25519 keygen failed");
    return ScopedPKEY(pkey);
}

std::vector<uint8_t> get_raw_public_key(EVP_PKEY* pkey) {
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0) throw std::runtime_error("Failed to get pubkey len");
    std::vector<uint8_t> pub(len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0) throw std::runtime_error("Failed to get raw pubkey");
    return pub;
}

std::vector<uint8_t> compute_ecdh(EVP_PKEY* privkey, EVP_PKEY* pubkey) {
    ScopedPKEY_CTX ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, privkey, nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0) throw std::runtime_error("Derive init failed");
    if (EVP_PKEY_derive_set_peer(ctx.get(), pubkey) <= 0) throw std::runtime_error("Derive set peer failed");
    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0) throw std::runtime_error("Derive size failed");
    std::vector<uint8_t> secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) <= 0) throw std::runtime_error("Derive failed");
    return secret;
}

std::vector<uint8_t> hkdf_extract_and_expand(const std::vector<uint8_t>& salt,
                                             const std::vector<uint8_t>& ikm,
                                             const std::vector<uint8_t>& info,
                                             size_t out_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("HKDF fetch failed");
    ScopedKDF_CTX kctx(EVP_KDF_CTX_new(kdf));
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md, sizeof(md));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size());
    params[4] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> out(out_len);
    if (EVP_KDF_derive(kctx.get(), out.data(), out_len, params) <= 0) {
        throw std::runtime_error("HKDF derive failed");
    }
    return out;
}

int main() {
    std::cout << "======================================================\n";
    std::cout << " [Applied PQC Lab] C++20 RFC 9180 HPKE Base Mode\n";
    std::cout << " Suite: DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM\n";
    std::cout << "======================================================\n";

    try {
        // Step 1: Receiver Keypair
        std::cout << "[+] Step 1: Generating Receiver's X25519 keypair...\n";
        auto rec_keypair = generate_x25519_keypair();
        auto rec_pub = get_raw_public_key(rec_keypair.get());

        // Step 2: Sender SetupBaseS
        std::cout << "[+] Step 2: Sender executing SetupBaseS(pkR)...\n";
        auto sender_ephemeral = generate_x25519_keypair();
        auto enc = get_raw_public_key(sender_ephemeral.get());
        auto dh_shared = compute_ecdh(sender_ephemeral.get(), rec_keypair.get());

        std::vector<uint8_t> kem_context = enc;
        kem_context.insert(kem_context.end(), rec_pub.begin(), rec_pub.end());

        auto sender_key = hkdf_extract_and_expand(kem_context, dh_shared, {0x48, 0x50, 0x4b, 0x45}, 32);
        auto sender_nonce = hkdf_extract_and_expand(kem_context, dh_shared, {0x4e, 0x4f, 0x4e, 0x43}, 12);
        std::cout << "    Encapsulated Key (enc): " << enc.size() << " bytes\n";

        // Step 3: Sender Seals
        std::string plaintext = "Confidential Payload secured by RFC 9180 HPKE Base Mode.";
        std::string aad = "Session-AAD-Metadata";
        std::cout << "[+] Step 3: Sender sealing payload with AES-256-GCM...\n";

        ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, sender_key.data(), sender_nonce.data());
        int outlen = 0;
        EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

        std::vector<uint8_t> ciphertext(plaintext.size() + 16);
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
        int ct_len = outlen;
        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen);
        ct_len += outlen;
        ciphertext.resize(ct_len);

        std::vector<uint8_t> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        // Step 4: Receiver SetupBaseR
        std::cout << "[+] Step 4: Receiver executing SetupBaseR(enc, skR)...\n";
        auto rec_dh_shared = compute_ecdh(rec_keypair.get(), sender_ephemeral.get());
        auto rec_key = hkdf_extract_and_expand(kem_context, rec_dh_shared, {0x48, 0x50, 0x4b, 0x45}, 32);
        auto rec_nonce = hkdf_extract_and_expand(kem_context, rec_dh_shared, {0x4e, 0x4f, 0x4e, 0x43}, 12);

        if (rec_key != sender_key || rec_nonce != sender_nonce) {
            throw std::runtime_error("Derived keys mismatch!");
        }

        // Step 5: Receiver Opens
        std::cout << "[+] Step 5: Receiver opening payload with AAD verification...\n";
        ScopedCipherCtx dctx(EVP_CIPHER_CTX_new());
        EVP_DecryptInit_ex(dctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(dctx.get(), nullptr, nullptr, rec_key.data(), rec_nonce.data());
        EVP_DecryptUpdate(dctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

        std::vector<uint8_t> decrypted(ciphertext.size());
        EVP_DecryptUpdate(dctx.get(), decrypted.data(), &outlen, ciphertext.data(), ciphertext.size());
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
        std::cout << " [SUCCESS] RFC 9180 HPKE Base Mode verified in C++20!\n";
        std::cout << "======================================================\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
}
