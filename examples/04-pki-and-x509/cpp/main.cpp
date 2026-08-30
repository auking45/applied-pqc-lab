// =============================================================================
// Applied PQC Lab - PQC X.509 PKI End-to-End Encryption in C++20
// (ML-DSA-65 Root CA + ML-KEM-768 Leaf Cert + AES-256-GCM)
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

struct X509Deleter { void operator()(X509* p) const { if (p) X509_free(p); } };
struct X509StoreDeleter { void operator()(X509_STORE* p) const { if (p) X509_STORE_free(p); } };
struct X509StoreCtxDeleter { void operator()(X509_STORE_CTX* p) const { if (p) X509_STORE_CTX_free(p); } };
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); } };

using ScopedX509 = std::unique_ptr<X509, X509Deleter>;
using ScopedX509Store = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using ScopedX509StoreCtx = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;
using ScopedPKEY = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using ScopedPKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> aes_gcm_encrypt(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
    const std::string& plaintext, const std::string& aad)
{
    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

    int outlen = 0;
    if (!aad.empty()) {
        EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
    }
    std::vector<uint8_t> ct(plaintext.size() + 16);
    EVP_EncryptUpdate(ctx.get(), ct.data(), &outlen, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    int total_len = outlen;
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx.get(), ct.data() + total_len, &final_len);
    total_len += final_len;
    ct.resize(total_len);

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    return {ct, tag};
}

std::string aes_gcm_decrypt(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ct, const std::vector<uint8_t>& tag, const std::string& aad)
{
    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

    int outlen = 0;
    if (!aad.empty()) {
        EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
    }
    std::vector<uint8_t> pt(ct.size() + 16);
    EVP_DecryptUpdate(ctx.get(), pt.data(), &outlen, ct.data(), ct.size());
    int total_len = outlen;
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag.data()));
    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx.get(), pt.data() + total_len, &final_len);
    if (ret <= 0) throw std::runtime_error("AES-GCM Authentication Failed!");
    total_len += final_len;
    return std::string(reinterpret_cast<char*>(pt.data()), total_len);
}

int main(int argc, char* argv[]) {
    std::string pki_dir = (argc > 1) ? argv[1] : "/tmp/pqc_pki_out";

    std::cout << "======================================================\n";
    std::cout << " [Applied PQC Lab] PQC X.509 PKI End-to-End in C++20\n";
    std::cout << " (ML-DSA-65 Root CA + ML-KEM-768 Leaf + AES-256-GCM)\n";
    std::cout << "======================================================\n";

    try {
        // 1. Load Root CA and Leaf Certs
        std::cout << "[+] Step 1: Loading Root CA (ML-DSA-65) and Receiver Cert (ML-KEM-768)...\n";
        FILE* ca_f = fopen((pki_dir + "/ca.crt").c_str(), "r");
        if (!ca_f) throw std::runtime_error("Failed to open ca.crt");
        ScopedX509 ca_cert(PEM_read_X509(ca_f, nullptr, nullptr, nullptr));
        fclose(ca_f);

        FILE* leaf_f = fopen((pki_dir + "/receiver.crt").c_str(), "r");
        if (!leaf_f) throw std::runtime_error("Failed to open receiver.crt");
        ScopedX509 leaf_cert(PEM_read_X509(leaf_f, nullptr, nullptr, nullptr));
        fclose(leaf_f);

        // 2. Sender verifies Certificate Chain
        std::cout << "[+] Step 2: Sender verifying Receiver X.509 Certificate Chain...\n";
        ScopedX509Store store(X509_STORE_new());
        X509_STORE_add_cert(store.get(), ca_cert.get());
        ScopedX509StoreCtx vctx(X509_STORE_CTX_new());
        X509_STORE_CTX_init(vctx.get(), store.get(), leaf_cert.get(), nullptr);
        int vret = X509_verify_cert(vctx.get());
        if (vret != 1) throw std::runtime_error("Certificate verification failed!");
        std::cout << "    [PASS] X.509 Certificate Chain signed by ML-DSA-65 Root CA verified!\n";

        // 3. Sender extracts ML-KEM-768 public key from verified cert and encapsulates
        std::cout << "[+] Step 3: Extracting ML-KEM-768 public key from verified certificate...\n";
        EVP_PKEY* extracted_pkey = X509_get0_pubkey(leaf_cert.get());
        if (!extracted_pkey) throw std::runtime_error("Failed to extract public key");

        std::cout << "[+] Step 4: Sender executing ML-KEM-768 Encap(pkR)...\n";
        ScopedPKEY_CTX ectx(EVP_PKEY_CTX_new(extracted_pkey, nullptr));
        EVP_PKEY_encapsulate_init(ectx.get(), nullptr);
        size_t ct_len = 0, secret_len = 0;
        EVP_PKEY_encapsulate(ectx.get(), nullptr, &ct_len, nullptr, &secret_len);
        std::vector<uint8_t> ct(ct_len), sender_secret(secret_len);
        EVP_PKEY_encapsulate(ectx.get(), ct.data(), &ct_len, sender_secret.data(), &secret_len);
        std::cout << "    Encapsulated Ciphertext size: " << ct.size() << " bytes (Expect 1088)\n";
        std::cout << "    Sender Shared Secret size   : " << sender_secret.size() << " bytes (32 bytes)\n";

        // 4. Sender encrypts payload with AES-256-GCM
        std::cout << "[+] Step 5: Sender encrypting confidential payload with AES-256-GCM...\n";
        std::string plaintext = "Authenticated End-to-End PQC Message delivered via X.509 PKI.";
        std::vector<uint8_t> nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        std::string aad = "PQC-PKI-v1-Auth";
        auto [ct_payload, tag] = aes_gcm_encrypt(sender_secret, nonce, plaintext, aad);

        // 5. Receiver loads private key and performs Decap
        std::cout << "[+] Step 6: Receiver decapsulating shared secret with private key...\n";
        FILE* key_f = fopen((pki_dir + "/receiver.key").c_str(), "r");
        if (!key_f) throw std::runtime_error("Failed to open receiver.key");
        ScopedPKEY rec_priv(PEM_read_PrivateKey(key_f, nullptr, nullptr, nullptr));
        fclose(key_f);

        ScopedPKEY_CTX dctx(EVP_PKEY_CTX_new(rec_priv.get(), nullptr));
        EVP_PKEY_decapsulate_init(dctx.get(), nullptr);
        std::vector<uint8_t> receiver_secret(secret_len);
        EVP_PKEY_decapsulate(dctx.get(), receiver_secret.data(), &secret_len, ct.data(), ct.size());

        if (sender_secret != receiver_secret) throw std::runtime_error("Decapsulated secret mismatch!");
        std::cout << "    [PASS] Decapsulated shared secret matches sender secret 100%!\n";

        // 6. Receiver decrypts payload
        std::cout << "[+] Step 7: Receiver decrypting payload and verifying AAD...\n";
        std::string decrypted = aes_gcm_decrypt(receiver_secret, nonce, ct_payload, tag, aad);
        assert(decrypted == plaintext);

        std::cout << "======================================================\n";
        std::cout << " [PASS] Decrypted message: \"" << decrypted << "\"\n";
        std::cout << " [SUCCESS] C++20 PQC X.509 PKI End-to-End verified!\n";
        std::cout << "======================================================\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
}
