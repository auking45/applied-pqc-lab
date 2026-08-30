// =============================================================================
// Applied PQC Lab - NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA in C++20
// Native OpenSSL 3.5+ EVP Encap/Decap & DigestSign/DigestVerify
// =============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <openssl/evp.h>

struct EvpPkeyDeleter
{
    void operator()(EVP_PKEY *p) const
    {
        if (p)
            EVP_PKEY_free(p);
    }
};
struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX *p) const
    {
        if (p)
            EVP_PKEY_CTX_free(p);
    }
};
struct EvpMdCtxDeleter
{
    void operator()(EVP_MD_CTX *p) const
    {
        if (p)
            EVP_MD_CTX_free(p);
    }
};

using ScopedPKEY = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using ScopedPKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using ScopedMD_CTX = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

ScopedPKEY generate_pqc_keypair(const std::string &alg_name)
{
    ScopedPKEY_CTX kctx(EVP_PKEY_CTX_new_from_name(nullptr, alg_name.c_str(), nullptr));
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0)
    {
        throw std::runtime_error("EVP_PKEY_keygen_init failed for " + alg_name);
    }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &pkey) <= 0)
    {
        throw std::runtime_error("EVP_PKEY_keygen failed for " + alg_name);
    }
    return ScopedPKEY(pkey);
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> mlkem_encapsulate(EVP_PKEY *pkey)
{
    ScopedPKEY_CTX ectx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ectx || EVP_PKEY_encapsulate_init(ectx.get(), nullptr) <= 0)
        throw std::runtime_error("Encap init failed");
    size_t ct_len = 0, secret_len = 0;
    EVP_PKEY_encapsulate(ectx.get(), nullptr, &ct_len, nullptr, &secret_len);
    std::vector<uint8_t> ct(ct_len), secret(secret_len);
    if (EVP_PKEY_encapsulate(ectx.get(), ct.data(), &ct_len, secret.data(), &secret_len) <= 0)
    {
        throw std::runtime_error("Encap execution failed");
    }
    return {ct, secret};
}

std::vector<uint8_t> mlkem_decapsulate(EVP_PKEY *pkey, const std::vector<uint8_t> &ct)
{
    ScopedPKEY_CTX dctx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!dctx || EVP_PKEY_decapsulate_init(dctx.get(), nullptr) <= 0)
        throw std::runtime_error("Decap init failed");
    size_t secret_len = 0;
    EVP_PKEY_decapsulate(dctx.get(), nullptr, &secret_len, ct.data(), ct.size());
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_decapsulate(dctx.get(), secret.data(), &secret_len, ct.data(), ct.size()) <= 0)
    {
        throw std::runtime_error("Decap execution failed");
    }
    return secret;
}

std::vector<uint8_t> mldsa_sign(EVP_PKEY *pkey, const std::string &message)
{
    ScopedMD_CTX mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, pkey) <= 0)
    {
        throw std::runtime_error("DigestSignInit failed");
    }
    size_t sig_len = 0;
    EVP_DigestSign(mctx.get(), nullptr, &sig_len, reinterpret_cast<const uint8_t *>(message.data()), message.size());
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(mctx.get(), sig.data(), &sig_len, reinterpret_cast<const uint8_t *>(message.data()), message.size()) <= 0)
    {
        throw std::runtime_error("DigestSign execution failed");
    }
    return sig;
}

bool mldsa_verify(EVP_PKEY *pkey, const std::string &message, const std::vector<uint8_t> &sig)
{
    ScopedMD_CTX vmctx(EVP_MD_CTX_new());
    if (!vmctx || EVP_DigestVerifyInit(vmctx.get(), nullptr, nullptr, nullptr, pkey) <= 0)
    {
        return false;
    }
    int vret = EVP_DigestVerify(vmctx.get(), sig.data(), sig.size(), reinterpret_cast<const uint8_t *>(message.data()), message.size());
    return vret > 0;
}

int main()
{
    std::cout << "======================================================\n";
    std::cout << " [Applied PQC Lab] NIST PQC Primitives in C++20\n";
    std::cout << " FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 (OpenSSL 3.5)\n";
    std::cout << "======================================================\n";

    try
    {
        // 1. ML-KEM-768
        std::cout << "\n--- [Part 1] FIPS 203 ML-KEM-768 Key Encapsulation ---\n";
        auto rec_kem = generate_pqc_keypair("ML-KEM-768");
        auto [ct, sender_secret] = mlkem_encapsulate(rec_kem.get());
        std::cout << "[+] Sender Encap: ct=" << ct.size() << "B, secret=" << sender_secret.size() << "B\n";

        auto receiver_secret = mlkem_decapsulate(rec_kem.get(), ct);
        if (receiver_secret != sender_secret)
            throw std::runtime_error("KEM Secret mismatch!");
        std::cout << "[+] Receiver Decap: [PASS] Derived matching 32B shared secret!\n";

        // 2. ML-DSA-65
        std::cout << "\n--- [Part 2] FIPS 204 ML-DSA-65 Digital Signature ---\n";
        auto signer_dsa = generate_pqc_keypair("ML-DSA-65");
        std::string message = "Critical Legal Contract signed with Quantum-Resistant FIPS 204 ML-DSA.";

        auto signature = mldsa_sign(signer_dsa.get(), message);
        std::cout << "[+] ML-DSA-65 Signature generated: size = " << signature.size() << " bytes (Expect 3309)\n";

        bool is_valid = mldsa_verify(signer_dsa.get(), message, signature);
        if (!is_valid)
            throw std::runtime_error("ML-DSA Signature verification failed!");
        std::cout << "    [PASS] Signature verified successfully!\n";

        std::cout << "======================================================\n";
        std::cout << " [SUCCESS] FIPS 203 ML-KEM & FIPS 204 ML-DSA verified in C++20!\n";
        std::cout << "======================================================\n";
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
}
