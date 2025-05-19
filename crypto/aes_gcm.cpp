#include "aes_gcm.hpp"
#include <openssl/evp.h>
#include <stdexcept>

namespace quicsand {

AesGcm::AesGcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
    : key_(key), iv_(iv) {
    if (key_.size() != 16) throw std::runtime_error("Key must be 16 bytes for AES-128-GCM");
    if (iv_.size() != 12) throw std::runtime_error("IV must be 12 bytes for AES-128-GCM");
}

AesGcm::~AesGcm() {
    // Cleanup if necessary
}

std::vector<uint8_t> AesGcm::encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& aad,
                                     std::vector<uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    int len;
    std::vector<uint8_t> ciphertext(plaintext.size());

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr))
        throw std::runtime_error("EncryptInit failed");
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv_.data());

    if (!aad.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
            throw std::runtime_error("AAD update failed");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
        throw std::runtime_error("EncryptUpdate failed");
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        throw std::runtime_error("EncryptFinal failed");
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()))
        throw std::runtime_error("GetTag failed");

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<uint8_t> AesGcm::decrypt(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& aad,
                                     const std::vector<uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    int len;
    std::vector<uint8_t> plaintext(ciphertext.size());

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr))
        throw std::runtime_error("DecryptInit failed");
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv_.data());

    if (!aad.empty()) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
            throw std::runtime_error("AAD update failed");
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
        throw std::runtime_error("DecryptUpdate failed");
    int plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())))
        throw std::runtime_error("SetTag failed");

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        throw std::runtime_error("DecryptFinal failed: authentication tag mismatch");
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

} // namespace quicsand
