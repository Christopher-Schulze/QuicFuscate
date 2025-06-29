#include "cipher_suite_selector.hpp"
#include <stdexcept>

namespace quicfuscate {
namespace crypto {

CipherSuiteSelector::CipherSuiteSelector() 
    : detector_(), auto_select_(true) {
    initialize_cipher_suites();
    current_suite_ = select_best_cipher_suite();
}

void CipherSuiteSelector::initialize_cipher_suites() {
    // Initialisiere alle verfügbaren Cipher Suites
    aegis128x_ = std::make_unique<AEGIS128X>();
    aegis128l_ = std::make_unique<AEGIS128L>();
    morus1280_ = std::make_unique<MORUS1280>();
}

CipherSuite CipherSuiteSelector::select_best_cipher_suite() const {
    // Implementierung der Auswahllogik wie vom User spezifiziert:
    // if (sodium_runtime_has_vaes())           // x86+VAES 
    //     use_aegis128x(); 
    // else if (sodium_runtime_has_aesni() || 
    //          sodium_runtime_has_armcrypto()) // ARMv8-A Crypto Extensions oder x86 AES-NI 
    //     use_aegis128l(); 
    // else 
    //     use_morus1280128();
    
    if (has_vaes_support()) {
        return CipherSuite::AEGIS_128X;
    } else if (has_aes_support()) {
        return CipherSuite::AEGIS_128L;
    } else {
        return CipherSuite::MORUS_1280_128;
    }
}

bool CipherSuiteSelector::has_vaes_support() const {
    // VAES benötigt AVX-512F und AVX-512BW (für VAES512)
    return detector_.has_feature(simd::CpuFeature::AVX512F) &&
           detector_.has_feature(simd::CpuFeature::AVX512BW);
}

bool CipherSuiteSelector::has_aes_support() const {
    // AES-NI auf x86 oder ARM Crypto Extensions
    return detector_.has_feature(simd::CpuFeature::AESNI) ||
           detector_.has_feature(simd::CpuFeature::ARM_CRYPTO);
}

void CipherSuiteSelector::set_cipher_suite(CipherSuite suite) {
    current_suite_ = suite;
    auto_select_ = false;
}

void CipherSuiteSelector::encrypt(const uint8_t* plaintext, size_t plaintext_len,
                                 const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* associated_data, size_t ad_len,
                                 uint8_t* ciphertext, uint8_t* tag) {
    
    // Automatische Auswahl wenn aktiviert
    if (auto_select_) {
        current_suite_ = select_best_cipher_suite();
    }
    
    switch (current_suite_) {
        case CipherSuite::AEGIS_128X:
            aegis128x_->encrypt(plaintext, plaintext_len, key, nonce,
                              associated_data, ad_len, ciphertext, tag);
            break;
            
        case CipherSuite::AEGIS_128L:
            aegis128l_->encrypt(plaintext, plaintext_len, key, nonce,
                              associated_data, ad_len, ciphertext, tag);
            break;
            
        case CipherSuite::MORUS_1280_128:
            morus1280_->encrypt(plaintext, plaintext_len, key, nonce,
                          associated_data, ad_len, ciphertext, tag);
            break;
            
        default:
            throw std::runtime_error("Unbekannte Cipher Suite");
    }
}

bool CipherSuiteSelector::decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                                 const uint8_t* key, const uint8_t* nonce,
                                 const uint8_t* associated_data, size_t ad_len,
                                 const uint8_t* tag, uint8_t* plaintext) {
    
    // Automatische Auswahl wenn aktiviert
    if (auto_select_) {
        current_suite_ = select_best_cipher_suite();
    }
    
    switch (current_suite_) {
        case CipherSuite::AEGIS_128X:
            return aegis128x_->decrypt(ciphertext, ciphertext_len, key, nonce,
                                     associated_data, ad_len, tag, plaintext);
            
        case CipherSuite::AEGIS_128L:
            return aegis128l_->decrypt(ciphertext, ciphertext_len, key, nonce,
                                     associated_data, ad_len, tag, plaintext);
            
        case CipherSuite::MORUS_1280_128:
            return morus1280_->decrypt(ciphertext, ciphertext_len, key, nonce,
                                 associated_data, ad_len, tag, plaintext);
            
        default:
            throw std::runtime_error("Unbekannte Cipher Suite");
    }
}

const char* CipherSuiteSelector::get_cipher_suite_name() const {
    switch (current_suite_) {
        case CipherSuite::AEGIS_128X:
            return "AEGIS-128X";
        case CipherSuite::AEGIS_128L:
            return "AEGIS-128L";
        case CipherSuite::MORUS_1280_128:
            return "MORUS-1280-128";
        default:
            return "Unknown";
    }
}

bool CipherSuiteSelector::is_hardware_accelerated() const {
    switch (current_suite_) {
        case CipherSuite::AEGIS_128X:
            return has_vaes_support();
        case CipherSuite::AEGIS_128L:
            return has_aes_support();
        case CipherSuite::MORUS_1280_128:
            return false; // MORUS ist immer Software-basiert
        default:
            return false;
    }
}

} // namespace crypto
} // namespace quicfuscate