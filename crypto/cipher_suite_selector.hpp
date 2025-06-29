#pragma once

#include "aegis128x.hpp"
#include "aegis128l.hpp"
#include "morus1280.hpp"
#include "../optimize/unified_optimizations.hpp"
#include <memory>
#include <cstdint>

namespace quicfuscate {
namespace crypto {

enum class CipherSuite {
    // AEGIS-128X Varianten (x86-64 optimiert)
    AEGIS_128X_VAES512,  // VAES-beschleunigt mit AVX-512
    AEGIS_128X_AESNI,    // AES-NI beschleunigt
    
    // AEGIS-128L Varianten (Multi-Architektur)
    AEGIS_128L_NEON,     // ARM NEON Crypto Extensions
    AEGIS_128L_AESNI,    // x86-64 AES-NI beschleunigt
    
    // Software-Fallback für alle Architekturen
    MORUS_1280_128       // Efficient AEAD cipher for hardware without AES acceleration
};

class CipherSuiteSelector {
public:
    CipherSuiteSelector();
    
    // Automatische Auswahl der besten verfügbaren Cipher Suite
    CipherSuite select_best_cipher_suite() const;
    
    // Manuelle Auswahl einer spezifischen Cipher Suite
    void set_cipher_suite(CipherSuite suite);
    
    // AEAD Verschlüsselung mit automatischer Cipher Suite Auswahl
    void encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                uint8_t* ciphertext, uint8_t* tag);
    
    // AEAD Entschlüsselung mit automatischer Cipher Suite Auswahl
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                const uint8_t* tag, uint8_t* plaintext);
    
    // Informationen über die aktuelle Cipher Suite
    CipherSuite get_current_cipher_suite() const { return current_suite_; }
    const char* get_cipher_suite_name() const;
    bool is_hardware_accelerated() const;
    
private:
    simd::FeatureDetector detector_;
    CipherSuite current_suite_;
    bool auto_select_;
    
    // Cipher Suite Implementierungen
    std::unique_ptr<AEGIS128X> aegis128x_;
    std::unique_ptr<AEGIS128L> aegis128l_;
    std::unique_ptr<MORUS1280> morus1280_;
    
    // Hilfsfunktionen
    void initialize_cipher_suites();
    bool has_vaes_support() const;
    bool has_aes_support() const;
};

} // namespace crypto
} // namespace quicfuscate