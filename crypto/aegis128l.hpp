#ifndef AEGIS128L_HPP
#define AEGIS128L_HPP

#include <cstdint>
#include <cstddef>

#ifdef __ARM_NEON
#include <arm_neon.h>
#elif defined(__x86_64__)
#include <immintrin.h>
#endif

namespace quicfuscate {
namespace crypto {

/**
 * AEGIS-128L Authenticated Encryption with Associated Data (AEAD)
 * 
 * AEGIS-128L ist optimiert für sowohl ARM- als auch x86-Systeme:
 * - ARM: Hardware-beschleunigt über ARMv8 Crypto Extensions (AES + PMULL)
 * - x86: Hardware-beschleunigt über AES-NI + AVX2
 * 
 * Hardware-Beschleunigung:
 * - ARM mit Crypto Extensions: AES-Instruktionen in NEON + PMULL
 * - x86 mit AES-NI/AVX2: Optimale Performance
 * - Software-Fallback für ältere Hardware
 * 
 * Empfohlene Verwendung:
 * - Primäre Wahl für ARM-Systeme mit Crypto Extensions
 * - Gute Wahl für x86-Systeme ohne VAES
 */
class AEGIS128L {
public:
    static constexpr size_t KEY_SIZE = 16;    // 128-bit key
    static constexpr size_t NONCE_SIZE = 16;  // 128-bit nonce
    static constexpr size_t TAG_SIZE = 16;    // 128-bit authentication tag
    static constexpr size_t BLOCK_SIZE = 16;  // 128-bit block size
    
    /**
     * Konstruktor - erkennt verfügbare Hardware-Features
     */
    AEGIS128L();
    
    /**
     * Verschlüsselt Daten mit AEGIS-128L
     * 
     * @param plaintext Zu verschlüsselnde Daten
     * @param plaintext_len Länge der Daten in Bytes
     * @param key 128-bit Schlüssel
     * @param nonce 128-bit Nonce (muss eindeutig pro Schlüssel sein)
     * @param associated_data Zusätzliche authentifizierte Daten (kann NULL sein)
     * @param ad_len Länge der zusätzlichen Daten
     * @param ciphertext Ausgabepuffer für verschlüsselte Daten (gleiche Größe wie plaintext)
     * @param tag Ausgabepuffer für 128-bit Authentifizierungs-Tag
     */
    void encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                uint8_t* ciphertext, uint8_t* tag);
    
    /**
     * Entschlüsselt und verifiziert Daten mit AEGIS-128L
     * 
     * @param ciphertext Verschlüsselte Daten
     * @param ciphertext_len Länge der verschlüsselten Daten
     * @param key 128-bit Schlüssel
     * @param nonce 128-bit Nonce
     * @param associated_data Zusätzliche authentifizierte Daten
     * @param ad_len Länge der zusätzlichen Daten
     * @param tag 128-bit Authentifizierungs-Tag zur Verifikation
     * @param plaintext Ausgabepuffer für entschlüsselte Daten
     * @return true wenn Entschlüsselung und Verifikation erfolgreich
     */
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, const uint8_t* nonce,
                const uint8_t* associated_data, size_t ad_len,
                const uint8_t* tag, uint8_t* plaintext);
    
    /**
     * Prüft, ob Hardware-Beschleunigung verfügbar ist
     * @return true wenn ARM Crypto Extensions oder x86 AES-NI verfügbar ist
     */
    bool is_hardware_accelerated() const;
    
private:
    bool has_arm_crypto_;  // ARM Crypto Extensions
    bool has_aesni_;       // x86 AES-NI
    bool has_avx2_;        // x86 AVX2
    bool has_pclmulqdq_;   // x86 PCLMULQDQ für GF-Multiplikation
    
#ifdef __ARM_NEON
    // ARM NEON + Crypto Extensions Implementierung
    void encrypt_arm_crypto(const uint8_t* plaintext, size_t plaintext_len,
                           const uint8_t* key, const uint8_t* nonce,
                           const uint8_t* associated_data, size_t ad_len,
                           uint8_t* ciphertext, uint8_t* tag);
    
    bool decrypt_arm_crypto(const uint8_t* ciphertext, size_t ciphertext_len,
                           const uint8_t* key, const uint8_t* nonce,
                           const uint8_t* associated_data, size_t ad_len,
                           const uint8_t* tag, uint8_t* plaintext);
    
    // ARM AEGIS-128L interne Funktionen
    void aegis_update_arm(uint8x16_t state[8], uint8x16_t msg0, uint8x16_t msg1);
    uint8x16_t aegis_encrypt_block_arm(uint8x16_t state[8], uint8x16_t plaintext);
#endif
    
#ifdef __x86_64__
    // x86 AES-NI + AVX2 Implementierung
    void encrypt_x86_aesni(const uint8_t* plaintext, size_t plaintext_len,
                          const uint8_t* key, const uint8_t* nonce,
                          const uint8_t* associated_data, size_t ad_len,
                          uint8_t* ciphertext, uint8_t* tag);
    
    bool decrypt_x86_aesni(const uint8_t* ciphertext, size_t ciphertext_len,
                          const uint8_t* key, const uint8_t* nonce,
                          const uint8_t* associated_data, size_t ad_len,
                          const uint8_t* tag, uint8_t* plaintext);
    
    // x86 AEGIS-128L interne Funktionen
    void aegis_update_x86(__m128i state[8], __m128i msg0, __m128i msg1);
    __m128i aegis_encrypt_block_x86(__m128i state[8], __m128i plaintext);
#endif
    
    // Software-Fallback (alle Architekturen)
    void encrypt_software(const uint8_t* plaintext, size_t plaintext_len,
                         const uint8_t* key, const uint8_t* nonce,
                         const uint8_t* associated_data, size_t ad_len,
                         uint8_t* ciphertext, uint8_t* tag);
    
    bool decrypt_software(const uint8_t* ciphertext, size_t ciphertext_len,
                         const uint8_t* key, const uint8_t* nonce,
                         const uint8_t* associated_data, size_t ad_len,
                         const uint8_t* tag, uint8_t* plaintext);
};

} // namespace crypto
} // namespace quicfuscate

#endif // AEGIS128L_HPP