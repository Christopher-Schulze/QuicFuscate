#ifndef AEGIS128X_HPP
#define AEGIS128X_HPP

#include <cstdint>
#include <cstddef>

#ifdef __x86_64__
#include <immintrin.h>
#endif

namespace quicfuscate {
namespace crypto {

/**
 * AEGIS-128X Authenticated Encryption with Associated Data (AEAD)
 * 
 * AEGIS-128X ist optimiert für x86-Systeme mit VAES (Vector AES) Unterstützung.
 * Auf ARM-Systemen wird ein Software-Fallback verwendet, da ARM kein 512-bit VAES hat.
 * 
 * Hardware-Beschleunigung:
 * - x86 mit VAES (AVX-512): Superschnelle 512-Bit-Blocks
 * - x86 mit AES-NI: Standard AES-Beschleunigung
 * - ARM: Software-Fallback (kein Hardware-Vorteil)
 * 
 * Empfohlene Verwendung:
 * - Nur auf x86-Systemen mit VAES-Unterstützung
 * - Für ARM-Systeme sollte AEGIS-128L verwendet werden
 */
class AEGIS128X {
public:
    static constexpr size_t KEY_SIZE = 16;    // 128-bit key
    static constexpr size_t NONCE_SIZE = 16;  // 128-bit nonce
    static constexpr size_t TAG_SIZE = 16;    // 128-bit authentication tag
    static constexpr size_t BLOCK_SIZE = 32;  // 256-bit block size
    
    /**
     * Konstruktor - erkennt verfügbare Hardware-Features
     */
    AEGIS128X();
    
    /**
     * Verschlüsselt Daten mit AEGIS-128X
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
     * Entschlüsselt und verifiziert Daten mit AEGIS-128X
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
     * @return true wenn VAES oder AES-NI verfügbar ist
     */
    bool is_hardware_accelerated() const;
    
private:
    bool has_vaes_;       // VAES (Vector AES) Unterstützung
    bool has_aesni_;      // AES-NI Unterstützung
    bool has_arm_crypto_; // ARM Crypto Extensions
    
#ifdef __x86_64__
    // VAES-optimierte Implementierung (x86 mit AVX-512 + VAES)
    void encrypt_vaes(const uint8_t* plaintext, size_t plaintext_len,
                     const uint8_t* key, const uint8_t* nonce,
                     const uint8_t* associated_data, size_t ad_len,
                     uint8_t* ciphertext, uint8_t* tag);
    
    bool decrypt_vaes(const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* key, const uint8_t* nonce,
                     const uint8_t* associated_data, size_t ad_len,
                     const uint8_t* tag, uint8_t* plaintext);
    
    // AES-NI Fallback (x86 ohne VAES)
    void encrypt_aesni(const uint8_t* plaintext, size_t plaintext_len,
                      const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* associated_data, size_t ad_len,
                      uint8_t* ciphertext, uint8_t* tag);
    
    bool decrypt_aesni(const uint8_t* ciphertext, size_t ciphertext_len,
                      const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* associated_data, size_t ad_len,
                      const uint8_t* tag, uint8_t* plaintext);
    
    // AEGIS-128X interne Funktionen
    void aegis_update_vaes(__m128i state[8], __m128i msg0, __m128i msg1);
    __m128i aegis_encrypt_block_vaes(__m128i state[8], __m128i plaintext);
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

#endif // AEGIS128X_HPP
