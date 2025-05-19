#ifndef SIMD_OPTIMIZATIONS_HPP
#define SIMD_OPTIMIZATIONS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>
#include <array>

// SIMD-spezifische Header
#ifdef __ARM_NEON
#include <arm_neon.h>  // ARM NEON SIMD-Instruktionen
#else
#include <immintrin.h>  // AVX, AVX2, AVX-512
#include <wmmintrin.h>  // AES-NI
#endif

namespace quicsand {
namespace simd {

// CPU-Funktionen Erkennung
enum class SIMDSupport {
    NONE = 0,
#ifdef __ARM_NEON
    // ARM-spezifische Features
    NEON = 1,
    ASIMD = 2,     // Advanced SIMD (ARMv8)
    SVE = 4,       // Scalable Vector Extension (ARMv8.2+)
    DOTPROD = 8,   // Dot Product (ARMv8.2+)
    CRYPTO = 16,   // AES/SHA Krypto-Erweiterungen
    CRC = 32       // CRC32/CRC32C
#else
    // x86/x64-spezifische Features
    SSE = 1,
    SSE2 = 2,
    SSE3 = 4,
    SSSE3 = 8,
    SSE41 = 16,
    SSE42 = 32,
    AVX = 64,
    AVX2 = 128,
    AVX512F = 256,
    AESNI = 512,
    PCLMULQDQ = 1024
#endif
};

/**
 * @brief Erkennt die unterstützten SIMD-Befehle der CPU
 * @return Kombination von SIMDSupport-Flags
 */
uint32_t detect_cpu_features();

/**
 * @brief Prüft, ob eine bestimmte SIMD-Funktion verfügbar ist
 * @param feature Die zu prüfende Funktion
 * @return true wenn die Funktion unterstützt wird, sonst false
 */
bool is_feature_supported(SIMDSupport feature);

/**
 * @brief Konvertiert die erkannten Features in einen String zur Ausgabe
 * @param features Bit-Maske der unterstützten Features
 * @return String-Repräsentation der Features
 */
std::string features_to_string(uint32_t features);

// AES-128-GCM-SIMD-Optimierungen

/**
 * @brief AES-128-GCM-Verschlüsselung mit AESNI-Beschleunigung
 * 
 * @param plaintext Klartextdaten
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param iv Initialisierungsvektor (12 Bytes empfohlen für GCM)
 * @param aad Additional Authenticated Data (optional)
 * @param tag_len Länge des Auth-Tags in Bytes (16 für volle Sicherheit)
 * @return std::vector<uint8_t> Verschlüsselte Daten mit angehängtem Auth-Tag
 */
std::vector<uint8_t> aes_128_gcm_encrypt_aesni(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16);

/**
 * @brief AES-128-GCM-Entschlüsselung mit AESNI-Beschleunigung
 * 
 * @param ciphertext Verschlüsselte Daten mit angehängtem Auth-Tag
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param iv Initialisierungsvektor (muss derselbe wie bei der Verschlüsselung sein)
 * @param aad Additional Authenticated Data (optional, muss dieselben sein wie bei der Verschlüsselung)
 * @param tag_len Länge des Auth-Tags in Bytes (muss dieselbe sein wie bei der Verschlüsselung)
 * @return std::vector<uint8_t> Entschlüsselte Daten oder leerer Vektor bei Authentication-Failure
 */
std::vector<uint8_t> aes_128_gcm_decrypt_aesni(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16);

/**
 * @brief AES-128-GCM-Verschlüsselung mit AESNI- und AVX2-Beschleunigung
 * 
 * Diese Version nutzt AVX2 für höhere Parallelisierung der AES-Operationen.
 * 
 * @param plaintext Klartextdaten
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param iv Initialisierungsvektor (12 Bytes empfohlen für GCM)
 * @param aad Additional Authenticated Data (optional)
 * @param tag_len Länge des Auth-Tags in Bytes (16 für volle Sicherheit)
 * @return std::vector<uint8_t> Verschlüsselte Daten mit angehängtem Auth-Tag
 */
std::vector<uint8_t> aes_128_gcm_encrypt_avx2(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16);

/**
 * @brief AES-128-GCM-Entschlüsselung mit AESNI- und AVX2-Beschleunigung
 * 
 * Diese Version nutzt AVX2 für höhere Parallelisierung der AES-Operationen.
 * 
 * @param ciphertext Verschlüsselte Daten mit angehängtem Auth-Tag
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param iv Initialisierungsvektor (muss derselbe wie bei der Verschlüsselung sein)
 * @param aad Additional Authenticated Data (optional, muss dieselben sein wie bei der Verschlüsselung)
 * @param tag_len Länge des Auth-Tags in Bytes (muss dieselbe sein wie bei der Verschlüsselung)
 * @return std::vector<uint8_t> Entschlüsselte Daten oder leerer Vektor bei Authentication-Failure
 */
std::vector<uint8_t> aes_128_gcm_decrypt_avx2(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad = {},
    size_t tag_len = 16);

// Ascon-128a-SIMD-Optimierungen

/**
 * @brief Ascon-128a-Verschlüsselung mit SIMD-Optimierung
 * 
 * @param plaintext Klartextdaten
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param nonce 128-bit Nonce (16 Bytes)
 * @param associated_data Zusätzliche authentifizierte Daten (optional)
 * @return std::vector<uint8_t> Verschlüsselte Daten mit angehängtem Auth-Tag
 */
std::vector<uint8_t> ascon_128a_encrypt_simd(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, 16>& key,
    const std::array<uint8_t, 16>& nonce,
    const std::vector<uint8_t>& associated_data = {});

/**
 * @brief Ascon-128a-Entschlüsselung mit SIMD-Optimierung
 * 
 * @param ciphertext Verschlüsselte Daten mit angehängtem Auth-Tag
 * @param key 128-bit Schlüssel (16 Bytes)
 * @param nonce 128-bit Nonce (16 Bytes)
 * @param associated_data Zusätzliche authentifizierte Daten (optional)
 * @return std::vector<uint8_t> Entschlüsselte Daten oder leerer Vektor bei Authentication-Failure
 */
std::vector<uint8_t> ascon_128a_decrypt_simd(
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& key,
    const std::array<uint8_t, 16>& nonce,
    const std::vector<uint8_t>& associated_data = {});

// Tetrys-FEC-SIMD-Optimierungen

/**
 * @brief Galois-Feld-Multiplikation mit AVX2-Beschleunigung
 * 
 * @param a Erster Operand
 * @param b Zweiter Operand
 * @param elements Anzahl der zu multiplizierenden Elemente
 * @param result Array für das Ergebnis (muss mindestens elements groß sein)
 */
void gf_multiply_avx2(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);

/**
 * @brief Galois-Feld-Addition mit AVX2-Beschleunigung (im Grunde ein XOR)
 * 
 * @param a Erster Operand
 * @param b Zweiter Operand
 * @param elements Anzahl der zu addierenden Elemente
 * @param result Array für das Ergebnis (muss mindestens elements groß sein)
 */
void gf_add_avx2(const uint8_t* a, const uint8_t* b, size_t elements, uint8_t* result);

/**
 * @brief Tetrys-FEC-Encoding mit AVX2-Beschleunigung
 * 
 * @param source_packets Array von Quellpaketen
 * @param packet_size Größe jedes Pakets in Bytes
 * @param redundancy_ratio Verhältnis von Redundanzpaketen zu Quellpaketen
 * @return std::vector<std::vector<uint8_t>> Redundanzpakete
 */
std::vector<std::vector<uint8_t>> tetrys_encode_avx2(
    const std::vector<std::vector<uint8_t>>& source_packets,
    size_t packet_size,
    double redundancy_ratio);

/**
 * @brief Tetrys-FEC-Decoding mit AVX2-Beschleunigung
 * 
 * @param received_packets Array von empfangenen Paketen (Quell- und Redundanzpakete)
 * @param packet_indices Array von Paket-Indizes (zur Identifikation der Pakete)
 * @param packet_size Größe jedes Pakets in Bytes
 * @param total_packets Gesamtzahl der erwarteten Pakete
 * @return std::vector<std::vector<uint8_t>> Rekonstruierte Pakete
 */
std::vector<std::vector<uint8_t>> tetrys_decode_avx2(
    const std::vector<std::vector<uint8_t>>& received_packets,
    const std::vector<uint16_t>& packet_indices,
    size_t packet_size,
    size_t total_packets);

// Hilfsklasse für automatische Auswahl der optimalen SIMD-Implementierung
class SIMDDispatcher {
public:
    SIMDDispatcher();
    
    // AES-128-GCM-Auswahl
    std::vector<uint8_t> aes_128_gcm_encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 16>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& aad = {},
        size_t tag_len = 16);
        
    std::vector<uint8_t> aes_128_gcm_decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::array<uint8_t, 16>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& aad = {},
        size_t tag_len = 16);
        
    // Ascon-128a-Auswahl
    std::vector<uint8_t> ascon_128a_encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& nonce,
        const std::vector<uint8_t>& associated_data = {});
        
    std::vector<uint8_t> ascon_128a_decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::array<uint8_t, 16>& key,
        const std::array<uint8_t, 16>& nonce,
        const std::vector<uint8_t>& associated_data = {});
        
    // Tetrys-FEC-Auswahl
    std::vector<std::vector<uint8_t>> tetrys_encode(
        const std::vector<std::vector<uint8_t>>& source_packets,
        size_t packet_size,
        double redundancy_ratio);
        
    std::vector<std::vector<uint8_t>> tetrys_decode(
        const std::vector<std::vector<uint8_t>>& received_packets,
        const std::vector<uint16_t>& packet_indices,
        size_t packet_size,
        size_t total_packets);
        
private:
    uint32_t supported_features_;
};

} // namespace simd
} // namespace quicsand

#endif // SIMD_OPTIMIZATIONS_HPP
