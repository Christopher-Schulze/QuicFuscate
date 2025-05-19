#ifndef AES128GCM_OPTIMIZED_HPP
#define AES128GCM_OPTIMIZED_HPP

#include <vector>
#include <array>
#include <cstdint>
#include <memory>

namespace quicsand::crypto {

/**
 * @brief SIMD-optimierte AES-128-GCM Implementierung
 * 
 * Diese Klasse bietet eine optimierte Implementierung von AES-128-GCM mit direkter
 * SIMD-Unterstützung für ARM-Prozessoren (Apple M1/M2). Sie nutzt die ARM Crypto
 * Extensions für maximale Leistung.
 * 
 * Die Klasse bietet eine OpenSSL-kompatible Schnittstelle, nutzt jedoch intern
 * optimierte SIMD-Funktionen für die Verschlüsselung und Entschlüsselung.
 */
class Aes128GcmOptimized {
public:
    /**
     * @brief Erstellt eine neue AES-128-GCM Instanz mit gegebenem Schlüssel und IV
     * @param key 16-Byte AES-Schlüssel (128 Bit)
     * @param iv Initialisierungsvektor (empfohlen: 12 Bytes für GCM)
     */
    Aes128GcmOptimized(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    
    /**
     * @brief Erstellt eine neue AES-128-GCM Instanz mit gegebenem Schlüssel und IV
     * @param key 16-Byte AES-Schlüssel (128 Bit)
     * @param iv Initialisierungsvektor (empfohlen: 12 Bytes für GCM)
     */
    Aes128GcmOptimized(const std::array<uint8_t, 16>& key, const std::vector<uint8_t>& iv);
    
    /**
     * @brief Destruktor
     */
    ~Aes128GcmOptimized();
    
    /**
     * @brief Verschlüsselt Daten mit AES-128-GCM
     * @param plaintext Klartext-Daten
     * @param aad Zusätzliche authentifizierte Daten (optional)
     * @return Verschlüsselte Daten mit angehängtem Authentifizierungs-Tag (16 Bytes)
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                const std::vector<uint8_t>& aad = {});
    
    /**
     * @brief Entschlüsselt Daten mit AES-128-GCM
     * @param ciphertext Verschlüsselte Daten
     * @param aad Zusätzliche authentifizierte Daten (müssen gleich sein wie bei der Verschlüsselung)
     * @param tag Authentifizierungs-Tag (16 Bytes)
     * @return Entschlüsselte Daten oder leerer Vektor bei Authentifizierungsfehler
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                const std::vector<uint8_t>& aad = {},
                                const std::vector<uint8_t>& tag = {});
    
    /**
     * @brief Zero-Copy-optimierte Verschlüsselung
     * @param plaintext_data Zeiger auf Klartext-Daten
     * @param plaintext_len Länge der Klartext-Daten
     * @param aad_data Zeiger auf AAD-Daten (kann nullptr sein)
     * @param aad_len Länge der AAD-Daten (0 wenn kein AAD)
     * @param output_buffer Ausgabe-Puffer (muss mindestens plaintext_len + 16 Bytes groß sein)
     * @return Länge der verschlüsselten Daten inklusive Tag oder -1 bei Fehler
     */
    int encrypt_zero_copy(const uint8_t* plaintext_data, size_t plaintext_len,
                         const uint8_t* aad_data, size_t aad_len, 
                         uint8_t* output_buffer);
    
    /**
     * @brief Zero-Copy-optimierte Entschlüsselung 
     * @param ciphertext_data Zeiger auf verschlüsselte Daten
     * @param ciphertext_len Länge der verschlüsselten Daten (ohne Tag)
     * @param aad_data Zeiger auf AAD-Daten (kann nullptr sein)
     * @param aad_len Länge der AAD-Daten (0 wenn kein AAD)
     * @param tag_data Zeiger auf das Tag (16 Bytes)
     * @param output_buffer Ausgabe-Puffer (muss mindestens ciphertext_len Bytes groß sein)
     * @return Länge der entschlüsselten Daten oder -1 bei Authentifizierungsfehler
     */
    int decrypt_zero_copy(const uint8_t* ciphertext_data, size_t ciphertext_len,
                         const uint8_t* aad_data, size_t aad_len,
                         const uint8_t* tag_data, 
                         uint8_t* output_buffer);
                         
    /**
     * @brief Prüft, ob SIMD-Optimierungen verfügbar sind
     * @return true wenn ARM Crypto Extensions verfügbar sind, sonst false
     */
    static bool is_hardware_acceleration_available();
    
private:
    class Impl; // PIMPL-Idiom für plattformspezifische Implementierungen
    std::unique_ptr<Impl> impl_;
    
    bool use_aesni_; // Hardware-Beschleunigung verwenden
    std::array<uint8_t, 16> key_; // AES-Schlüssel
    std::vector<uint8_t> iv_; // Initialisierungsvektor
    
    // GCM-Hilfsmethoden
    void gcm_init(const std::vector<uint8_t>& iv);
    void gcm_update_aad(const uint8_t* aad, size_t aad_len);
    void gcm_encrypt_block(uint8_t* output, const uint8_t* input);
    void gcm_decrypt_block(uint8_t* output, const uint8_t* input);
    void gcm_finish(uint8_t* tag);
};

} // namespace quicsand::crypto

#endif // AES128GCM_OPTIMIZED_HPP
