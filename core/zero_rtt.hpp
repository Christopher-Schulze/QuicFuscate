#ifndef ZERO_RTT_HPP
#define ZERO_RTT_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>
#include "common_configs.hpp"
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace quicsand {

/**
 * Token zur Erkennung und Validierung von Zero-RTT-Wiederverbindungen
 */
struct ZeroRttToken {
    std::string hostname;                      // Hostname, für den das Token gilt
    std::vector<uint8_t> token_data;           // Token-Daten für die Validierung
    std::chrono::system_clock::time_point timestamp; // Zeitpunkt der Token-Erstellung
    uint32_t lifetime_s;                       // Gültigkeitsdauer in Sekunden
    
    // Hilfsmethode zur Überprüfung der Gültigkeit des Tokens
    bool is_valid() const {
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count();
        return age < lifetime_s;
    }
};

/**
 * Zero-RTT-Manager verwaltet Tokens für Zero-RTT-Wiederverbindungen
 * und bietet Methoden zur Implementierung von Zero-RTT in QUIC-Verbindungen
 */
class ZeroRttManager {
public:
    // Singleton-Zugriff
    static ZeroRttManager& getInstance();
    
    /**
     * Generiert ein neues Token für einen Hostnamen
     * @param hostname Hostname, für den das Token generiert wird
     * @param config Konfiguration für das Token
     * @return Generiertes Token
     */
    ZeroRttToken generateToken(const std::string& hostname, const ZeroRttConfig& config);
    
    /**
     * Validiert ein Token für einen Hostnamen
     * @param token Token zur Validierung
     * @param hostname Hostname, für den das Token validiert wird
     * @return true, wenn das Token gültig ist
     */
    bool validateToken(const ZeroRttToken& token, const std::string& hostname);
    
    /**
     * Speichert ein Token für einen Hostnamen
     * @param hostname Hostname, für den das Token gespeichert wird
     * @param token Token, das gespeichert werden soll
     */
    void storeToken(const std::string& hostname, const ZeroRttToken& token);
    
    /**
     * Ruft ein gespeichertes Token für einen Hostnamen ab
     * @param hostname Hostname, für den das Token abgerufen wird
     * @return Gespeichertes Token oder leeres Token, wenn keines gefunden wurde
     */
    ZeroRttToken getToken(const std::string& hostname);
    
    /**
     * Entfernt ein gespeichertes Token für einen Hostnamen
     * @param hostname Hostname, für den das Token entfernt wird
     */
    void removeToken(const std::string& hostname);
    
    /**
     * Bereinigt abgelaufene Tokens
     */
    void cleanupExpiredTokens();
    
    /**
     * Setzt den Hauptschlüssel für die Token-Generierung
     * @param master_key Hauptschlüssel
     */
    void setMasterKey(const std::vector<uint8_t>& master_key);
    
    /**
     * Generiert einen neuen Hauptschlüssel für die Token-Generierung
     */
    void generateNewMasterKey();
    
    /**
     * Gibt die Anzahl der gespeicherten Tokens zurück
     * @return Anzahl der gespeicherten Tokens
     */
    size_t getTokenCount() const;
    
    /**
     * Überprüft, ob Zero-RTT für einen Hostnamen möglich ist
     * @param hostname Hostname, für den die Überprüfung durchgeführt wird
     * @param config Konfiguration für die Überprüfung
     * @return true, wenn Zero-RTT möglich ist
     */
    bool isZeroRttPossible(const std::string& hostname, const ZeroRttConfig& config);
    
private:
    // Private Konstruktor für Singleton-Pattern
    ZeroRttManager();
    
    // Privater Destruktor
    ~ZeroRttManager();
    
    // Verhindere Kopieren des Singletons
    ZeroRttManager(const ZeroRttManager&) = delete;
    ZeroRttManager& operator=(const ZeroRttManager&) = delete;
    
    // Private Hilfsmethoden
    std::vector<uint8_t> generateTokenData(const std::string& hostname, 
                                          const std::chrono::system_clock::time_point& timestamp);
    
    bool verifyTokenData(const std::string& hostname, 
                        const std::vector<uint8_t>& token_data, 
                        const std::chrono::system_clock::time_point& timestamp);
    
    // Member-Variablen
    mutable std::mutex mutex_;
    std::map<std::string, ZeroRttToken> token_store_;
    std::vector<uint8_t> master_key_;
    bool has_custom_master_key_;
};

} // namespace quicsand

#endif // ZERO_RTT_HPP
