#include "zero_rtt.hpp"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace quicsand {

// Singleton-Instanz
ZeroRttManager& ZeroRttManager::getInstance() {
    static ZeroRttManager instance;
    return instance;
}

// Konstruktor
ZeroRttManager::ZeroRttManager() : has_custom_master_key_(false) {
    // Generiere einen zufälligen Master-Key bei der Initialisierung
    generateNewMasterKey();
}

// Destruktor
ZeroRttManager::~ZeroRttManager() {
    // Sicheres Löschen des Master-Keys
    if (!master_key_.empty()) {
        OPENSSL_cleanse(master_key_.data(), master_key_.size());
    }
}

// Generiert ein neues Token für einen Hostnamen
ZeroRttToken ZeroRttManager::generateToken(const std::string& hostname, const ZeroRttConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ZeroRttToken token;
    token.hostname = hostname;
    token.timestamp = std::chrono::system_clock::now();
    token.lifetime_s = config.max_token_lifetime_s;
    
    // Generiere die Token-Daten mit dem Hostnamen und Zeitstempel
    token.token_data = generateTokenData(hostname, token.timestamp);
    
    return token;
}

// Validiert ein Token für einen Hostnamen
bool ZeroRttManager::validateToken(const ZeroRttToken& token, const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Überprüfe, ob das Token gültig ist (nicht abgelaufen)
    if (!token.is_valid()) {
        return false;
    }
    
    // Überprüfe, ob das Token für den richtigen Hostnamen ausgestellt wurde
    if (token.hostname != hostname) {
        return false;
    }
    
    // Überprüfe die Token-Daten mit dem HMAC
    return verifyTokenData(hostname, token.token_data, token.timestamp);
}

// Speichert ein Token für einen Hostnamen
void ZeroRttManager::storeToken(const std::string& hostname, const ZeroRttToken& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Lösche eventuell bereits vorhandene Tokens für diesen Hostnamen
    std::map<std::string, ZeroRttToken> local_token_store;
    local_token_store[hostname] = token;
}

// Ruft ein gespeichertes Token für einen Hostnamen ab
ZeroRttToken ZeroRttManager::getToken(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = token_store_.find(hostname);
    if (it != token_store_.end() && it->second.is_valid()) {
        return it->second;
    }
    
    // Wenn kein gültiges Token gefunden wurde, gib ein leeres Token zurück
    return ZeroRttToken();
}

// Entfernt ein gespeichertes Token für einen Hostnamen
void ZeroRttManager::removeToken(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = token_store_.find(hostname);
    if (it != token_store_.end()) {
        token_store_.erase(it);
    }
}

// Bereinigt abgelaufene Tokens
void ZeroRttManager::cleanupExpiredTokens() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = token_store_.begin();
    while (it != token_store_.end()) {
        if (!it->second.is_valid()) {
            it = token_store_.erase(it);
        } else {
            ++it;
        }
    }
}

// Setzt den Hauptschlüssel für die Token-Generierung
void ZeroRttManager::setMasterKey(const std::vector<uint8_t>& master_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (master_key.size() < 32) {
        // Schlüssel ist zu kurz, verwende stattdessen einen generierten Schlüssel
        std::cerr << "Warnung: ZeroRttManager master_key ist zu kurz (< 32 Bytes), generiere neuen Schlüssel" << std::endl;
        generateNewMasterKey();
        return;
    }
    
    // Sichere den neuen Master-Key
    master_key_ = master_key;
    has_custom_master_key_ = true;
}

// Generiert einen neuen Hauptschlüssel für die Token-Generierung
void ZeroRttManager::generateNewMasterKey() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Generiere einen 32-Byte-Schlüssel
    master_key_.resize(32);
    if (RAND_bytes(master_key_.data(), static_cast<int>(master_key_.size())) != 1) {
        std::cerr << "Fehler bei der Generierung des ZeroRttManager master_key" << std::endl;
        // Fülle mit einem festen Wert, falls RAND_bytes fehlschlägt
        std::fill(master_key_.begin(), master_key_.end(), 0x42);
    }
    
    has_custom_master_key_ = false;
}

// Gibt die Anzahl der gespeicherten Tokens zurück
size_t ZeroRttManager::getTokenCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return token_store_.size();
}

// Überprüft, ob Zero-RTT für einen Hostnamen möglich ist
bool ZeroRttManager::isZeroRttPossible(const std::string& hostname, const ZeroRttConfig& config) {
    // Überprüfe, ob Zero-RTT aktiviert ist
    if (!config.enabled) {
        return false;
    }
    
    // Überprüfe, ob ein gültiges Token für den Hostnamen existiert
    ZeroRttToken token = getToken(hostname);
    if (token.hostname.empty() || token.token_data.empty()) {
        return false;
    }
    
    // Validiere das Token
    return validateToken(token, hostname);
}

// Generiert Token-Daten mit HMAC
std::vector<uint8_t> ZeroRttManager::generateTokenData(const std::string& hostname, 
                                                    const std::chrono::system_clock::time_point& timestamp) {
    // Verwende HMAC-SHA256 für die Token-Generierung
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    
    // Erstelle die Nachricht: hostname + timestamp
    auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    
    std::string message = hostname;
    message += ":" + std::to_string(timestamp_ms);
    
    // Berechne den HMAC
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) {
        std::cerr << "Fehler beim Erstellen des HMAC-Kontexts" << std::endl;
        return {};
    }
    
    if (HMAC_Init_ex(ctx, master_key_.data(), static_cast<int>(master_key_.size()), EVP_sha256(), nullptr) != 1) {
        std::cerr << "Fehler bei HMAC_Init_ex" << std::endl;
        HMAC_CTX_free(ctx);
        return {};
    }
    
    if (HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1) {
        std::cerr << "Fehler bei HMAC_Update" << std::endl;
        HMAC_CTX_free(ctx);
        return {};
    }
    
    if (HMAC_Final(ctx, hmac, &hmac_len) != 1) {
        std::cerr << "Fehler bei HMAC_Final" << std::endl;
        HMAC_CTX_free(ctx);
        return {};
    }
    
    HMAC_CTX_free(ctx);
    
    // Konvertiere das HMAC-Ergebnis in einen Vektor
    std::vector<uint8_t> token_data(hmac, hmac + hmac_len);
    
    return token_data;
}

// Überprüft Token-Daten mit HMAC
bool ZeroRttManager::verifyTokenData(const std::string& hostname, 
                                    const std::vector<uint8_t>& token_data, 
                                    const std::chrono::system_clock::time_point& timestamp) {
    // Generiere erwartete Token-Daten und vergleiche sie mit den gegebenen Daten
    std::vector<uint8_t> expected_data = generateTokenData(hostname, timestamp);
    
    // Überprüfe, ob die Token-Daten übereinstimmen
    if (expected_data.size() != token_data.size()) {
        return false;
    }
    
    // Constante-Zeit-Vergleich, um Timing-Angriffe zu vermeiden
    return CRYPTO_memcmp(expected_data.data(), token_data.data(), expected_data.size()) == 0;
}

} // namespace quicsand
