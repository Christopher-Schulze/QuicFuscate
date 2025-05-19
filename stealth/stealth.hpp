#pragma once

#include <vector>
#include <memory>
#include <map>
#include <string>
#include "http3_masquerading.hpp"
#include "../core/quic_packet.hpp"

namespace quicsand {

// Arten der Verschleierungsstrategie
enum class StealthMode {
    NONE,              // Keine Verschleierung
    FAKE_TLS,          // Einfache TLS-Record-Verschleierung
    HTTP3_MASQUERADING, // Volle HTTP/3-Emulation
    CUSTOM             // Benutzerdefinierte Verschleierung
};

// Stealth: Verpackt Daten für Tarnung im Netzwerk
class Stealth {
public:
    Stealth();
    ~Stealth();
    
    // Initialisierung mit Konfigurationsoptionen
    void initialize(const std::map<std::string, std::string>& config);
    
    // Verschleierungsmodus setzen
    void set_mode(StealthMode mode);
    StealthMode get_mode() const;
    
    // Browser-Profil für HTTP/3-Masquerading setzen
    void set_browser_profile(const std::string& profile);
    std::string get_browser_profile() const;
    
    // Legacy-Methoden für einfache TLS-Verschleierung
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> deobfuscate(const std::vector<uint8_t>& data) const;
    
    // Neue Methoden für erweiterte Verschleierung von QUIC-Paketen
    bool process_outgoing_packet(std::shared_ptr<QuicPacket> packet);
    bool process_incoming_packet(std::shared_ptr<QuicPacket> packet);
    
    // HTTP/3-Anfrage für einen bestimmten Host generieren
    std::vector<uint8_t> create_http3_request(const std::string& host, const std::string& path);

private:
    // Aktueller Verschleierungsmodus
    StealthMode mode_;
    
    // HTTP/3-Masquerading-Handler
    std::unique_ptr<Http3Masquerading> http3_masquerading_;
};

} // namespace quicsand
