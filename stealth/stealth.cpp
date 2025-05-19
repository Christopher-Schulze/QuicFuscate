#include "stealth/stealth.hpp"
#include "stealth/http3_masquerading.hpp"
#include <vector>
#include <cstdint>
#include <iostream>
#include <memory>

namespace quicsand {

// Konstruktor
Stealth::Stealth() : mode_(StealthMode::FAKE_TLS), 
                     http3_masquerading_(std::make_unique<Http3Masquerading>()) {
    std::cout << "Stealth: Initialisiert im FAKE_TLS-Modus" << std::endl;
}

// Destruktor
Stealth::~Stealth() = default;

// Initialisierung mit Konfigurationsoptionen
void Stealth::initialize(const std::map<std::string, std::string>& config) {
    // Konfigurationsoptionen auswerten
    auto mode_it = config.find("stealth_mode");
    if (mode_it != config.end()) {
        if (mode_it->second == "none") {
            mode_ = StealthMode::NONE;
        } else if (mode_it->second == "fake_tls") {
            mode_ = StealthMode::FAKE_TLS;
        } else if (mode_it->second == "http3") {
            mode_ = StealthMode::HTTP3_MASQUERADING;
        } else if (mode_it->second == "custom") {
            mode_ = StealthMode::CUSTOM;
        }
    }
    
    // HTTP/3-Masquerading-Handler initialisieren, wenn im HTTP3-Modus
    if (mode_ == StealthMode::HTTP3_MASQUERADING) {
        http3_masquerading_->initialize(config);
        std::cout << "Stealth: HTTP/3-Masquerading aktiviert" << std::endl;
    }
    
    std::cout << "Stealth: Konfiguration abgeschlossen, Modus = " 
              << static_cast<int>(mode_) << std::endl;
}

// Verschleierungsmodus setzen
void Stealth::set_mode(StealthMode mode) {
    mode_ = mode;
    std::cout << "Stealth: Modus geändert auf " << static_cast<int>(mode_) << std::endl;
}

// Aktuellen Verschleierungsmodus abfragen
StealthMode Stealth::get_mode() const {
    return mode_;
}

// Browser-Profil für HTTP/3-Masquerading setzen
void Stealth::set_browser_profile(const std::string& profile) {
    if (http3_masquerading_) {
        http3_masquerading_->set_browser_profile(profile);
        std::cout << "Stealth: Browser-Profil auf '" << profile << "' gesetzt" << std::endl;
    }
}

// Aktuelles Browser-Profil abfragen
std::string Stealth::get_browser_profile() const {
    if (http3_masquerading_) {
        return http3_masquerading_->get_browser_profile();
    }
    return "";
}

// Legacy-Methode: TLS-Record-Verschleierung für rohe Daten
std::vector<uint8_t> Stealth::obfuscate(const std::vector<uint8_t>& data) const {
    // Keine Verschleierung im NONE-Modus
    if (mode_ == StealthMode::NONE) {
        return data;
    }
    
    // Standard-Implementierung: Fake TLS ApplicationData record
    uint16_t len = data.size();
    std::vector<uint8_t> out;
    out.reserve(5 + len);
    out.push_back(0x17);  // ContentType: Application Data
    out.push_back(0x03);  // ProtocolVersion: TLS 1.2 (Major)
    out.push_back(0x03);  // ProtocolVersion: TLS 1.2 (Minor)
    // network byte order length
    out.push_back((len >> 8) & 0xFF);
    out.push_back(len & 0xFF);
    // payload
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

// Legacy-Methode: Entfernt TLS-Record-Verschleierung von rohen Daten
std::vector<uint8_t> Stealth::deobfuscate(const std::vector<uint8_t>& data) const {
    // Keine Entschleierung im NONE-Modus
    if (mode_ == StealthMode::NONE) {
        return data;
    }
    
    // Standard-Implementierung: TLS Record parsen
    if (data.size() < 5) return {};
    if (data[0] != 0x17 || data[1] != 0x03 || data[2] != 0x03) return {};
    uint16_t len = (uint16_t(data[3]) << 8) | data[4];
    if (data.size() < 5 + len) return {};
    return std::vector<uint8_t>(data.begin() + 5, data.begin() + 5 + len);
}

// Neue Methode: Paket-basierte Verschleierung für ausgehende Pakete
bool Stealth::process_outgoing_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    // Je nach Modus unterschiedliche Verschleierung anwenden
    switch (mode_) {
        case StealthMode::NONE:
            // Keine Verschleierung
            return true;
            
        case StealthMode::FAKE_TLS:
            // Einfache TLS-Record-Verschleierung auf die Payload anwenden
            {
                auto payload = packet->payload();
                auto obfuscated = obfuscate(payload);
                packet->set_payload(obfuscated);
            }
            return true;
            
        case StealthMode::HTTP3_MASQUERADING:
            // HTTP/3-Masquerading für QUIC-Pakete
            if (http3_masquerading_) {
                return http3_masquerading_->process_outgoing_packet(packet);
            }
            return false;
            
        case StealthMode::CUSTOM:
            // Benutzerdefinierte Verschleierung (nicht implementiert)
            std::cerr << "Stealth: CUSTOM-Modus nicht implementiert" << std::endl;
            return false;
    }
    
    return false;
}

// Neue Methode: Paket-basierte Entschleierung für eingehende Pakete
bool Stealth::process_incoming_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    // Je nach Modus unterschiedliche Entschleierung anwenden
    switch (mode_) {
        case StealthMode::NONE:
            // Keine Entschleierung
            return true;
            
        case StealthMode::FAKE_TLS:
            // Einfache TLS-Record-Entschleierung auf die Payload anwenden
            {
                auto payload = packet->payload();
                auto deobfuscated = deobfuscate(payload);
                packet->set_payload(deobfuscated);
            }
            return true;
            
        case StealthMode::HTTP3_MASQUERADING:
            // HTTP/3-Masquerading-Entschleierung für QUIC-Pakete
            if (http3_masquerading_) {
                return http3_masquerading_->process_incoming_packet(packet);
            }
            return false;
            
        case StealthMode::CUSTOM:
            // Benutzerdefinierte Entschleierung (nicht implementiert)
            std::cerr << "Stealth: CUSTOM-Modus nicht implementiert" << std::endl;
            return false;
    }
    
    return false;
}

// HTTP/3-Anfrage für einen bestimmten Host generieren
std::vector<uint8_t> Stealth::create_http3_request(const std::string& host, const std::string& path) {
    if (mode_ == StealthMode::HTTP3_MASQUERADING && http3_masquerading_) {
        return http3_masquerading_->create_http3_request(host, path);
    }
    
    // Fallback: Leere Anfrage zurückgeben
    return {};
}

} // namespace quicsand
