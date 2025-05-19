/**
 * utls_client_configurator_extensions.cpp
 * 
 * Implementierungen der TLS-Erweiterungs-Generator-Methoden für das QuicSand-Projekt.
 * Diese Methoden erzeugen realistische TLS-Erweiterungen, die typischen Browsern entsprechen.
 */

#include "utls_client_configurator.hpp"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <iostream>

namespace quicsand {

// ALPN (Application-Layer Protocol Negotiation) Extension generieren
void UTLSClientConfigurator::generate_alpn_extension(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
    // ALPN-Protokolle für verschiedene Browser
    std::vector<std::string> protocols;
    
    switch (fingerprint) {
        case BrowserFingerprint::CHROME_LATEST:
        case BrowserFingerprint::CHROME_70:
        case BrowserFingerprint::CHROME_ANDROID:
        case BrowserFingerprint::EDGE_CHROMIUM:
            // Chrome und Chrome-basierte Browser
            protocols = {"h3", "h3-29", "h2", "http/1.1"};
            break;
            
        case BrowserFingerprint::FIREFOX_LATEST:
        case BrowserFingerprint::FIREFOX_63:
            // Firefox tendiert zu weniger Protokollen
            protocols = {"h2", "http/1.1"};
            break;
            
        case BrowserFingerprint::SAFARI_LATEST:
        case BrowserFingerprint::SAFARI_IOS:
            // Safari unterstützt HTTP/2 und HTTP/1.1
            protocols = {"h2", "http/1.1"};
            break;
            
        case BrowserFingerprint::OPERA_LATEST:
            // Opera (Chromium-basiert)
            protocols = {"h3", "h3-29", "h2", "http/1.1"};
            break;
            
        case BrowserFingerprint::BRAVE_LATEST:
            // Brave (Chromium-basiert)
            protocols = {"h3", "h3-29", "h2", "http/1.1"};
            break;
            
        case BrowserFingerprint::RANDOMIZED:
        case BrowserFingerprint::CUSTOM:
        default:
            // Zufällige Auswahl oder Fallback
            protocols = {"h2", "http/1.1"};
            
            // Zufällig auch HTTP/3 hinzufügen
            if (rand() % 2 == 0) {
                protocols.insert(protocols.begin(), "h3");
                protocols.insert(protocols.begin() + 1, "h3-29");
            }
            break;
    }
    
    // Berechne die Größe der ALPN-Erweiterung
    size_t total_size = 2; // 2 Bytes für die Länge der gesamten Liste
    
    for (const auto& protocol : protocols) {
        total_size += 1 + protocol.size(); // 1 Byte für Länge + Protokollname
    }
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
    if (*out == nullptr) {
        *outlen = 0;
        return;
    }
    
    unsigned char* p = *out;
    
    // Berechne die Länge der Protokollliste
    uint16_t list_length = static_cast<uint16_t>(total_size - 2);
    
    // Setze die Länge der gesamten Liste (Network Byte Order)
    *p++ = static_cast<unsigned char>((list_length >> 8) & 0xFF);
    *p++ = static_cast<unsigned char>(list_length & 0xFF);
    
    // Füge jedes Protokoll hinzu
    for (const auto& protocol : protocols) {
        uint8_t proto_len = static_cast<uint8_t>(protocol.size());
        *p++ = proto_len;
        std::memcpy(p, protocol.c_str(), proto_len);
        p += proto_len;
    }
    
    *outlen = total_size;
}

// Supported Versions Extension generieren
void UTLSClientConfigurator::generate_supported_versions(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
    // TLS-Versionen für verschiedene Browser (in Prioritätsreihenfolge)
    std::vector<uint16_t> versions;
    
    switch (fingerprint) {
        case BrowserFingerprint::CHROME_LATEST:
        case BrowserFingerprint::EDGE_CHROMIUM:
        case BrowserFingerprint::BRAVE_LATEST:
        case BrowserFingerprint::OPERA_LATEST:
            // Moderne Chrome-basierte Browser
            versions = {0x0304, 0x0303, 0x0302}; // TLS 1.3, TLS 1.2, TLS 1.1
            break;
            
        case BrowserFingerprint::CHROME_70:
            // Ältere Chrome-Version
            versions = {0x0303, 0x0302, 0x0301}; // TLS 1.2, TLS 1.1, TLS 1.0
            break;
            
        case BrowserFingerprint::CHROME_ANDROID:
            // Chrome für Android
            versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
            break;
            
        case BrowserFingerprint::FIREFOX_LATEST:
            // Moderner Firefox
            versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
            break;
            
        case BrowserFingerprint::FIREFOX_63:
            // Älterer Firefox
            versions = {0x0303, 0x0302, 0x0301}; // TLS 1.2, TLS 1.1, TLS 1.0
            break;
            
        case BrowserFingerprint::SAFARI_LATEST:
        case BrowserFingerprint::SAFARI_IOS:
            // Safari
            versions = {0x0304, 0x0303, 0x0302}; // TLS 1.3, TLS 1.2, TLS 1.1
            break;
            
        case BrowserFingerprint::RANDOMIZED:
        case BrowserFingerprint::CUSTOM:
        default:
            // Zufällige Auswahl oder Fallback
            versions = {0x0304, 0x0303}; // TLS 1.3, TLS 1.2
            break;
    }
    
    // Berechne die Größe der Extension
    size_t total_size = 1 + versions.size() * 2; // 1 Byte für die Länge + 2 Bytes pro Version
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
    if (*out == nullptr) {
        *outlen = 0;
        return;
    }
    
    unsigned char* p = *out;
    
    // Setze die Länge der Versionsliste
    *p++ = static_cast<unsigned char>(versions.size() * 2);
    
    // Füge jede Version hinzu (Network Byte Order)
    for (uint16_t version : versions) {
        *p++ = static_cast<unsigned char>((version >> 8) & 0xFF);
        *p++ = static_cast<unsigned char>(version & 0xFF);
    }
    
    *outlen = total_size;
}

// PSK Key Exchange Modes Extension generieren
void UTLSClientConfigurator::generate_psk_modes(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
    // PSK-Modi für verschiedene Browser
    std::vector<uint8_t> modes;
    
    // Die meisten modernen Browser unterstützen PSK mit (EC)DHE
    modes = {0x01}; // PSK with (EC)DHE key establishment
    
    // Spezialfall: Erweiterung vollständig weglassen für ältere Browser
    if (fingerprint == BrowserFingerprint::CHROME_70 || 
        fingerprint == BrowserFingerprint::FIREFOX_63) {
        *out = nullptr;
        *outlen = 0;
        return;
    }
    
    // Berechne die Größe der Extension
    size_t total_size = 1 + modes.size(); // 1 Byte für die Länge + 1 Byte pro Modus
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
    if (*out == nullptr) {
        *outlen = 0;
        return;
    }
    
    unsigned char* p = *out;
    
    // Setze die Länge der Modiliste
    *p++ = static_cast<unsigned char>(modes.size());
    
    // Füge jeden Modus hinzu
    for (uint8_t mode : modes) {
        *p++ = mode;
    }
    
    *outlen = total_size;
}

// Key Share Extension generieren
void UTLSClientConfigurator::generate_key_share(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
    // Da die tatsächliche Schlüsselgenerierung komplex ist, erstellen wir hier
    // eine vereinfachte Erweiterung mit einem Platzhalter-Schlüssel
    
    // Key-Share-Gruppen für verschiedene Browser
    std::vector<uint16_t> groups;
    
    switch (fingerprint) {
        case BrowserFingerprint::CHROME_LATEST:
        case BrowserFingerprint::EDGE_CHROMIUM:
        case BrowserFingerprint::BRAVE_LATEST:
        case BrowserFingerprint::OPERA_LATEST:
            // Moderne Chrome-basierte Browser
            groups = {0x001D, 0x0017}; // x25519, secp256r1
            break;
            
        case BrowserFingerprint::FIREFOX_LATEST:
            // Moderner Firefox
            groups = {0x001D, 0x0017}; // x25519, secp256r1
            break;
            
        case BrowserFingerprint::SAFARI_LATEST:
        case BrowserFingerprint::SAFARI_IOS:
            // Safari
            groups = {0x001D, 0x0017}; // x25519, secp256r1
            break;
            
        case BrowserFingerprint::RANDOMIZED:
        case BrowserFingerprint::CUSTOM:
        default:
            // Ein zufällige Gruppe
            groups = {0x001D}; // x25519
            break;
    }
    
    // Simuliere einen einfachen Key Share für X25519 (32 Bytes)
    uint8_t key_data[32];
    RAND_bytes(key_data, sizeof(key_data));
    
    // Berechne die Größe der Extension
    size_t client_shares_size = 0;
    for (size_t i = 0; i < groups.size(); i++) {
        // 2 Bytes für die Gruppe + 2 Bytes für die Keylänge + simulierte Keylänge (32 Bytes)
        client_shares_size += 2 + 2 + 32;
    }
    
    size_t total_size = 2 + client_shares_size; // 2 Bytes für die Länge + Inhalt
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
    if (*out == nullptr) {
        *outlen = 0;
        return;
    }
    
    unsigned char* p = *out;
    
    // Setze die Länge der Client-Shares
    uint16_t shares_length = static_cast<uint16_t>(client_shares_size);
    *p++ = static_cast<unsigned char>((shares_length >> 8) & 0xFF);
    *p++ = static_cast<unsigned char>(shares_length & 0xFF);
    
    // Füge jeden Key Share hinzu
    for (uint16_t group : groups) {
        // Named Group
        *p++ = static_cast<unsigned char>((group >> 8) & 0xFF);
        *p++ = static_cast<unsigned char>(group & 0xFF);
        
        // Key Exchange Länge
        uint16_t key_length = 32; // X25519 hat immer 32 Bytes
        *p++ = static_cast<unsigned char>((key_length >> 8) & 0xFF);
        *p++ = static_cast<unsigned char>(key_length & 0xFF);
        
        // Key Exchange Daten (zufällig)
        RAND_bytes(p, key_length);
        p += key_length;
    }
    
    *outlen = total_size;
}

// EC Point Formats Extension generieren
void UTLSClientConfigurator::generate_ec_point_formats(unsigned char** out, size_t* outlen, BrowserFingerprint fingerprint) {
    // EC Point Formats für verschiedene Browser
    std::vector<uint8_t> formats;
    
    // Die meisten Browser verwenden nur uncompressed
    formats = {0x00}; // uncompressed
    
    // Berechne die Größe der Extension
    size_t total_size = 1 + formats.size(); // 1 Byte für die Länge + 1 Byte pro Format
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(total_size));
    if (*out == nullptr) {
        *outlen = 0;
        return;
    }
    
    unsigned char* p = *out;
    
    // Setze die Länge der Formatliste
    *p++ = static_cast<unsigned char>(formats.size());
    
    // Füge jedes Format hinzu
    for (uint8_t format : formats) {
        *p++ = format;
    }
    
    *outlen = total_size;
}

// Zufällige Extensions-Daten generieren
void UTLSClientConfigurator::generate_random_extension_data(unsigned char** out, size_t* outlen, unsigned int ext_type) {
    // Generiere eine zufällige Länge zwischen 0 und 32 Bytes
    size_t length = rand() % 33;
    
    // Allokiere Speicher für die Erweiterung
    *out = static_cast<unsigned char*>(OPENSSL_malloc(length));
    if (*out == nullptr || length == 0) {
        *out = static_cast<unsigned char*>(OPENSSL_malloc(0));
        *outlen = 0;
        return;
    }
    
    // Generiere zufällige Daten
    RAND_bytes(*out, length);
    
    *outlen = length;
}

} // namespace quicsand
