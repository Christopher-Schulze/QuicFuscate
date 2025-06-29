#include "DomainFronting.hpp"
#include <algorithm>
#include <random>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>

namespace quicfuscate {
namespace stealth {

// Konstruktor mit Konfiguration
SniHiding::SniHiding(const SniConfig& config)
    : config_(config) {
    init_enabled_techniques();
}

// Initialisierung der aktivierten Techniken basierend auf der Konfiguration
void SniHiding::init_enabled_techniques() {
    enabled_techniques_[SniTechnique::DOMAIN_FRONTING] = config_.enable_domain_fronting;
    enabled_techniques_[SniTechnique::SNI_OMISSION] = config_.enable_sni_omission;
    enabled_techniques_[SniTechnique::SNI_PADDING] = config_.enable_sni_padding;
    enabled_techniques_[SniTechnique::SNI_SPLIT] = config_.enable_sni_split;
    enabled_techniques_[SniTechnique::ECH] = config_.enable_ech;
    enabled_techniques_[SniTechnique::ESNI] = config_.enable_esni;
}

// Aktiviere eine Technik
void SniHiding::enable_technique(SniTechnique technique) {
    enabled_techniques_[technique] = true;
    
    // Aktualisiere auch die Konfiguration
    switch (technique) {
        case SniTechnique::DOMAIN_FRONTING:
            config_.enable_domain_fronting = true;
            break;
        case SniTechnique::SNI_OMISSION:
            config_.enable_sni_omission = true;
            break;
        case SniTechnique::SNI_PADDING:
            config_.enable_sni_padding = true;
            break;
        case SniTechnique::SNI_SPLIT:
            config_.enable_sni_split = true;
            break;
        case SniTechnique::ECH:
            config_.enable_ech = true;
            break;
        case SniTechnique::ESNI:
            config_.enable_esni = true;
            break;
    }
}

// Deaktiviere eine Technik
void SniHiding::disable_technique(SniTechnique technique) {
    enabled_techniques_[technique] = false;
    
    // Aktualisiere auch die Konfiguration
    switch (technique) {
        case SniTechnique::DOMAIN_FRONTING:
            config_.enable_domain_fronting = false;
            break;
        case SniTechnique::SNI_OMISSION:
            config_.enable_sni_omission = false;
            break;
        case SniTechnique::SNI_PADDING:
            config_.enable_sni_padding = false;
            break;
        case SniTechnique::SNI_SPLIT:
            config_.enable_sni_split = false;
            break;
        case SniTechnique::ECH:
            config_.enable_ech = false;
            break;
        case SniTechnique::ESNI:
            config_.enable_esni = false;
            break;
    }
}

// Überprüfe, ob eine Technik aktiviert ist
bool SniHiding::is_technique_enabled(SniTechnique technique) const {
    auto it = enabled_techniques_.find(technique);
    if (it != enabled_techniques_.end()) {
        return it->second;
    }
    return false;
}

// Verarbeite ein TLS Client Hello Paket
std::vector<uint8_t> SniHiding::process_client_hello(const std::vector<uint8_t>& client_hello) {
    std::vector<uint8_t> processed_hello = client_hello;
    
    // Wende Domain Fronting an
    if (is_technique_enabled(SniTechnique::DOMAIN_FRONTING)) {
        processed_hello = modify_sni(processed_hello, config_.front_domain);
    }
    
    // Wende SNI-Padding an
    if (is_technique_enabled(SniTechnique::SNI_PADDING)) {
        processed_hello = apply_sni_padding(processed_hello);
    }
    
    // Wende SNI-Omission an (wenn aktiviert)
    if (is_technique_enabled(SniTechnique::SNI_OMISSION)) {
        processed_hello = apply_sni_omission(processed_hello);
    }
    
    // Wende ECH an (wenn aktiviert)
    if (is_technique_enabled(SniTechnique::ECH)) {
        processed_hello = apply_ech(processed_hello);
    }
    
    // Wende ESNI an (wenn aktiviert)
    if (is_technique_enabled(SniTechnique::ESNI)) {
        processed_hello = apply_esni(processed_hello);
    }
    
    // SNI-Split wird später angewendet, da es mehrere Pakete zurückgibt
    
    return processed_hello;
}

// Modifiziere den SNI-Wert in einem TLS Client Hello Paket
std::vector<uint8_t> SniHiding::modify_sni(const std::vector<uint8_t>& client_hello, const std::string& new_sni) {
    // Finde die SNI-Extension
    size_t extension_offset = 0;
    size_t extension_length = 0;
    
    if (!find_sni_extension(client_hello, extension_offset, extension_length)) {
        // Keine SNI-Extension gefunden, gib das Original-Paket zurück
        return client_hello;
    }
    
    // Erstelle eine Kopie des Pakets
    std::vector<uint8_t> modified_hello = client_hello;
    
    // Position des SNI-Werts innerhalb der Extension (überspringen von SNI-Typ und Länge)
    size_t sni_value_offset = extension_offset + 7; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ, 2 für List-Länge
    
    // Ursprüngliche SNI-Länge berechnen (2 Bytes, Big Endian)
    size_t orig_sni_length = (client_hello[sni_value_offset - 2] << 8) | client_hello[sni_value_offset - 1];
    
    // Neue SNI-Länge
    uint16_t new_sni_length = static_cast<uint16_t>(new_sni.length());
    
    // Berechne die Größendifferenz
    int length_diff = static_cast<int>(new_sni_length) - static_cast<int>(orig_sni_length);
    
    if (length_diff == 0) {
        // Gleiche Länge, einfach ersetzen
        std::copy(new_sni.begin(), new_sni.end(), modified_hello.begin() + sni_value_offset);
    } else {
        // Unterschiedliche Länge, wir müssen das Paket neu aufbauen
        
        // Kopiere den Anfang bis zur SNI-Extension
        std::vector<uint8_t> new_packet(client_hello.begin(), client_hello.begin() + sni_value_offset);
        
        // Füge den neuen SNI-Wert hinzu
        new_packet.insert(new_packet.end(), new_sni.begin(), new_sni.end());
        
        // Füge den Rest des Pakets hinzu
        new_packet.insert(new_packet.end(), 
                         client_hello.begin() + sni_value_offset + orig_sni_length, 
                         client_hello.end());
        
        // Aktualisiere alle Längenfelder (Extension-Länge, List-Länge)
        size_t extension_len_offset = extension_offset + 2; // 2 für Extension-Typ
        uint16_t new_extension_length = static_cast<uint16_t>((client_hello[extension_len_offset] << 8) | 
                                                             client_hello[extension_len_offset + 1]) + length_diff;
        new_packet[extension_len_offset] = (new_extension_length >> 8) & 0xFF;
        new_packet[extension_len_offset + 1] = new_extension_length & 0xFF;
        
        size_t list_len_offset = extension_offset + 5; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ
        uint16_t new_list_length = static_cast<uint16_t>((client_hello[list_len_offset] << 8) | 
                                                        client_hello[list_len_offset + 1]) + length_diff;
        new_packet[list_len_offset] = (new_list_length >> 8) & 0xFF;
        new_packet[list_len_offset + 1] = new_list_length & 0xFF;
        
        // Aktualisiere die SNI-Länge
        new_packet[sni_value_offset - 2] = (new_sni_length >> 8) & 0xFF;
        new_packet[sni_value_offset - 1] = new_sni_length & 0xFF;
        
        // Aktualisiere die Gesamtlänge des ClientHello
        if (client_hello[0] == 0x16) { // TLS Handshake
            uint16_t record_length = (client_hello[3] << 8) | client_hello[4];
            record_length += length_diff;
            new_packet[3] = (record_length >> 8) & 0xFF;
            new_packet[4] = record_length & 0xFF;
        }
        
        modified_hello = new_packet;
    }
    
    return modified_hello;
}

// Wendet Domain Fronting auf HTTP-Headers an
std::string SniHiding::apply_domain_fronting(const std::string& http_headers) {
    // Ersetze den Host-Header mit der tatsächlichen Domain
    std::regex host_regex("Host:\\s*([^\\r\\n]+)", std::regex::icase);
    std::string new_headers = std::regex_replace(http_headers, host_regex, "Host: " + config_.real_domain);
    
    return new_headers;
}

// Suche die SNI-Extension in einem TLS ClientHello-Paket
bool SniHiding::find_sni_extension(const std::vector<uint8_t>& client_hello, size_t& extension_offset, size_t& extension_length) {
    // Vereinfachte TLS ClientHello-Parsing
    if (client_hello.size() < 43 || client_hello[0] != 0x16) { // TLS Handshake
        return false;
    }
    
    // Überspringe TLS Record Header (5 Bytes)
    size_t offset = 5;
    
    // Überspringe Handshake-Typ und Länge (4 Bytes)
    offset += 4;
    
    // Überspringe TLS-Version und Random (2 + 32 Bytes)
    offset += 34;
    
    // Überspringe Session ID
    uint8_t session_id_length = client_hello[offset];
    offset += 1 + session_id_length;
    
    if (offset + 2 >= client_hello.size()) {
        return false;
    }
    
    // Überspringe Cipher Suites
    uint16_t cipher_suites_length = (client_hello[offset] << 8) | client_hello[offset + 1];
    offset += 2 + cipher_suites_length;
    
    if (offset + 1 >= client_hello.size()) {
        return false;
    }
    
    // Überspringe Compression Methods
    uint8_t compression_methods_length = client_hello[offset];
    offset += 1 + compression_methods_length;
    
    if (offset + 2 >= client_hello.size()) {
        return false;
    }
    
    // Extensions-Länge
    uint16_t extensions_length = (client_hello[offset] << 8) | client_hello[offset + 1];
    offset += 2;
    
    if (offset + extensions_length > client_hello.size()) {
        return false;
    }
    
    // Durchsuche die Extensions nach SNI (Typ 0x0000)
    size_t extensions_end = offset + extensions_length;
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = (client_hello[offset] << 8) | client_hello[offset + 1];
        uint16_t extension_size = (client_hello[offset + 2] << 8) | client_hello[offset + 3];
        
        if (extension_type == 0x0000) { // SNI Extension
            extension_offset = offset;
            extension_length = extension_size + 4; // +4 für Typ und Länge
            return true;
        }
        
        offset += 4 + extension_size;
    }
    
    return false;
}

// ECH-Konfiguration generieren
std::optional<std::vector<uint8_t>> SniHiding::generate_ech_config(const std::string& target_domain) {
    // In einer realen Implementierung würde hier die ECH-Konfiguration vom Server abgerufen werden
    // und mit der Public Key der ECH-Konfiguration verarbeitet werden.
    // Für dieses Beispiel generieren wir einfach Dummy-Daten.
    
    std::vector<uint8_t> ech_config;
    
    // ECH Config Version
    ech_config.push_back(0xfe); // Version 0xfe0d
    ech_config.push_back(0x0d);
    
    // ECH Config Length (wird später aktualisiert)
    ech_config.push_back(0x00);
    ech_config.push_back(0x00);
    
    // Public Name
    std::string public_name = "public." + target_domain;
    ech_config.push_back(static_cast<uint8_t>(public_name.length()));
    ech_config.insert(ech_config.end(), public_name.begin(), public_name.end());
    
    // Public Key (Dummy-Daten)
    ech_config.push_back(0x00); // Key-Länge (2 Bytes)
    ech_config.push_back(0x20);
    for (int i = 0; i < 32; i++) {
        ech_config.push_back(static_cast<uint8_t>(i));
    }
    
    // Weitere Parameter
    ech_config.push_back(0x00); // Key-Encryption Algorithm: HPKE_DHKEM_X25519_HKDF_SHA256
    ech_config.push_back(0x01); // Symmetric Algorithm: HPKE_AEGIS_128X (ersetzt AES-128-GCM)
    ech_config.push_back(0x00); // Maximum Name Length
    ech_config.push_back(0xff);
    
    // Aktualisiere die ECH Config Length
    size_t config_length = ech_config.size() - 4; // -4 für Version und Länge
    ech_config[2] = (config_length >> 8) & 0xFF;
    ech_config[3] = config_length & 0xFF;
    
    return ech_config;
}

// Aktuelle ECH-Konfiguration abrufen
std::vector<uint8_t> SniHiding::get_ech_config() const {
    return config_.ech_config_data;
}

// Konfiguration setzen
void SniHiding::set_config(const SniConfig& config) {
    config_ = config;
    init_enabled_techniques();
}

// Konfiguration abrufen
SniConfig SniHiding::get_config() const {
    return config_;
}

// Vertrauenswürdige Fronting-Domain hinzufügen
void SniHiding::add_trusted_front(const std::string& domain) {
    // Überprüfe, ob die Domain bereits vorhanden ist
    auto it = std::find(config_.trusted_fronts.begin(), config_.trusted_fronts.end(), domain);
    if (it == config_.trusted_fronts.end()) {
        config_.trusted_fronts.push_back(domain);
    }
}

// Vertrauenswürdige Fronting-Domain entfernen
void SniHiding::remove_trusted_front(const std::string& domain) {
    auto it = std::find(config_.trusted_fronts.begin(), config_.trusted_fronts.end(), domain);
    if (it != config_.trusted_fronts.end()) {
        config_.trusted_fronts.erase(it);
    }
}

// Alle vertrauenswürdigen Fronting-Domains abrufen
std::vector<std::string> SniHiding::get_trusted_fronts() const {
    return config_.trusted_fronts;
}

// SNI-Padding anwenden
std::vector<uint8_t> SniHiding::apply_sni_padding(const std::vector<uint8_t>& client_hello) {
    // Finde die SNI-Extension
    size_t extension_offset = 0;
    size_t extension_length = 0;
    
    if (!find_sni_extension(client_hello, extension_offset, extension_length)) {
        // Keine SNI-Extension gefunden, gib das Original-Paket zurück
        return client_hello;
    }
    
    // Extrahiere den aktuellen SNI-Wert
    size_t sni_value_offset = extension_offset + 7; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ, 2 für List-Länge
    size_t sni_length = (client_hello[sni_value_offset - 2] << 8) | client_hello[sni_value_offset - 1];
    std::string current_sni(client_hello.begin() + sni_value_offset, client_hello.begin() + sni_value_offset + sni_length);
    
    // Füge Padding zum SNI hinzu
    std::string padded_sni = current_sni;
    
    // Füge einen zufälligen Subdomain-Präfix hinzu
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist_len(5, 10); // Länge des Präfixes
    std::uniform_int_distribution<> dist_char(0, sizeof(charset) - 2);
    
    std::string prefix;
    int prefix_len = dist_len(gen);
    for (int i = 0; i < prefix_len; i++) {
        prefix += charset[dist_char(gen)];
    }
    
    padded_sni = prefix + "." + padded_sni;
    
    // Modifiziere das Paket mit dem neuen SNI-Wert
    return modify_sni(client_hello, padded_sni);
}

// SNI-Omission anwenden
std::vector<uint8_t> SniHiding::apply_sni_omission(const std::vector<uint8_t>& client_hello) {
    // Finde die SNI-Extension
    size_t extension_offset = 0;
    size_t extension_length = 0;
    
    if (!find_sni_extension(client_hello, extension_offset, extension_length)) {
        // Keine SNI-Extension gefunden, gib das Original-Paket zurück
        return client_hello;
    }
    
    // Erstelle eine Kopie des Pakets ohne die SNI-Extension
    std::vector<uint8_t> modified_hello;
    modified_hello.insert(modified_hello.end(), client_hello.begin(), client_hello.begin() + extension_offset);
    modified_hello.insert(modified_hello.end(), 
                       client_hello.begin() + extension_offset + extension_length, 
                       client_hello.end());
    
    // Aktualisiere die Gesamtlänge des ClientHello
    if (client_hello[0] == 0x16) { // TLS Handshake
        uint16_t record_length = (client_hello[3] << 8) | client_hello[4];
        record_length -= extension_length;
        modified_hello[3] = (record_length >> 8) & 0xFF;
        modified_hello[4] = record_length & 0xFF;
    }
    
    // Aktualisiere die Extensions-Länge
    size_t extensions_len_offset = 0;
    
    // Vereinfachte Suche nach dem Extensions-Feld
    for (size_t i = 5; i < client_hello.size() - 2; i++) {
        // Suche nach einem charakteristischen Muster für die Extensions-Länge
        if (client_hello[i] == 0x00 && client_hello[i+1] >= 0x10 && client_hello[i+1] <= 0xFF) {
            extensions_len_offset = i;
            break;
        }
    }
    
    if (extensions_len_offset > 0) {
        uint16_t extensions_length = (client_hello[extensions_len_offset] << 8) | client_hello[extensions_len_offset + 1];
        extensions_length -= extension_length;
        modified_hello[extensions_len_offset] = (extensions_length >> 8) & 0xFF;
        modified_hello[extensions_len_offset + 1] = extensions_length & 0xFF;
    }
    
    return modified_hello;
}

// SNI-Split anwenden - Verteilung des SNI über mehrere TLS-Pakete
std::vector<uint8_t> SniHiding::apply_sni_split(const std::vector<uint8_t>& client_hello) {
    // Finde die SNI-Extension
    size_t extension_offset = 0;
    size_t extension_length = 0;
    
    if (!find_sni_extension(client_hello, extension_offset, extension_length)) {
        // Keine SNI-Extension gefunden, gib das Original-Paket zurück
        return client_hello;
    }
    
    // Position des SNI-Werts innerhalb der Extension (überspringen von SNI-Typ und Länge)
    size_t sni_value_offset = extension_offset + 7; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ, 2 für List-Länge
    
    // SNI-Länge berechnen (2 Bytes, Big Endian)
    size_t sni_length = (client_hello[sni_value_offset - 2] << 8) | client_hello[sni_value_offset - 1];
    
    // Extrahiere den SNI-Wert
    std::string sni_value(client_hello.begin() + sni_value_offset, 
                         client_hello.begin() + sni_value_offset + sni_length);
    
    // Erstelle ein modifiziertes ClientHello-Paket mit einem "fragmentierten" SNI
    // durch das Einfügen eines speziellen Zeichens, das weitere Fragmentierung erzwingt
    
    // Berechne die Stelle, an der der SNI gesplittet werden soll (in der Mitte)
    size_t split_pos = sni_length / 2;
    
    // Erstelle einen modifizierten SNI-Wert mit einem speziellen Zeichen an der Split-Position
    // Hier verwenden wir '\0' als Split-Marker, da dies in TLS-Implementierungen oft
    // als Ende eines Strings interpretiert wird und die Verarbeitung ungewöhnlich macht
    std::string modified_sni = sni_value;
    modified_sni.insert(split_pos, 1, '\0');
    
    // Erstelle das modifizierte ClientHello-Paket
    std::vector<uint8_t> modified_hello = client_hello;
    
    // Ersetze den SNI-Wert im Paket
    modified_hello.erase(modified_hello.begin() + sni_value_offset, 
                       modified_hello.begin() + sni_value_offset + sni_length);
    modified_hello.insert(modified_hello.begin() + sni_value_offset, 
                        modified_sni.begin(), modified_sni.end());
    
    // Aktualisiere die Längen im Paket
    // SNI-Länge aktualisieren
    size_t new_sni_length = modified_sni.length();
    modified_hello[sni_value_offset - 2] = (new_sni_length >> 8) & 0xFF;
    modified_hello[sni_value_offset - 1] = new_sni_length & 0xFF;
    
    // Extension-Länge aktualisieren
    size_t extension_len_offset = extension_offset + 2; // 2 für Extension-Typ
    uint16_t new_extension_length = (client_hello[extension_len_offset] << 8 | 
                                   client_hello[extension_len_offset + 1]) + 
                                   (new_sni_length - sni_length);
    modified_hello[extension_len_offset] = (new_extension_length >> 8) & 0xFF;
    modified_hello[extension_len_offset + 1] = new_extension_length & 0xFF;
    
    // List-Länge aktualisieren
    size_t list_len_offset = extension_offset + 5; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ
    uint16_t new_list_length = (client_hello[list_len_offset] << 8 | 
                              client_hello[list_len_offset + 1]) + 
                              (new_sni_length - sni_length);
    modified_hello[list_len_offset] = (new_list_length >> 8) & 0xFF;
    modified_hello[list_len_offset + 1] = new_list_length & 0xFF;
    
    // Handshake-Länge aktualisieren
    if (client_hello[0] == 0x16) { // TLS Handshake
        uint16_t record_length = (client_hello[3] << 8) | client_hello[4];
        record_length += (new_sni_length - sni_length);
        modified_hello[3] = (record_length >> 8) & 0xFF;
        modified_hello[4] = record_length & 0xFF;
    }
    
    // Alternative Implementierung: Zwei separate ClientHello-Pakete erzeugen
    // Der erste Teil des SNI ist im ersten Paket, der Rest im zweiten
    // Dies erfordert jedoch eine speziellere Behandlung auf TCP/IP-Ebene,
    // was über den Rahmen dieser Funktion hinausgeht
    
    // Hier ist eine erweiterte Implementierung möglich, die TCP-Segmente manipuliert
    // und mit gezielten SNI-Fragmentierungsmustern arbeitet.
    
    return modified_hello;
}

// ECH anwenden
std::vector<uint8_t> SniHiding::apply_ech(const std::vector<uint8_t>& client_hello) {
    // Wenn keine ECH-Konfiguration vorhanden ist, versuche eine zu generieren
    if (config_.ech_config_data.empty()) {
        auto ech_config = generate_ech_config(config_.real_domain);
        if (ech_config) {
            config_.ech_config_data = *ech_config;
        } else {
            // Keine ECH-Konfiguration verfügbar, gib das Original-Paket zurück
            return client_hello;
        }
    }
    
    // In einer realen Implementierung würde hier die ECH-Extension zum ClientHello hinzugefügt werden
    // und die tatsächliche Domain würde verschlüsselt werden
    
    // Für dieses Beispiel erstellen wir eine vereinfachte Version
    
    // Erstelle eine Kopie des Pakets
    std::vector<uint8_t> ech_hello = client_hello;
    
    // Finde das Ende der Extensions
    size_t extensions_end = 0;
    for (size_t i = client_hello.size() - 1; i >= 43; i--) {
        if (client_hello[i-3] == 0x00 && client_hello[i-2] == 0x0d && // Beispiel für eine Extension
            (client_hello[i-1] << 8 | client_hello[i]) <= 32) {
            extensions_end = i + 1;
            break;
        }
    }
    
    if (extensions_end == 0) {
        // Konnte das Ende der Extensions nicht finden
        return client_hello;
    }
    
    // Füge die ECH-Extension hinzu (Typ 0xfe0d)
    ech_hello.insert(ech_hello.end() - (client_hello.size() - extensions_end), 0xfe);
    ech_hello.insert(ech_hello.end() - (client_hello.size() - extensions_end), 0x0d);
    
    // Extension-Länge (2 Bytes)
    size_t ech_data_size = config_.ech_config_data.size();
    ech_hello.insert(ech_hello.end() - (client_hello.size() - extensions_end), (ech_data_size >> 8) & 0xFF);
    ech_hello.insert(ech_hello.end() - (client_hello.size() - extensions_end), ech_data_size & 0xFF);
    
    // ECH-Daten
    ech_hello.insert(ech_hello.end() - (client_hello.size() - extensions_end), 
                    config_.ech_config_data.begin(), 
                    config_.ech_config_data.end());
    
    // Aktualisiere die Gesamtlänge des Handshake-Records
    if (ech_hello[0] == 0x16) { // TLS Handshake
        uint16_t record_length = (ech_hello[3] << 8) | ech_hello[4];
        record_length += 4 + ech_data_size; // 4 Bytes für Typ und Länge
        ech_hello[3] = (record_length >> 8) & 0xFF;
        ech_hello[4] = record_length & 0xFF;
    }
    
    // Aktualisiere die Extensions-Länge
    size_t extensions_len_offset = 0;
    
    // Vereinfachte Suche nach dem Extensions-Feld
    for (size_t i = 5; i < client_hello.size() - 2; i++) {
        // Suche nach einem charakteristischen Muster für die Extensions-Länge
        if (client_hello[i] == 0x00 && client_hello[i+1] >= 0x10 && client_hello[i+1] <= 0xFF) {
            extensions_len_offset = i;
            break;
        }
    }
    
    if (extensions_len_offset > 0) {
        uint16_t extensions_length = (ech_hello[extensions_len_offset] << 8) | ech_hello[extensions_len_offset + 1];
        extensions_length += 4 + ech_data_size; // 4 Bytes für Typ und Länge
        ech_hello[extensions_len_offset] = (extensions_length >> 8) & 0xFF;
        ech_hello[extensions_len_offset + 1] = extensions_length & 0xFF;
    }
    
    return ech_hello;
}

// ESNI anwenden (veraltet, durch ECH ersetzt)
// ESNI (Encrypted Server Name Indication) war ein Vorläufer von ECH
// Diese Implementierung wird für Legacy-Support beibehalten
std::vector<uint8_t> SniHiding::apply_esni(const std::vector<uint8_t>& client_hello) {
    // Finde die SNI-Extension
    size_t extension_offset = 0;
    size_t extension_length = 0;
    
    if (!find_sni_extension(client_hello, extension_offset, extension_length)) {
        // Keine SNI-Extension gefunden, gib das Original-Paket zurück
        return client_hello;
    }
    
    // ESNI verwendet ein anderes Extension-Format als ECH
    // Extension Type für ESNI ist 0xffce (experimenteller Wert in Draft)
    const uint16_t ESNI_EXTENSION_TYPE = 0xffce;
    
    // Ersetze die Standard-SNI-Extension mit einer ESNI-Extension
    std::vector<uint8_t> modified_hello = client_hello;
    
    // Extrahiere den SNI-Wert
    size_t sni_value_offset = extension_offset + 7; // 2 für Extension-Typ, 2 für Länge, 1 für List-Typ, 2 für List-Länge
    size_t sni_length = (client_hello[sni_value_offset - 2] << 8) | client_hello[sni_value_offset - 1];
    std::string sni_value(client_hello.begin() + sni_value_offset, 
                         client_hello.begin() + sni_value_offset + sni_length);
    
    // Generiere einen zufälligen Schlüssel für die Verschlüsselung
    std::vector<uint8_t> esni_key(16, 0);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    for (auto& byte : esni_key) {
        byte = static_cast<uint8_t>(distrib(gen));
    }
    
    // Eine einfache XOR-Verschlüsselung als Beispiel (in der Praxis würde eine stärkere Verschlüsselung verwendet)
    std::vector<uint8_t> encrypted_sni(sni_length);
    for (size_t i = 0; i < sni_length; ++i) {
        encrypted_sni[i] = static_cast<uint8_t>(sni_value[i]) ^ esni_key[i % esni_key.size()];
    }
    
    // Entferne die alte SNI-Extension
    modified_hello.erase(modified_hello.begin() + extension_offset,
                        modified_hello.begin() + extension_offset + extension_length);
    
    // Erstelle die neue ESNI-Extension
    std::vector<uint8_t> esni_extension;
    
    // Extension Type (ESNI)
    esni_extension.push_back((ESNI_EXTENSION_TYPE >> 8) & 0xFF);
    esni_extension.push_back(ESNI_EXTENSION_TYPE & 0xFF);
    
    // Extension Length (2 Bytes) - wird später aktualisiert
    esni_extension.push_back(0);
    esni_extension.push_back(0);
    
    // ESNI Key (16 Bytes)
    esni_extension.insert(esni_extension.end(), esni_key.begin(), esni_key.end());
    
    // Verschlüsselter SNI
    esni_extension.insert(esni_extension.end(), encrypted_sni.begin(), encrypted_sni.end());
    
    // Aktualisiere die Extension-Länge
    uint16_t esni_extension_length = esni_extension.size() - 4; // Abzüglich Type und Length-Bytes
    esni_extension[2] = (esni_extension_length >> 8) & 0xFF;
    esni_extension[3] = esni_extension_length & 0xFF;
    
    // Füge die ESNI-Extension an der Stelle der ursprünglichen SNI-Extension ein
    modified_hello.insert(modified_hello.begin() + extension_offset,
                         esni_extension.begin(), esni_extension.end());
    
    // Aktualisiere die Handshake-Länge im TLS-Record-Header
    if (modified_hello[0] == 0x16) { // TLS Handshake
        int16_t size_diff = esni_extension.size() - extension_length;
        uint16_t record_length = (modified_hello[3] << 8) | modified_hello[4];
        record_length += size_diff;
        modified_hello[3] = (record_length >> 8) & 0xFF;
        modified_hello[4] = record_length & 0xFF;
    }
    
    // Hinweis: Dies ist eine vereinfachte ESNI-Implementierung
    // Die tatsächliche ESNI-Spezifikation erfordert:  
    // 1. Den Abruf von ESNI-Konfigurationsdaten über DNS
    // 2. Eine korrekte kryptografische Implementierung mit HPKE
    // 3. Die Integration mit dem TLS-Stack
    //
    // Da ECH (Encrypted Client Hello) ESNI ersetzt hat und standardisiert wird,
    // wird empfohlen, ECH für alle neuen Implementierungen zu verwenden.
    
    return modified_hello;
}

} // namespace stealth
} // namespace quicfuscate