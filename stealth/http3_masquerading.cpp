/**
 * http3_masquerading.cpp
 * 
 * Implementierung der HTTP/3-Masquerading-Funktionalität für QuicFuscate.
 * Diese Komponente ermöglicht es, den VPN-Traffic als regulären HTTP/3-Traffic
 * erscheinen zu lassen, um Erkennung und Blockierung zu vermeiden.
 */

#include "HTTP3_Masquerading.hpp"
#include "browser_profiles/fingerprints/browser_fingerprints.hpp"
#include <iostream>
#include <algorithm>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace quicfuscate {

// Konstruktor
Http3Masquerading::Http3Masquerading(std::shared_ptr<QuicConnection> conn, int id, StreamType type)
    : QuicStream(conn, id, type),
      browser_profile_("Chrome_Latest"),
      qpack_codec_(std::make_unique<QpackCodec>()) {
    std::cout << "HTTP/3 Masquerading: Initialisiert mit Standard-Browser-Profil" << std::endl;
}

// Destruktor
Http3Masquerading::~Http3Masquerading() = default;

// Initialisierung mit Konfigurationsoptionen
void Http3Masquerading::initialize(const std::map<std::string, std::string>& config) {
    config_ = config;
    
    // Browser-Profil aus Konfiguration übernehmen, falls vorhanden
    auto it = config.find("browser_profile");
    if (it != config.end()) {
        browser_profile_ = it->second;
    }
    
    std::cout << "HTTP/3 Masquerading: Konfiguriert mit Browser-Profil '" 
              << browser_profile_ << "'" << std::endl;
}

// Verarbeitet ausgehende Pakete und verschleiert sie als HTTP/3-Traffic
bool Http3Masquerading::process_outgoing_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    // Use base class stream state management
    if (QuicStream::is_closed()) {
        return false;
    }
    
    // Hier analysieren wir den QUIC-Pakettyp und entscheiden, ob HTTP/3-Masquerading angewendet werden soll
    
    // Für InitialPackets: Ein HTTP/3 SETTINGS-Frame am Anfang hinzufügen
    if (packet->is_initial()) {
        // Erstellen eines Settings-Frames für Stream 0 (Kontrollstream)
        std::vector<uint8_t> settings_frame = create_frame(Http3FrameType::SETTINGS, {
            // SETTINGS-Einträge, z.B. MAX_HEADER_LIST_SIZE = 16K
            0x06, 0x00, 0x00, 0x40, 0x00
        });
        
        // Die Frame-Daten am Anfang der Nutzlast einfügen
        auto payload = packet->payload();
        payload.insert(payload.begin(), settings_frame.begin(), settings_frame.end());
        packet->set_payload(payload);
        
        return true;
    }
    
    // Für Stream-Daten: Wenn es sich um einen neuen Stream handelt, HTTP/3-Header hinzufügen
    if (packet->is_stream()) {
        // Hier würden wir prüfen, ob es ein neuer Stream ist und ggf. Headers hinzufügen
        // In einer vollständigen Implementierung würden wir die Stream-ID tracken
        
        return true;
    }
    
    // Für andere Pakettypen keine Änderungen vornehmen
    return true;
}

// Verarbeitet eingehende Pakete und entfernt die HTTP/3-Maskierung
bool Http3Masquerading::process_incoming_packet(std::shared_ptr<QuicPacket> packet) {
    if (!packet) {
        return false;
    }
    
    // Hier entfernen wir die HTTP/3-Headers und -Frames aus dem eingehenden Paket
    // und extrahieren die eigentliche Nutzlast
    
    // Für InitialPackets: Prüfen auf SETTINGS-Frames im Kontrollstream
    if (packet->is_initial()) {
        auto payload = packet->payload();
        
        // Extrahieren und Entfernen aller HTTP/3-Frames aus dem Paket
        std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>> frames;
        if (extract_frames(payload, frames)) {
            // Nur die eigentliche Nutzlast (ohne HTTP/3-Frames) beibehalten
            size_t http3_overhead = 0;
            for (const auto& frame : frames) {
                // Größe des Frame-Headers + Payload berechnen
                http3_overhead += frame.second.size() + 2; // 2 Bytes für Type und Length (vereinfacht)
            }
            
            if (http3_overhead < payload.size()) {
                payload.erase(payload.begin(), payload.begin() + http3_overhead);
                packet->set_payload(payload);
            }
        }
        
        return true;
    }
    
    // Für Stream-Daten: HTTP/3-Frames entfernen
    if (packet->is_stream()) {
        // Hier würden wir die HTTP/3-Frames aus den Stream-Daten extrahieren
        // In einer vollständigen Implementierung würden wir die Stream-ID tracken
        
        return true;
    }
    
    // Für andere Pakettypen keine Änderungen vornehmen
    return true;
}

// Erzeugt eine realistische HTTP/3-Anfrage für den angegebenen Host
std::vector<uint8_t> Http3Masquerading::create_http3_request(const std::string& host, 
                                                          const std::string& path) {
    std::vector<uint8_t> request;
    
    // HEADERS Frame erstellen, der Header mit dem Browser-Profil enthält
    auto headers_frame = create_headers_frame(generate_realistic_headers(host, path));
    
    // Optional einen leeren DATA-Frame anhängen (für GET-Requests)
    auto data_frame = create_frame(Http3FrameType::DATA, {});
    
    // Da headers_frame und data_frame bereits std::vector<uint8_t> sind,
    // können wir sie direkt anhängen
    request.insert(request.end(), headers_frame.begin(), headers_frame.end());
    request.insert(request.end(), data_frame.begin(), data_frame.end());
    
    return request;
}

// Erstellt einen HTTP/3-Frame mit dem spezifizierten Typ und Inhalt
std::vector<uint8_t> Http3Masquerading::create_frame(Http3FrameType type, 
                                                   const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    
    // 1. Frame-Typ hinzufügen
    frame.push_back(static_cast<uint8_t>(type));
    
    // 2. Payload-Länge als Variable-Length Integer codieren
    auto length_bytes = encode_varint(payload.size());
    frame.insert(frame.end(), length_bytes.begin(), length_bytes.end());
    
    // 3. Payload hinzufügen
    frame.insert(frame.end(), payload.begin(), payload.end());
    
    return frame;
}

// Erstellt HEADERS-Frame mit QPACK-codierten Headern
std::vector<uint8_t> Http3Masquerading::create_headers_frame(const std::vector<Http3HeaderField>& headers) {
    // 1. Header mit QPACK codieren
    // QpackCodec hat encode_header_block statt encode_headers
    // Wir müssen die Header-Struktur anpassen
    std::vector<std::pair<std::string, std::string>> header_pairs;
    for (const auto& header : headers) {
        header_pairs.push_back({header.name, header.value});
    }
    auto encoded_headers = qpack_codec_->encode_header_block(header_pairs);
    
    // 2. Encoded Headers in einen HEADERS-Frame verpacken
    return create_frame(Http3FrameType::HEADERS, encoded_headers);
}

// Extrahiert Frames aus einem HTTP/3-Stream
bool Http3Masquerading::extract_frames(
    const std::vector<uint8_t>& data, 
    std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>>& frames) {
    
    if (data.empty()) {
        return false;
    }
    
    size_t offset = 0;
    while (offset < data.size()) {
        // 1. Frame-Typ extrahieren
        if (offset >= data.size()) break;
        Http3FrameType frame_type = static_cast<Http3FrameType>(data[offset++]);
        
        // 2. Länge als Variable-Length Integer decodieren
        size_t bytes_read = 0;
        if (offset >= data.size()) break;
        uint64_t length = decode_varint(&data[offset], data.size() - offset, bytes_read);
        offset += bytes_read;
        
        // 3. Payload extrahieren
        if (offset + length > data.size()) break;
        std::vector<uint8_t> payload(data.begin() + offset, data.begin() + offset + length);
        offset += length;
        
        // 4. Frame zur Liste hinzufügen
        frames.emplace_back(frame_type, payload);
    }
    
    return !frames.empty();
}

// Setter für Browser-Profil
void Http3Masquerading::set_browser_profile(const std::string& profile) {
    browser_profile_ = profile;
}

// Getter für Browser-Profil
std::string Http3Masquerading::get_browser_profile() const {
    return browser_profile_;
}

// Simuliert realistische Timings für Browseranfragen
void Http3Masquerading::simulate_realistic_timing(uint64_t& delay_ms) {
    // Einfache Timing-Simulation basierend auf Browser-Profil
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(50, 200);
    
    delay_ms = dis(gen);
    
    // Zusätzliche Verzögerung für realistische Browser-Simulation
    if (browser_profile_.find("Chrome") != std::string::npos) {
        delay_ms += 10;
    } else if (browser_profile_.find("Firefox") != std::string::npos) {
        delay_ms += 15;
    }
}

// Verwende die optimierten Hilfsfunktionen aus http3_util
std::vector<uint8_t> Http3Masquerading::encode_varint(uint64_t value) {
    std::vector<uint8_t> result;
    
    if (value < 64) {
        result.push_back(static_cast<uint8_t>(value));
    } else if (value < 16384) {
        result.push_back(static_cast<uint8_t>(0x40 | (value >> 8)));
        result.push_back(static_cast<uint8_t>(value & 0xFF));
    } else if (value < 1073741824) {
        result.push_back(static_cast<uint8_t>(0x80 | (value >> 24)));
        result.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(value & 0xFF));
    } else {
        result.push_back(static_cast<uint8_t>(0xC0 | (value >> 56)));
        for (int i = 7; i >= 0; i--) {
            result.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }
    
    return result;
}

uint64_t Http3Masquerading::decode_varint(const uint8_t* data, size_t len, size_t& bytes_read) {
    if (len == 0) {
        bytes_read = 0;
        return 0;
    }
    
    uint8_t first_byte = data[0];
    uint8_t length_bits = (first_byte & 0xC0) >> 6;
    
    switch (length_bits) {
        case 0: // 1 byte
            bytes_read = 1;
            return first_byte & 0x3F;
        case 1: // 2 bytes
            if (len < 2) {
                bytes_read = 0;
                return 0;
            }
            bytes_read = 2;
            return ((first_byte & 0x3F) << 8) | data[1];
        case 2: // 4 bytes
            if (len < 4) {
                bytes_read = 0;
                return 0;
            }
            bytes_read = 4;
            return ((first_byte & 0x3F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        case 3: // 8 bytes
            if (len < 8) {
                bytes_read = 0;
                return 0;
            }
            bytes_read = 8;
            uint64_t result = (first_byte & 0x3F);
            for (int i = 1; i < 8; i++) {
                result = (result << 8) | data[i];
            }
            return result;
    }
    
    bytes_read = 0;
    return 0;
}

// Generiert realistische HTTP-Headers basierend auf dem Browser-Profil
std::vector<Http3HeaderField> Http3Masquerading::generate_realistic_headers(
    const std::string& host, const std::string& path) {
    
    std::vector<Http3HeaderField> headers;
    
    // Add HTTP/3 pseudo-headers
    headers.push_back({": method", "GET"});
    headers.push_back({": scheme", "https"});
    headers.push_back({": authority", host});
    headers.push_back({": path", path});
    
    // Add standard browser headers
    headers.push_back({"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"});
    headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"});
    headers.push_back({"accept-language", "en-US,en;q=0.9"});
    headers.push_back({"accept-encoding", "gzip, deflate, br"});
    headers.push_back({"sec-fetch-dest", "document"});
    headers.push_back({"sec-fetch-mode", "navigate"});
    headers.push_back({"sec-fetch-site", "none"});
    headers.push_back({"sec-fetch-user", "?1"});
    
    // Add timestamp-based headers
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream date_ss;
    date_ss << std::put_time(std::gmtime(&time_t_now), "%a, %d %b %Y %H:%M:%S GMT");
    
    headers.push_back({"cache-control", "max-age=0"});
    headers.push_back({"date", date_ss.str()});
    headers.push_back({"upgrade-insecure-requests", "1"});
    
    // Add device-specific headers for mobile devices
    headers.push_back({"device-memory", "4"});
    headers.push_back({"device-model", "iPhone15,3"});
    
    return headers;
}


} // namespace quicfuscate
