/**
 * http3_masquerading.cpp
 * 
 * Implementierung der HTTP/3-Masquerading-Funktionalität für QuicSand.
 * Diese Komponente ermöglicht es, den VPN-Traffic als regulären HTTP/3-Traffic
 * erscheinen zu lassen, um Erkennung und Blockierung zu vermeiden.
 */

#include "http3_masquerading.hpp"
#include <iostream>
#include <algorithm>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace quicsand {

// Konstruktor
Http3Masquerading::Http3Masquerading() 
    : browser_profile_("Chrome_Latest"),
      qpack_encoder_(std::make_unique<QpackEncoder>()) {
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
    
    // 1. Realistische HTTP-Headers generieren
    auto headers = generate_realistic_headers(host, path);
    
    // 2. Headers in einen HEADERS-Frame verpacken
    auto headers_frame = create_headers_frame(headers);
    
    // 3. Optional einen leeren DATA-Frame anhängen (für GET-Requests)
    auto data_frame = create_frame(Http3FrameType::DATA, {});
    
    // 4. Frames zur Anfrage hinzufügen
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
std::vector<uint8_t> Http3Masquerading::create_headers_frame(const std::vector<Http3Header>& headers) {
    // 1. Header mit QPACK codieren
    auto encoded_headers = qpack_encoder_->encode_headers(headers);
    
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
    // Zufallsgenerator für realistische Verzögerungen
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Typische Browser-Verzögerungen zwischen Requests (20-150ms)
    std::uniform_int_distribution<> distrib(20, 150);
    delay_ms = distrib(gen);
}

// Hilfsmethode für Variable-Length Integer Kodierung gemäß HTTP/3
std::vector<uint8_t> Http3Masquerading::encode_varint(uint64_t value) {
    std::vector<uint8_t> encoded;
    
    // HTTP/3 verwendet variable-length integers mit 2^N-1 Byte-Länge
    if (value < 64) {
        // 6-bit Präfix (0)
        encoded.push_back(static_cast<uint8_t>(value));
    } else if (value < 16384) {
        // 14-bit Präfix (01)
        encoded.push_back(static_cast<uint8_t>(0x40 | (value >> 8)));
        encoded.push_back(static_cast<uint8_t>(value & 0xFF));
    } else if (value < 1073741824) {
        // 30-bit Präfix (10)
        encoded.push_back(static_cast<uint8_t>(0x80 | (value >> 24)));
        encoded.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        encoded.push_back(static_cast<uint8_t>(value & 0xFF));
    } else {
        // 62-bit Präfix (11)
        encoded.push_back(static_cast<uint8_t>(0xC0 | (value >> 56)));
        encoded.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        encoded.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        encoded.push_back(static_cast<uint8_t>(value & 0xFF));
    }
    
    return encoded;
}

// Hilfsmethode für Variable-Length Integer Dekodierung gemäß HTTP/3
uint64_t Http3Masquerading::decode_varint(const uint8_t* data, size_t len, size_t& bytes_read) {
    if (len == 0) {
        bytes_read = 0;
        return 0;
    }
    
    uint8_t first_byte = data[0];
    uint8_t prefix = first_byte & 0xC0; // Die ersten 2 Bits extrahieren
    
    if (prefix == 0x00) {
        // 6-bit Präfix (0)
        bytes_read = 1;
        return first_byte & 0x3F;
    } else if (prefix == 0x40) {
        // 14-bit Präfix (01)
        if (len < 2) {
            bytes_read = 0;
            return 0;
        }
        bytes_read = 2;
        return ((static_cast<uint64_t>(first_byte & 0x3F) << 8) |
                 static_cast<uint64_t>(data[1]));
    } else if (prefix == 0x80) {
        // 30-bit Präfix (10)
        if (len < 4) {
            bytes_read = 0;
            return 0;
        }
        bytes_read = 4;
        return ((static_cast<uint64_t>(first_byte & 0x3F) << 24) |
                (static_cast<uint64_t>(data[1]) << 16) |
                (static_cast<uint64_t>(data[2]) << 8) |
                 static_cast<uint64_t>(data[3]));
    } else {
        // 62-bit Präfix (11)
        if (len < 8) {
            bytes_read = 0;
            return 0;
        }
        bytes_read = 8;
        return ((static_cast<uint64_t>(first_byte & 0x3F) << 56) |
                (static_cast<uint64_t>(data[1]) << 48) |
                (static_cast<uint64_t>(data[2]) << 40) |
                (static_cast<uint64_t>(data[3]) << 32) |
                (static_cast<uint64_t>(data[4]) << 24) |
                (static_cast<uint64_t>(data[5]) << 16) |
                (static_cast<uint64_t>(data[6]) << 8) |
                 static_cast<uint64_t>(data[7]));
    }
}

// Generiert realistische HTTP-Headers basierend auf dem Browser-Profil
std::vector<Http3Header> Http3Masquerading::generate_realistic_headers(
    const std::string& host, const std::string& path) {
    
    std::vector<Http3Header> headers;
    
    // Grundlegende Headers für jeden HTTP/3-Request
    headers.push_back({":method", "GET"});
    headers.push_back({":scheme", "https"});
    headers.push_back({":authority", host});
    headers.push_back({":path", path});
    
    // Aktuelle Zeit für Date-Header
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream date_ss;
    date_ss << std::put_time(std::gmtime(&time_t_now), "%a, %d %b %Y %H:%M:%S GMT");
    
    // Browser-spezifische Headers
    if (browser_profile_ == "Chrome_Latest") {
        headers.push_back({"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"});
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"});
        headers.push_back({"accept-encoding", "gzip, deflate, br"});
        headers.push_back({"accept-language", "en-US,en;q=0.9"});
        headers.push_back({"sec-ch-ua", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"91\", \"Google Chrome\";v=\"91\""});
        headers.push_back({"sec-ch-ua-mobile", "?0"});
        headers.push_back({"sec-fetch-dest", "document"});
        headers.push_back({"sec-fetch-mode", "navigate"});
        headers.push_back({"sec-fetch-site", "none"});
        headers.push_back({"sec-fetch-user", "?1"});
    } 
    else if (browser_profile_ == "Firefox_Latest") {
        headers.push_back({"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"});
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"});
        headers.push_back({"accept-encoding", "gzip, deflate, br"});
        headers.push_back({"accept-language", "en-US,en;q=0.5"});
        headers.push_back({"dnt", "1"});
        headers.push_back({"te", "trailers"});
    }
    else if (browser_profile_ == "Safari_Latest") {
        headers.push_back({"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"});
        headers.push_back({"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"});
        headers.push_back({"accept-encoding", "gzip, deflate, br"});
        headers.push_back({"accept-language", "en-US,en;q=0.9"});
    }
    else {
        // Standardprofil, falls keines der bekannten Profile verwendet wird
        headers.push_back({"user-agent", "QuicSand/1.0"});
        headers.push_back({"accept", "*/*"});
    }
    
    // Gemeinsame Header für alle Profile
    headers.push_back({"cache-control", "max-age=0"});
    headers.push_back({"date", date_ss.str()});
    headers.push_back({"upgrade-insecure-requests", "1"});
    
    return headers;
}

// QPACK-Encoder-Implementierung
std::vector<uint8_t> Http3Masquerading::QpackEncoder::encode_headers(
    const std::vector<Http3Header>& headers) {
    
    // In dieser vereinfachten Implementierung erstellen wir ein einfaches binäres Format,
    // das die tatsächliche QPACK-Kompression simuliert
    
    std::vector<uint8_t> encoded;
    
    // QPACK-Header - vereinfachte Version
    // Die ersten beiden Bytes sind die Required Insert Count (0) und Base (0)
    encoded.push_back(0x00); // Required Insert Count
    encoded.push_back(0x00); // Base
    
    // Für jeden Header den Namen und Wert encodieren
    for (const auto& header : headers) {
        // Präfix für literale Header-Felder (in dieser vereinfachten Version)
        encoded.push_back(0x20); // Literal Header Field With Name Reference
        
        // Name-Länge und Name
        encoded.push_back(static_cast<uint8_t>(header.name.size()));
        encoded.insert(encoded.end(), header.name.begin(), header.name.end());
        
        // Wert-Länge und Wert
        encoded.push_back(static_cast<uint8_t>(header.value.size()));
        encoded.insert(encoded.end(), header.value.begin(), header.value.end());
    }
    
    return encoded;
}

// QPACK-Decoder-Implementierung
std::vector<Http3Header> Http3Masquerading::QpackEncoder::decode_headers(
    const std::vector<uint8_t>& encoded) {
    
    // In dieser vereinfachten Implementierung decodieren wir das einfache binäre Format,
    // das wir in encode_headers erstellt haben
    
    std::vector<Http3Header> headers;
    
    if (encoded.size() < 2) {
        // Ungültige Eingabe - zu kurz für Required Insert Count und Base
        return headers;
    }
    
    // Die ersten beiden Bytes (Required Insert Count und Base) überspringen
    size_t offset = 2;
    
    // Headers dekodieren
    while (offset < encoded.size()) {
        // Präfix für literales Header-Feld überspringen
        offset++;
        
        if (offset >= encoded.size()) break;
        
        // Name-Länge und Name
        uint8_t name_length = encoded[offset++];
        if (offset + name_length > encoded.size()) break;
        
        std::string name(encoded.begin() + offset, encoded.begin() + offset + name_length);
        offset += name_length;
        
        if (offset >= encoded.size()) break;
        
        // Wert-Länge und Wert
        uint8_t value_length = encoded[offset++];
        if (offset + value_length > encoded.size()) break;
        
        std::string value(encoded.begin() + offset, encoded.begin() + offset + value_length);
        offset += value_length;
        
        // Header zur Liste hinzufügen
        headers.push_back({name, value});
    }
    
    return headers;
}

} // namespace quicsand
