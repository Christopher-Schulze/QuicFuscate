/**
 * http3_util.cpp
 * 
 * Hilfsfunktionen für die Stealth-Komponente des QuicSand-Projekts,
 * insbesondere für die HTTP/3-Maskierung des Netzwerkverkehrs.
 */

#include "stealth/http3_masquerading.hpp" 
#include "core/quic_packet.hpp"
#include <iostream>

namespace quicsand {

// Dieses Hilfsmodul implementiert fehlende Symbole, die der Linker bei der
// Kompilierung des Hauptprojekts nicht finden kann. Diese Funktionalität
// wird benötigt, wenn der Stealth-Modus die HTTP/3-Maskierung verwendet.

// Implementierung der HTTP/3-Masquerading-QpackEncoder-Klasse
std::vector<uint8_t> Http3Masquerading::QpackEncoder::encode_headers(
    const std::vector<Http3Header>& headers) {
    
    // Vereinfachte Implementierung der QPACK-Kodierung
    std::vector<uint8_t> result;
    
    // Füge einen Header für die Kodierung hinzu
    result.push_back(0); // Field section prefix byte 1
    result.push_back(0); // Field section prefix byte 2
    
    for (const auto& header : headers) {
        // Kodiere den Header-Namen
        uint8_t name_length = static_cast<uint8_t>(header.name.size());
        result.push_back(name_length);
        result.insert(result.end(), header.name.begin(), header.name.end());
        
        // Kodiere den Header-Wert
        uint8_t value_length = static_cast<uint8_t>(header.value.size());
        result.push_back(value_length);
        result.insert(result.end(), header.value.begin(), header.value.end());
    }
    
    return result;
}

std::vector<Http3Header> Http3Masquerading::QpackEncoder::decode_headers(
    const std::vector<uint8_t>& encoded) {
    
    std::vector<Http3Header> headers;
    size_t pos = 2; // Überspringe den Field section prefix
    
    while (pos < encoded.size()) {
        // Name lesen
        if (pos >= encoded.size()) break;
        uint8_t name_length = encoded[pos++];
        
        if (pos + name_length > encoded.size()) break;
        std::string name(encoded.begin() + pos, encoded.begin() + pos + name_length);
        pos += name_length;
        
        // Wert lesen
        if (pos >= encoded.size()) break;
        uint8_t value_length = encoded[pos++];
        
        if (pos + value_length > encoded.size()) break;
        std::string value(encoded.begin() + pos, encoded.begin() + pos + value_length);
        pos += value_length;
        
        headers.push_back({name, value});
    }
    
    return headers;
}

} // namespace quicsand
