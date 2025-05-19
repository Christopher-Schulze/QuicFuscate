#include "../stealth/sni_hiding.hpp"
#include <vector>
#include <string>
#include <iostream>
#include <cassert>
#include <iomanip>

using namespace quicsand::stealth;

// Hilfsfunktion zum Generieren eines einfachen TLS ClientHello-Pakets mit SNI
std::vector<uint8_t> create_client_hello_with_sni(const std::string& sni_value) {
    // TLS Record Header (5 Bytes)
    std::vector<uint8_t> client_hello = {
        0x16,                   // ContentType: Handshake (22)
        0x03, 0x01,             // Version: TLS 1.0 (für ClientHello)
        0x00, 0x00              // Length: wird später aktualisiert
    };
    
    // Handshake Header (4 Bytes)
    std::vector<uint8_t> handshake = {
        0x01,                   // HandshakeType: ClientHello (1)
        0x00, 0x00, 0x00        // Length: wird später aktualisiert
    };
    
    // ClientHello Körper
    std::vector<uint8_t> hello_body = {
        0x03, 0x03,             // ClientVersion: TLS 1.2
        // Random (32 Bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x00,                   // SessionID Length: 0
        0x00, 0x04,             // CipherSuites Length: 4
        0x00, 0x01,             // CipherSuite: TLS_RSA_WITH_NULL_MD5
        0x00, 0x02,             // CipherSuite: TLS_RSA_WITH_NULL_SHA
        0x01,                   // CompressionMethods Length: 1
        0x00,                   // CompressionMethod: null
        0x00, 0x00              // Extensions Length: wird später aktualisiert
    };
    
    // SNI Extension
    std::vector<uint8_t> sni_extension = {
        0x00, 0x00,             // Extension Type: server_name (0)
        0x00, 0x00,             // Extension Length: wird später aktualisiert
        0x00, 0x00,             // Server Name List Length: wird später aktualisiert
        0x00,                   // Server Name Type: host_name (0)
        0x00, 0x00              // Server Name Length: wird später aktualisiert
    };
    
    // SNI-Wert hinzufügen
    sni_extension.insert(sni_extension.end(), sni_value.begin(), sni_value.end());
    
    // SNI-Längen aktualisieren
    uint16_t sni_length = sni_value.length();
    sni_extension[9] = (sni_length >> 8) & 0xFF;
    sni_extension[10] = sni_length & 0xFF;
    
    uint16_t list_length = sni_length + 3; // 1 Byte Typ + 2 Bytes Länge
    sni_extension[5] = (list_length >> 8) & 0xFF;
    sni_extension[6] = list_length & 0xFF;
    
    uint16_t ext_length = list_length + 2; // 2 Bytes List-Länge
    sni_extension[3] = (ext_length >> 8) & 0xFF;
    sni_extension[4] = ext_length & 0xFF;
    
    // Extensions Length aktualisieren
    uint16_t extensions_length = sni_extension.size();
    hello_body[hello_body.size() - 2] = (extensions_length >> 8) & 0xFF;
    hello_body[hello_body.size() - 1] = extensions_length & 0xFF;
    
    // ClientHello zusammenbauen
    handshake.insert(handshake.end(), hello_body.begin(), hello_body.end());
    handshake.insert(handshake.end(), sni_extension.begin(), sni_extension.end());
    
    // Handshake-Länge aktualisieren
    uint32_t handshake_length = handshake.size() - 4; // 4 Bytes Header abziehen
    handshake[1] = (handshake_length >> 16) & 0xFF;
    handshake[2] = (handshake_length >> 8) & 0xFF;
    handshake[3] = handshake_length & 0xFF;
    
    // Record-Länge aktualisieren
    uint16_t record_length = handshake.size();
    client_hello[3] = (record_length >> 8) & 0xFF;
    client_hello[4] = record_length & 0xFF;
    
    // Record und Handshake zusammenfügen
    client_hello.insert(client_hello.end(), handshake.begin(), handshake.end());
    
    return client_hello;
}

// Hilfsfunktion zum Extrahieren des SNI-Werts aus einem ClientHello-Paket
std::optional<std::string> extract_sni_from_client_hello(const std::vector<uint8_t>& client_hello) {
    // Suche nach der SNI-Extension
    const uint8_t SNI_EXTENSION_TYPE[] = {0x00, 0x00}; // server_name (0)
    
    // Überspringe TLS Record Header (5 Bytes) und Handshake Header (4 Bytes)
    size_t pos = 9;
    
    // Überspringe ClientVersion (2 Bytes), Random (32 Bytes), und SessionID
    pos += 2 + 32;
    if (pos >= client_hello.size()) return std::nullopt;
    
    // SessionID Length
    uint8_t session_id_length = client_hello[pos];
    pos += 1 + session_id_length;
    if (pos + 2 > client_hello.size()) return std::nullopt;
    
    // CipherSuites Length
    uint16_t cipher_suites_length = (client_hello[pos] << 8) | client_hello[pos + 1];
    pos += 2 + cipher_suites_length;
    if (pos + 1 > client_hello.size()) return std::nullopt;
    
    // CompressionMethods Length
    uint8_t compression_methods_length = client_hello[pos];
    pos += 1 + compression_methods_length;
    if (pos + 2 > client_hello.size()) return std::nullopt;
    
    // Extensions Length
    uint16_t extensions_length = (client_hello[pos] << 8) | client_hello[pos + 1];
    pos += 2;
    
    // Suche nach der SNI-Extension
    const size_t extensions_end = pos + extensions_length;
    while (pos + 4 <= extensions_end) {
        // Extension Type
        if (client_hello[pos] == SNI_EXTENSION_TYPE[0] && client_hello[pos + 1] == SNI_EXTENSION_TYPE[1]) {
            // SNI-Extension gefunden
            pos += 2;
            
            // Extension Length
            uint16_t extension_length = (client_hello[pos] << 8) | client_hello[pos + 1];
            pos += 2;
            
            if (pos + extension_length > client_hello.size()) return std::nullopt;
            
            // Server Name List Length
            uint16_t list_length = (client_hello[pos] << 8) | client_hello[pos + 1];
            pos += 2;
            
            if (list_length == 0) return std::nullopt;
            
            // Server Name Type
            if (client_hello[pos] != 0x00) return std::nullopt; // Nur host_name wird unterstützt
            pos += 1;
            
            // Server Name Length
            uint16_t name_length = (client_hello[pos] << 8) | client_hello[pos + 1];
            pos += 2;
            
            if (pos + name_length > client_hello.size()) return std::nullopt;
            
            // Server Name
            return std::string(client_hello.begin() + pos, client_hello.begin() + pos + name_length);
        }
        
        // Nächste Extension
        pos += 2;
        uint16_t extension_length = (client_hello[pos] << 8) | client_hello[pos + 1];
        pos += 2 + extension_length;
    }
    
    return std::nullopt;
}

// Hilfsfunktion zum Anzeigen von Daten im Hexadezimal-Format
void print_hex(const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

// Test 1: Überprüfe, ob SNI_SPLIT korrekt funktioniert
void test_sni_split_basic() {
    std::cout << "Test 1: Grundlegende SNI-Split-Funktionalität" << std::endl;
    
    // Erstelle ein SniHiding-Objekt mit aktiviertem SNI-Split
    SniConfig config;
    config.enable_sni_split = true;
    SniHiding sni_hiding(config);
    
    // Erstelle ein ClientHello-Paket mit SNI
    std::string sni_value = "example.com";
    auto client_hello = create_client_hello_with_sni(sni_value);
    
    // Extrahiere den ursprünglichen SNI-Wert
    auto original_sni = extract_sni_from_client_hello(client_hello);
    
    std::cout << "Ursprünglicher SNI: ";
    if (original_sni) {
        std::cout << *original_sni << std::endl;
    } else {
        std::cout << "Nicht gefunden!" << std::endl;
        assert(false);
    }
    
    // Wende SNI-Split an
    auto modified_hello = sni_hiding.process_client_hello(client_hello);
    
    // Überprüfe, ob das modifizierte Paket gültig ist und ein SNI enthält
    auto modified_sni = extract_sni_from_client_hello(modified_hello);
    
    std::cout << "Modifizierter SNI: ";
    if (modified_sni) {
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        bool contains_null = false;
        for (char c : *modified_sni) {
            if (c == '\0') {
                contains_null = true;
                break;
            }
        }
        
        // Drucke mit Hex-Darstellung für Null-Bytes
        for (char c : *modified_sni) {
            if (c == '\0') {
                std::cout << "\\0";
            } else {
                std::cout << c;
            }
        }
        std::cout << std::endl;
        
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        assert(contains_null);
        
        // Der modifizierte SNI sollte länger sein als der ursprüngliche
        assert(modified_sni->length() > original_sni->length());
        
        // Der erste Teil des SNI sollte noch immer der ursprüngliche sein
        size_t split_pos = modified_sni->find('\0');
        assert(modified_sni->substr(0, split_pos) == original_sni->substr(0, split_pos));
        
        std::cout << "SNI-Split erfolgreich angewendet." << std::endl;
    } else {
        std::cout << "Fehler: SNI nicht gefunden nach Anwendung von SNI-Split!" << std::endl;
        assert(false);
    }
}

// Test 2: Überprüfe, ob SNI_SPLIT mit verschiedenen SNI-Längen funktioniert
void test_sni_split_different_lengths() {
    std::cout << "\nTest 2: SNI-Split mit verschiedenen SNI-Längen" << std::endl;
    
    SniConfig config;
    config.enable_sni_split = true;
    SniHiding sni_hiding(config);
    
    // Teste verschiedene SNI-Längen
    std::vector<std::string> sni_values = {
        "a.com",                    // Kurz (5 Zeichen)
        "subdomain.example.com",    // Mittel (22 Zeichen)
        "very-long-subdomain.very-long-domain-name.very-long-tld" // Lang (55 Zeichen)
    };
    
    for (const auto& sni : sni_values) {
        std::cout << "Teste SNI: " << sni << " (Länge: " << sni.length() << ")" << std::endl;
        
        auto client_hello = create_client_hello_with_sni(sni);
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        auto original_sni = extract_sni_from_client_hello(client_hello);
        auto modified_sni = extract_sni_from_client_hello(modified_hello);
        
        assert(original_sni.has_value());
        assert(modified_sni.has_value());
        
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        bool contains_null = false;
        for (char c : *modified_sni) {
            if (c == '\0') {
                contains_null = true;
                break;
            }
        }
        
        assert(contains_null);
        
        // Der Split sollte etwa in der Mitte erfolgen
        size_t split_pos = modified_sni->find('\0');
        size_t expected_split = sni.length() / 2;
        
        std::cout << "  Split-Position: " << split_pos << " (erwartet ca. " << expected_split << ")" << std::endl;
        
        // Erlaube eine kleine Abweichung
        assert(split_pos >= expected_split - 1 && split_pos <= expected_split + 1);
        
        std::cout << "  Test bestanden." << std::endl;
    }
}

// Test 3: Überprüfe die Interaktion zwischen SNI_SPLIT und anderen Techniken
void test_sni_split_with_other_techniques() {
    std::cout << "\nTest 3: SNI-Split mit anderen Techniken kombiniert" << std::endl;
    
    // Test mit SNI_SPLIT + SNI_PADDING
    {
        std::cout << "Test mit SNI_SPLIT + SNI_PADDING:" << std::endl;
        
        SniConfig config;
        config.enable_sni_split = true;
        config.enable_sni_padding = true;
        SniHiding sni_hiding(config);
        
        std::string sni_value = "example.com";
        auto client_hello = create_client_hello_with_sni(sni_value);
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        auto original_sni = extract_sni_from_client_hello(client_hello);
        auto modified_sni = extract_sni_from_client_hello(modified_hello);
        
        assert(original_sni.has_value());
        assert(modified_sni.has_value());
        
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        bool contains_null = false;
        for (char c : *modified_sni) {
            if (c == '\0') {
                contains_null = true;
                break;
            }
        }
        
        assert(contains_null);
        
        // Durch Padding sollte der SNI noch länger sein
        assert(modified_sni->length() > original_sni->length() + 1);
        
        std::cout << "  Ursprüngliche SNI-Länge: " << original_sni->length() << std::endl;
        std::cout << "  Modifizierte SNI-Länge: " << modified_sni->length() << std::endl;
        std::cout << "  Test bestanden." << std::endl;
    }
    
    // Test mit SNI_SPLIT und DOMAIN_FRONTING
    {
        std::cout << "Test mit SNI_SPLIT und DOMAIN_FRONTING:" << std::endl;
        
        SniConfig config;
        config.enable_sni_split = true;
        config.enable_domain_fronting = true;
        config.front_domain = "front-domain.com";
        config.real_domain = "real-domain.com";
        SniHiding sni_hiding(config);
        
        // Verwende die reale Domain im ClientHello
        auto client_hello = create_client_hello_with_sni("real-domain.com");
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        auto modified_sni = extract_sni_from_client_hello(modified_hello);
        
        assert(modified_sni.has_value());
        
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        bool contains_null = false;
        for (char c : *modified_sni) {
            if (c == '\0') {
                contains_null = true;
                break;
            }
        }
        
        assert(contains_null);
        
        // Der SNI sollte mit der Front-Domain beginnen
        assert(modified_sni->find("front-domain.com") != std::string::npos);
        
        std::cout << "  Test bestanden." << std::endl;
    }
}

// Test 4: Überprüfe die Robustheit der SNI-Split-Implementierung
void test_sni_split_robustness() {
    std::cout << "\nTest 4: Robustheit der SNI-Split-Implementierung" << std::endl;
    
    SniConfig config;
    config.enable_sni_split = true;
    SniHiding sni_hiding(config);
    
    // Test mit leerem SNI
    {
        std::cout << "Test mit leerem SNI:" << std::endl;
        
        auto client_hello = create_client_hello_with_sni("");
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        // Die Implementierung sollte nicht abstürzen
        std::cout << "  Test bestanden (keine Abstürze)." << std::endl;
    }
    
    // Test mit SNI, der bereits ein Null-Byte enthält
    {
        std::cout << "Test mit SNI, der bereits ein Null-Byte enthält:" << std::endl;
        
        std::string sni_value = "example\0.com";
        auto client_hello = create_client_hello_with_sni(std::string(sni_value.c_str(), 12));
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        // Die Implementierung sollte nicht abstürzen
        std::cout << "  Test bestanden (keine Abstürze)." << std::endl;
    }
    
    // Test mit SNI, der Sonderzeichen enthält
    {
        std::cout << "Test mit SNI, der Sonderzeichen enthält:" << std::endl;
        
        std::string sni_value = "special-chars!@#$%^&*().com";
        auto client_hello = create_client_hello_with_sni(sni_value);
        auto modified_hello = sni_hiding.process_client_hello(client_hello);
        
        auto modified_sni = extract_sni_from_client_hello(modified_hello);
        
        assert(modified_sni.has_value());
        
        // Der modifizierte SNI sollte ein Null-Byte enthalten
        bool contains_null = false;
        for (char c : *modified_sni) {
            if (c == '\0') {
                contains_null = true;
                break;
            }
        }
        
        assert(contains_null);
        
        std::cout << "  Test bestanden." << std::endl;
    }
}

// Hauptfunktion
int main() {
    std::cout << "=== SNI-Split-Tests ===" << std::endl;
    
    // Führe alle Tests aus
    test_sni_split_basic();
    test_sni_split_different_lengths();
    test_sni_split_with_other_techniques();
    test_sni_split_robustness();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    
    return 0;
}
