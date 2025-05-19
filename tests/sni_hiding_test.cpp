#include <gtest/gtest.h>
#include "../stealth/sni_hiding.hpp"
#include <vector>
#include <string>
#include <algorithm>
#include <random>

using namespace quicsand::stealth;

// Hilfsfunktion zum Erstellen eines einfachen TLS ClientHello-Pakets mit SNI-Extension
std::vector<uint8_t> create_tls_client_hello_with_sni(const std::string& domain) {
    // TLS Record Header (5 Bytes)
    // Type: Handshake (0x16), Version: TLS 1.2 (0x0303), Length: wird später gesetzt
    std::vector<uint8_t> hello = {
        0x16,                   // Type: Handshake
        0x03, 0x03,             // Version: TLS 1.2
        0x00, 0x00              // Length: wird später gesetzt
    };
    
    // Handshake-Header (4 Bytes)
    // Type: ClientHello (0x01), Length: wird später gesetzt
    hello.push_back(0x01);      // Type: ClientHello
    hello.push_back(0x00);      // Length (3 Bytes): wird später gesetzt
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Client Version (2 Bytes)
    hello.push_back(0x03);      // TLS 1.2
    hello.push_back(0x03);
    
    // Random (32 Bytes)
    for (int i = 0; i < 32; i++) {
        hello.push_back(i);
    }
    
    // Session ID Length (1 Byte) - Kein Session ID
    hello.push_back(0x00);
    
    // Cipher Suites Length (2 Bytes)
    hello.push_back(0x00);
    hello.push_back(0x02);
    
    // Cipher Suite (2 Bytes) - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    hello.push_back(0xC0);
    hello.push_back(0x2F);
    
    // Compression Methods Length (1 Byte)
    hello.push_back(0x01);
    
    // Compression Method (1 Byte) - null
    hello.push_back(0x00);
    
    // Extensions Length (2 Bytes) - wird später gesetzt
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Server Name Indication Extension
    std::vector<uint8_t> sni_extension;
    
    // Extension Type: server_name (0x0000)
    sni_extension.push_back(0x00);
    sni_extension.push_back(0x00);
    
    // Extension Length: wird später gesetzt
    sni_extension.push_back(0x00);
    sni_extension.push_back(0x00);
    
    // Server Name List Length: wird später gesetzt
    sni_extension.push_back(0x00);
    sni_extension.push_back(0x00);
    
    // Server Name Type: host_name (0x00)
    sni_extension.push_back(0x00);
    
    // Server Name Length: wird später gesetzt
    sni_extension.push_back(0x00);
    sni_extension.push_back(0x00);
    
    // Server Name Value
    for (char c : domain) {
        sni_extension.push_back(static_cast<uint8_t>(c));
    }
    
    // Aktualisiere die Server Name Length
    uint16_t domain_length = domain.size();
    sni_extension[7] = (domain_length >> 8) & 0xFF;
    sni_extension[8] = domain_length & 0xFF;
    
    // Aktualisiere die Server Name List Length
    uint16_t list_length = domain_length + 3; // Typ (1) + Länge (2)
    sni_extension[4] = (list_length >> 8) & 0xFF;
    sni_extension[5] = list_length & 0xFF;
    
    // Aktualisiere die Extension Length
    uint16_t extension_length = list_length + 2; // List-Länge (2)
    sni_extension[2] = (extension_length >> 8) & 0xFF;
    sni_extension[3] = extension_length & 0xFF;
    
    // Füge die Extension zum ClientHello hinzu
    hello.insert(hello.end(), sni_extension.begin(), sni_extension.end());
    
    // Aktualisiere die Extensions Length
    uint16_t extensions_length = sni_extension.size();
    size_t extensions_length_offset = hello.size() - extensions_length - 2;
    hello[extensions_length_offset] = (extensions_length >> 8) & 0xFF;
    hello[extensions_length_offset + 1] = extensions_length & 0xFF;
    
    // Aktualisiere die Handshake Length
    uint32_t handshake_length = hello.size() - 9; // Record Header (5) + Handshake Type (1) + Length (3)
    hello[6] = (handshake_length >> 16) & 0xFF;
    hello[7] = (handshake_length >> 8) & 0xFF;
    hello[8] = handshake_length & 0xFF;
    
    // Aktualisiere die Record Length
    uint16_t record_length = hello.size() - 5; // Record Header (5)
    hello[3] = (record_length >> 8) & 0xFF;
    hello[4] = record_length & 0xFF;
    
    return hello;
}

// Hilfsfunktion zum Extrahieren des SNI aus einem TLS ClientHello-Paket
std::string extract_sni_from_client_hello(const std::vector<uint8_t>& client_hello) {
    // Suche nach der SNI-Extension (Typ 0x0000)
    for (size_t i = 0; i < client_hello.size() - 4; i++) {
        if (client_hello[i] == 0x00 && client_hello[i + 1] == 0x00) {
            // Überprüfe, ob es sich um die SNI-Extension handelt
            uint16_t extension_length = (client_hello[i + 2] << 8) | client_hello[i + 3];
            if (i + 4 + extension_length <= client_hello.size()) {
                // Finde den SNI-Wert
                uint16_t list_length = (client_hello[i + 4] << 8) | client_hello[i + 5];
                if (client_hello[i + 6] == 0x00) { // host_name Typ
                    uint16_t sni_length = (client_hello[i + 7] << 8) | client_hello[i + 8];
                    if (i + 9 + sni_length <= client_hello.size()) {
                        return std::string(client_hello.begin() + i + 9, 
                                          client_hello.begin() + i + 9 + sni_length);
                    }
                }
            }
        }
    }
    return "";
}

// Hilfsfunktion zum Finden einer Null-Sequenz in einem Byte-Array
bool contains_null_byte(const std::vector<uint8_t>& data, size_t start_offset) {
    for (size_t i = start_offset; i < data.size(); i++) {
        if (data[i] == 0x00) {
            return true;
        }
    }
    return false;
}

// Test-Fixture für SniHiding-Tests
class SniHidingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Konfiguration mit allen SNI-Hiding-Techniken aktiviert
        config.enable_domain_fronting = true;
        config.enable_sni_omission = true;
        config.enable_sni_padding = true;
        config.enable_sni_split = true;
        config.enable_ech = true;
        config.enable_esni = true;
        
        // Standard-Domain für Tests
        test_domain = "example.com";
        
        // Erstelle Client-Hello-Paket mit SNI
        client_hello = create_tls_client_hello_with_sni(test_domain);
    }
    
    SniConfig config;
    std::string test_domain;
    std::vector<uint8_t> client_hello;
};

// Test 1: Überprüfe die grundlegende Funktionalität des SniHiding-Konstruktors
TEST_F(SniHidingTest, BasicConstructorTest) {
    SniHiding sni_hiding(config);
    
    // Überprüfe, ob alle Techniken korrekt aktiviert wurden
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::DOMAIN_FRONTING));
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::SNI_OMISSION));
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::SNI_PADDING));
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::SNI_SPLIT));
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::ECH));
    EXPECT_TRUE(sni_hiding.is_technique_enabled(SniTechnique::ESNI));
}

// Test 2: SNI-Padding-Test
TEST_F(SniHidingTest, SniPaddingTest) {
    // Erstelle SniHiding-Objekt mit nur SNI-Padding aktiviert
    SniConfig padding_config;
    padding_config.enable_sni_padding = true;
    
    SniHiding sni_hiding(padding_config);
    
    // Verarbeite das Client-Hello-Paket
    std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(client_hello);
    
    // Extrahiere den SNI-Wert aus dem modifizierten Paket
    std::string modified_sni = extract_sni_from_client_hello(modified_hello);
    
    // Überprüfe, ob der SNI-Wert größer als das Original ist (Padding)
    EXPECT_GT(modified_sni.length(), test_domain.length());
    
    // Überprüfe, ob der Original-SNI im modifizierten SNI enthalten ist
    EXPECT_TRUE(modified_sni.find(test_domain) != std::string::npos);
}

// Test 3: SNI-Split-Test
TEST_F(SniHidingTest, SniSplitTest) {
    // Erstelle SniHiding-Objekt mit nur SNI-Split aktiviert
    SniConfig split_config;
    split_config.enable_sni_split = true;
    
    SniHiding sni_hiding(split_config);
    
    // Verarbeite das Client-Hello-Paket
    std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(client_hello);
    
    // Extrahiere den SNI-Wert aus dem modifizierten Paket
    std::string modified_sni = extract_sni_from_client_hello(modified_hello);
    
    // Das modifizierte Paket sollte Null-Bytes enthalten (Split-Marker)
    size_t sni_offset = modified_hello.size() - modified_sni.length() - 10; // Ungefähre Position des SNI
    EXPECT_TRUE(contains_null_byte(modified_hello, sni_offset));
    
    // Überprüfe, ob der SNI-Wert noch immer den Domainnamen enthält (möglicherweise mit Null-Bytes)
    std::string domain_part = test_domain.substr(0, test_domain.length() / 2);
    EXPECT_TRUE(modified_sni.find(domain_part) != std::string::npos);
}

// Test 4: Domain Fronting Test
TEST_F(SniHidingTest, DomainFrontingTest) {
    // Erstelle SniHiding-Objekt mit nur Domain Fronting aktiviert
    SniConfig fronting_config;
    fronting_config.enable_domain_fronting = true;
    
    SniHiding sni_hiding(fronting_config);
    
    // Füge eine Trusted-Front-Domain hinzu
    std::string front_domain = "cloudflare.com";
    sni_hiding.add_trusted_front(front_domain);
    
    // Verarbeite das Client-Hello-Paket
    std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(client_hello);
    
    // Extrahiere den SNI-Wert aus dem modifizierten Paket
    std::string modified_sni = extract_sni_from_client_hello(modified_hello);
    
    // Der SNI-Wert sollte nun die Front-Domain enthalten, nicht die Original-Domain
    EXPECT_EQ(modified_sni, front_domain);
}

// Test 5: ECH und ESNI Tests
TEST_F(SniHidingTest, EncryptedClientHelloTest) {
    // Teste sowohl ECH als auch ESNI
    for (bool use_ech : {true, false}) {
        SniConfig encrypt_config;
        if (use_ech) {
            encrypt_config.enable_ech = true;
        } else {
            encrypt_config.enable_esni = true;
        }
        
        SniHiding sni_hiding(encrypt_config);
        
        // Verarbeite das Client-Hello-Paket
        std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(client_hello);
        
        // Extrahiere den SNI-Wert aus dem modifizierten Paket
        std::string modified_sni = extract_sni_from_client_hello(modified_hello);
        
        // Bei ECH/ESNI sollte der Original-SNI nicht mehr sichtbar sein
        if (!modified_sni.empty()) {
            EXPECT_NE(modified_sni, test_domain);
        }
    }
}

// Test 6: Test aller Techniken zusammen
TEST_F(SniHidingTest, AllTechniquesTest) {
    // Erstelle SniHiding-Objekt mit allen Techniken aktiviert
    SniHiding sni_hiding(config);
    
    // Verarbeite das Client-Hello-Paket
    std::vector<uint8_t> modified_hello = sni_hiding.process_client_hello(client_hello);
    
    // Extrahiere den SNI-Wert aus dem modifizierten Paket
    std::string modified_sni = extract_sni_from_client_hello(modified_hello);
    
    // Der modifizierte SNI sollte nicht mit dem Original-SNI übereinstimmen
    EXPECT_NE(modified_sni, test_domain);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
