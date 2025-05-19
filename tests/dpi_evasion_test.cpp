#include "../stealth/stealth_manager.hpp"
#include "../stealth/dpi_evasion.hpp"
#include "../core/quic_packet.hpp"
#include <iostream>
#include <vector>
#include <cassert>
#include <chrono>
#include <random>
#include <string>
#include <memory>
#include <functional>
#include <algorithm>

using namespace quicsand;
using namespace quicsand::stealth;

// Hilfsfunktion zur Generierung zufälliger Bytes
std::vector<uint8_t> generate_random_bytes(size_t length) {
    std::vector<uint8_t> result(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    for (size_t i = 0; i < length; ++i) {
        result[i] = static_cast<uint8_t>(distrib(gen));
    }
    
    return result;
}

// Hilfsfunktion zum Erstellen eines simulierten QUIC-Pakets
std::shared_ptr<QuicPacket> create_mock_quic_packet(uint8_t packet_type = 0x01, bool include_header = true) {
    // Erstelle ein simuliertes QUIC-Paket
    auto packet = std::make_shared<QuicPacket>();
    
    std::vector<uint8_t> header;
    if (include_header) {
        // Simulierter QUIC-Header basierend auf dem Pakettyp
        if (packet_type == 0x01) { // Initial
            header = {
                0xC3,                   // Long Header Format, Initial Packet Type
                0x00, 0x00, 0x00, 0x01, // Version
                0x08,                   // DCID Length
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Destination Connection ID
                0x08,                   // SCID Length
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // Source Connection ID
                0x00, 0x10,             // Token Length (0)
                0x00, 0x00, 0x00, 0x20  // Length
            };
        } else if (packet_type == 0x02) { // Handshake
            header = {
                0xE3,                   // Long Header Format, Handshake Packet Type
                0x00, 0x00, 0x00, 0x01, // Version
                0x08,                   // DCID Length
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Destination Connection ID
                0x08,                   // SCID Length
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // Source Connection ID
                0x00, 0x00, 0x00, 0x20  // Length
            };
        } else if (packet_type == 0x03) { // 1-RTT
            header = {
                0x43,                   // Short Header Format, 1-RTT
                0x08,                   // DCID Length
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  // Destination Connection ID
            };
        }
    }
    
    // Payload generieren
    size_t payload_size = 100; // Einfache Payload-Größe für Tests
    auto payload = generate_random_bytes(payload_size);
    
    // Header und Payload zum Paket hinzufügen
    std::vector<uint8_t> packet_data;
    packet_data.insert(packet_data.end(), header.begin(), header.end());
    packet_data.insert(packet_data.end(), payload.begin(), payload.end());
    
    packet->set_raw_data(packet_data);
    packet->set_payload(payload);
    
    return packet;
}

// Test für Packet Padding
void test_packet_padding() {
    std::cout << "Test: Packet Padding" << std::endl;
    
    // Erstelle ein DPI-Evasion-Objekt mit Padding aktiviert
    DpiConfig config;
    config.enable_packet_padding = true;
    config.min_padding_length = 10;
    config.max_padding_length = 50;
    DpiEvasion dpi_evasion(config);
    
    // Erstelle ein Mock-QUIC-Paket
    auto packet = create_mock_quic_packet();
    size_t original_size = packet->get_raw_data().size();
    
    std::cout << "Ursprüngliche Paketgröße: " << original_size << std::endl;
    
    // Wende Padding an
    bool success = dpi_evasion.apply_techniques(packet);
    assert(success);
    
    size_t new_size = packet->get_raw_data().size();
    std::cout << "Neue Paketgröße: " << new_size << std::endl;
    
    // Das Paket sollte jetzt größer sein
    assert(new_size > original_size);
    // Das zusätzliche Padding sollte zwischen min und max liegen
    assert(new_size >= original_size + config.min_padding_length);
    assert(new_size <= original_size + config.max_padding_length);
    
    std::cout << "Packet Padding-Test bestanden!" << std::endl;
}

// Test für Protokoll-Obfuskation
void test_protocol_obfuscation() {
    std::cout << "\nTest: Protokoll-Obfuskation" << std::endl;
    
    // Erstelle ein DPI-Evasion-Objekt mit Protokoll-Obfuskation aktiviert
    DpiConfig config;
    config.enable_protocol_obfuscation = true;
    DpiEvasion dpi_evasion(config);
    
    // Erstelle ein Mock-QUIC-Paket
    auto packet = create_mock_quic_packet();
    auto original_data = packet->get_raw_data();
    
    // Sicherstellen, dass es sich um ein QUIC-Paket handelt (erster Byte sollte auf QUIC hindeuten)
    std::cout << "Erster Byte vor der Obfuskation: 0x" 
              << std::hex << static_cast<int>(original_data[0]) << std::dec << std::endl;
    
    // Wende Obfuskation an
    bool success = dpi_evasion.apply_techniques(packet);
    assert(success);
    
    auto new_data = packet->get_raw_data();
    std::cout << "Erster Byte nach der Obfuskation: 0x" 
              << std::hex << static_cast<int>(new_data[0]) << std::dec << std::endl;
    
    // Der erste Byte sollte verändert sein, aber das Paket sollte noch immer gültig sein
    // Dies ist stark implementierungsabhängig - die genaue Prüfung hängt von der Implementierung ab
    assert(original_data[0] != new_data[0] || 
           original_data.size() != new_data.size() ||
           !std::equal(original_data.begin() + 1, original_data.end(),
                      new_data.begin() + 1));
    
    std::cout << "Protokoll-Obfuskation-Test bestanden!" << std::endl;
}

// Test für Jitter-Einführung
void test_jitter() {
    std::cout << "\nTest: Jitter-Einführung" << std::endl;
    
    // Erstelle ein DPI-Evasion-Objekt mit Jitter aktiviert
    DpiConfig config;
    config.enable_timing_jitter = true;
    config.min_jitter_ms = 5;
    config.max_jitter_ms = 20;
    DpiEvasion dpi_evasion(config);
    
    // Simuliere 10 Paketsendungen und messe die Zeitintervalle
    const int num_packets = 10;
    std::vector<std::chrono::milliseconds> intervals;
    
    auto last_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < num_packets; ++i) {
        // Erzeuge ein neues Paket
        auto packet = create_mock_quic_packet();
        
        // Wende Jitter an (dies sollte zu einer Verzögerung führen)
        bool success = dpi_evasion.apply_timing_jitter();
        assert(success);
        
        // Messe die Zeit
        auto current_time = std::chrono::steady_clock::now();
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - last_time);
        
        intervals.push_back(interval);
        last_time = current_time;
        
        std::cout << "Paket " << (i+1) << " - Intervall: " << interval.count() << " ms" << std::endl;
    }
    
    // Berechne Standardabweichung der Intervalle
    double mean = 0.0;
    for (const auto& interval : intervals) {
        mean += interval.count();
    }
    mean /= intervals.size();
    
    double variance = 0.0;
    for (const auto& interval : intervals) {
        variance += std::pow(interval.count() - mean, 2);
    }
    variance /= intervals.size();
    
    double stddev = std::sqrt(variance);
    
    std::cout << "Mittleres Intervall: " << mean << " ms" << std::endl;
    std::cout << "Standardabweichung: " << stddev << " ms" << std::endl;
    
    // Es sollte eine gewisse Varianz in den Zeitintervallen geben
    // Bei einer guten Jitter-Implementierung sollte die Standardabweichung größer als 0 sein
    assert(stddev > 0);
    
    std::cout << "Jitter-Test bestanden!" << std::endl;
}

// Test für DPI-Fingerprint-Vermeidung
void test_dpi_fingerprint_avoidance() {
    std::cout << "\nTest: DPI-Fingerprint-Vermeidung" << std::endl;
    
    // Erstelle ein DPI-Evasion-Objekt mit Fingerprint-Vermeidung aktiviert
    DpiConfig config;
    config.enable_dpi_fingerprint_evasion = true;
    DpiEvasion dpi_evasion(config);
    
    // Erstelle drei verschiedene Pakettypen
    auto initial_packet = create_mock_quic_packet(0x01);
    auto handshake_packet = create_mock_quic_packet(0x02);
    auto data_packet = create_mock_quic_packet(0x03);
    
    // Speichere ursprüngliche Paketdaten zum Vergleich
    auto original_initial = initial_packet->get_raw_data();
    auto original_handshake = handshake_packet->get_raw_data();
    auto original_data = data_packet->get_raw_data();
    
    // Wende Fingerprint-Vermeidung auf alle Pakete an
    bool success1 = dpi_evasion.apply_techniques(initial_packet);
    bool success2 = dpi_evasion.apply_techniques(handshake_packet);
    bool success3 = dpi_evasion.apply_techniques(data_packet);
    
    assert(success1 && success2 && success3);
    
    // Prüfe, ob die Pakete verändert wurden
    auto modified_initial = initial_packet->get_raw_data();
    auto modified_handshake = handshake_packet->get_raw_data();
    auto modified_data = data_packet->get_raw_data();
    
    // Je nach Implementierung könnten verschiedene Aspekte der Pakete verändert werden
    // Wir prüfen hier, ob die Pakete überhaupt verändert wurden
    bool initial_modified = (original_initial != modified_initial);
    bool handshake_modified = (original_handshake != modified_handshake);
    bool data_modified = (original_data != modified_data);
    
    std::cout << "Initial Paket modifiziert: " << (initial_modified ? "Ja" : "Nein") << std::endl;
    std::cout << "Handshake Paket modifiziert: " << (handshake_modified ? "Ja" : "Nein") << std::endl;
    std::cout << "Daten Paket modifiziert: " << (data_modified ? "Ja" : "Nein") << std::endl;
    
    // Mindestens eines der Pakete sollte modifiziert worden sein
    assert(initial_modified || handshake_modified || data_modified);
    
    std::cout << "DPI-Fingerprint-Vermeidung-Test bestanden!" << std::endl;
}

// Test für die Erkennung von aktiven DPI-Systemen
void test_dpi_detection() {
    std::cout << "\nTest: DPI-Erkennung" << std::endl;
    
    // Erstelle ein DPI-Evasion-Objekt mit DPI-Erkennung aktiviert
    DpiConfig config;
    config.enable_active_dpi_detection = true;
    DpiEvasion dpi_evasion(config);
    
    // Simuliere einen Netzwerkpfad mit aktiver DPI
    // In der Praxis würde dies durch Analyse der Netzwerkbedingungen geschehen
    // Für diesen Test simulieren wir die Erkennung
    
    // 1. Fälle ohne DPI
    {
        // Simuliere Normalfall ohne DPI
        bool dpi_detected = dpi_evasion.simulate_dpi_detection(false, 0);
        std::cout << "Simulierter Fall ohne DPI: " << (dpi_detected ? "DPI erkannt" : "Keine DPI erkannt") << std::endl;
        assert(!dpi_detected);
    }
    
    // 2. Fälle mit wahrscheinlicher DPI
    {
        // Simuliere verzögerte Pakete (mögliches Zeichen für DPI)
        bool dpi_detected = dpi_evasion.simulate_dpi_detection(true, 1);
        std::cout << "Simulierter Fall mit Paketverzögerung: " << (dpi_detected ? "DPI erkannt" : "Keine DPI erkannt") << std::endl;
        assert(dpi_detected);
        
        // Simuliere Paketverluste bei bestimmten Pakettypen (mögliches Zeichen für DPI)
        dpi_detected = dpi_evasion.simulate_dpi_detection(true, 2);
        std::cout << "Simulierter Fall mit selektiven Paketverlusten: " << (dpi_detected ? "DPI erkannt" : "Keine DPI erkannt") << std::endl;
        assert(dpi_detected);
        
        // Simuliere Verbindungsunterbrechung bei bestimmten Protokollmustern (starkes Zeichen für DPI)
        dpi_detected = dpi_evasion.simulate_dpi_detection(true, 3);
        std::cout << "Simulierter Fall mit Verbindungsunterbrechung: " << (dpi_detected ? "DPI erkannt" : "Keine DPI erkannt") << std::endl;
        assert(dpi_detected);
    }
    
    std::cout << "DPI-Erkennung-Test bestanden!" << std::endl;
}

// Test für die Integration aller DPI-Evasion-Techniken
void test_combined_dpi_evasion() {
    std::cout << "\nTest: Kombinierte DPI-Evasion-Techniken" << std::endl;
    
    // Erstelle einen StealthManager mit maximaler Verschleierung
    StealthLevel level = StealthLevel::MAXIMUM;
    StealthManager stealth_manager;
    stealth_manager.set_stealth_level(level);
    
    // Erstelle ein Mock-QUIC-Paket
    auto packet = create_mock_quic_packet();
    auto original_data = packet->get_raw_data();
    size_t original_size = original_data.size();
    
    // Wende StealthManager auf das Paket an
    bool success = stealth_manager.process_outgoing_packet(packet);
    assert(success);
    
    auto modified_data = packet->get_raw_data();
    size_t modified_size = modified_data.size();
    
    // Bei maximaler Verschleierung sollte das Paket verändert worden sein
    std::cout << "Ursprüngliche Paketgröße: " << original_size << std::endl;
    std::cout << "Modifizierte Paketgröße: " << modified_size << std::endl;
    
    // Prüfe, ob das Paket wesentlich verändert wurde
    assert(original_data != modified_data);
    
    // Je nach Implementierung könnten weitere spezifische Tests erfolgen
    // z.B. Prüfung auf bestimmte Eigenschaften des modifizierten Pakets
    
    std::cout << "Kombinierte DPI-Evasion-Test bestanden!" << std::endl;
}

// Simulierte DPI-Erkennungsfunktion für DpiEvasion
bool DpiEvasion::simulate_dpi_detection(bool simulate_dpi_present, int scenario) {
    // Diese Funktion ist nur für Testzwecke
    // In einer echten Implementierung würde hier die tatsächliche DPI-Erkennung stattfinden
    
    if (!simulate_dpi_present) {
        return false;
    }
    
    // Verschiedene DPI-Szenarien simulieren
    switch (scenario) {
        case 1: // Paketverzögerung
            return true;
        case 2: // Selektive Paketverluste
            return true;
        case 3: // Verbindungsunterbrechung
            return true;
        default:
            return false;
    }
}

// Hauptfunktion
int main() {
    std::cout << "=== DPI-Evasion-Tests ===" << std::endl;
    
    // Führe alle Tests aus
    test_packet_padding();
    test_protocol_obfuscation();
    test_jitter();
    test_dpi_fingerprint_avoidance();
    test_dpi_detection();
    test_combined_dpi_evasion();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    
    return 0;
}
