/**
 * http3_masquerading_simple_test.cpp
 * 
 * Einfacher Test für die HTTP/3-Masquerading-Funktionalität ohne externe Testbibliotheken.
 */

#include "../stealth/http3_masquerading.hpp"
#include "../core/quic_packet.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <cassert>
#include <vector>
#include <map>

using namespace quicsand;

// Hilfsfunktion zum Ausgeben von Ergebnissen
void log_result(const std::string& test_name, bool success) {
    std::cout << "Test '" << test_name << "': " << (success ? "PASSED" : "FAILED") << std::endl;
}

// Test: Korrekte Erzeugung eines HTTP/3-Frames
bool test_create_frame() {
    Http3Masquerading masquerading;
    
    // Einfachen DATA-Frame erstellen
    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto frame = masquerading.create_frame(Http3FrameType::DATA, payload);
    
    // Frame sollte nicht leer sein
    if (frame.empty()) {
        std::cerr << "  Fehler: Frame ist leer" << std::endl;
        return false;
    }
    
    // Erstes Byte sollte der Frame-Typ sein (DATA = 0x00)
    if (static_cast<uint8_t>(Http3FrameType::DATA) != frame[0]) {
        std::cerr << "  Fehler: Falscher Frame-Typ" << std::endl;
        return false;
    }
    
    // Die Frame-Größe sollte größer sein als die Payload-Größe (wegen Header)
    if (frame.size() <= payload.size()) {
        std::cerr << "  Fehler: Frame-Größe ist nicht größer als Payload-Größe" << std::endl;
        return false;
    }
    
    // Die Extrahierung von Frames sollte funktionieren
    std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>> extracted_frames;
    bool success = masquerading.extract_frames(frame, extracted_frames);
    
    if (!success) {
        std::cerr << "  Fehler: Frame-Extraktion fehlgeschlagen" << std::endl;
        return false;
    }
    
    if (extracted_frames.size() != 1) {
        std::cerr << "  Fehler: Falsche Anzahl extrahierter Frames: "
                  << extracted_frames.size() << std::endl;
        return false;
    }
    
    if (extracted_frames[0].first != Http3FrameType::DATA) {
        std::cerr << "  Fehler: Falscher extrahierter Frame-Typ" << std::endl;
        return false;
    }
    
    if (extracted_frames[0].second != payload) {
        std::cerr << "  Fehler: Extrahierte Payload stimmt nicht mit Original überein" << std::endl;
        return false;
    }
    
    return true;
}

// Test: Korrekte Erzeugung einer HTTP/3-Anfrage
bool test_create_request() {
    Http3Masquerading masquerading;
    
    // HTTP/3-Anfrage erstellen
    std::string host = "example.com";
    std::string path = "/index.html";
    auto request = masquerading.create_http3_request(host, path);
    
    // Request sollte nicht leer sein
    if (request.empty()) {
        std::cerr << "  Fehler: Request ist leer" << std::endl;
        return false;
    }
    
    // Die Extrahierung von Frames sollte funktionieren
    std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>> extracted_frames;
    bool success = masquerading.extract_frames(request, extracted_frames);
    
    if (!success) {
        std::cerr << "  Fehler: Frame-Extraktion fehlgeschlagen" << std::endl;
        return false;
    }
    
    // Eine Anfrage sollte mindestens einen Frame enthalten
    if (extracted_frames.empty()) {
        std::cerr << "  Fehler: Keine Frames in der Anfrage gefunden" << std::endl;
        return false;
    }
    
    // Der erste Frame sollte ein HEADERS-Frame sein
    if (extracted_frames[0].first != Http3FrameType::HEADERS) {
        std::cerr << "  Fehler: Erster Frame ist kein HEADERS-Frame" << std::endl;
        return false;
    }
    
    return true;
}

// Test: Prozessierung von Paketen
bool test_process_packets() {
    Http3Masquerading masquerading;
    
    // Ein QUIC Initial-Paket erstellen
    auto packet = std::make_shared<QuicPacket>();
    packet->set_packet_type(PacketType::INITIAL);
    
    // Einfache Payload setzen
    std::vector<uint8_t> payload = {'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a'};
    packet->set_payload(payload);
    
    // Größe vor Prozessierung merken
    size_t original_size = packet->payload().size();
    
    // Paket prozessieren
    bool success = masquerading.process_outgoing_packet(packet);
    
    // Prozessierung sollte erfolgreich sein
    if (!success) {
        std::cerr << "  Fehler: Paket-Prozessierung fehlgeschlagen" << std::endl;
        return false;
    }
    
    // Die neue Payload sollte länger sein als die ursprüngliche (wegen HTTP/3-Headers)
    if (packet->payload().size() <= original_size) {
        std::cerr << "  Fehler: Prozessierte Payload ist nicht größer als das Original" << std::endl;
        return false;
    }
    
    // Entgegengesetzte Richtung testen
    auto incoming_packet = std::make_shared<QuicPacket>(*packet);
    success = masquerading.process_incoming_packet(incoming_packet);
    
    // Prozessierung sollte erfolgreich sein
    if (!success) {
        std::cerr << "  Fehler: Eingehende Paket-Prozessierung fehlgeschlagen" << std::endl;
        return false;
    }
    
    return true;
}

// Test: Verschiedene Browser-Profile
bool test_browser_profiles() {
    Http3Masquerading masquerading;
    
    // Standard-Browser-Profil prüfen
    std::string host = "example.com";
    std::string path = "/index.html";
    
    // Chrome-Profil (Standard)
    auto chrome_request = masquerading.create_http3_request(host, path);
    
    // Auf Firefox wechseln
    masquerading.set_browser_profile("Firefox_Latest");
    if (masquerading.get_browser_profile() != "Firefox_Latest") {
        std::cerr << "  Fehler: Browser-Profil wurde nicht korrekt gesetzt" << std::endl;
        return false;
    }
    
    auto firefox_request = masquerading.create_http3_request(host, path);
    
    // Auf Safari wechseln
    masquerading.set_browser_profile("Safari_Latest");
    if (masquerading.get_browser_profile() != "Safari_Latest") {
        std::cerr << "  Fehler: Browser-Profil wurde nicht korrekt gesetzt" << std::endl;
        return false;
    }
    
    auto safari_request = masquerading.create_http3_request(host, path);
    
    // Die Anfragen sollten unterschiedlich sein
    if (chrome_request == firefox_request || chrome_request == safari_request || 
        firefox_request == safari_request) {
        std::cerr << "  Fehler: Browser-Profil-Anfragen sind identisch" << std::endl;
        return false;
    }
    
    return true;
}

// Hauptfunktion für den Test
int main() {
    std::cout << "===== HTTP/3 Masquerading Simple Test =====" << std::endl;
    
    int passed = 0;
    int total = 0;
    
    // Test 1: Frame-Erzeugung
    total++;
    bool result = test_create_frame();
    log_result("Frame-Erzeugung", result);
    if (result) passed++;
    
    // Test 2: Request-Erzeugung
    total++;
    result = test_create_request();
    log_result("Request-Erzeugung", result);
    if (result) passed++;
    
    // Test 3: Paket-Prozessierung
    total++;
    result = test_process_packets();
    log_result("Paket-Prozessierung", result);
    if (result) passed++;
    
    // Test 4: Browser-Profile
    total++;
    result = test_browser_profiles();
    log_result("Browser-Profile", result);
    if (result) passed++;
    
    // Ergebnis ausgeben
    std::cout << "\n===== Testergebnisse =====" << std::endl;
    std::cout << "Bestanden: " << passed << "/" << total << " Tests" << std::endl;
    
    bool all_passed = (passed == total);
    std::cout << "Gesamtstatus: " << (all_passed ? "BESTANDEN" : "FEHLGESCHLAGEN") << std::endl;
    
    return all_passed ? 0 : 1;
}
