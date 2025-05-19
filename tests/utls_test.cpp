#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

#include "../tls/utls_client_configurator.hpp"
#include "../tls/fingerprint_rotator.hpp"
#include "../tls/session_ticket_manager.hpp"

using namespace quicsand;

// Hilfsfunktion für farbige Konsolenausgabe
void print_colored(const std::string& text, int color_code) {
    std::cout << "\033[" << color_code << "m" << text << "\033[0m" << std::endl;
}

void test_basic_utls_configuration() {
    print_colored("=== Test: Basis uTLS Konfiguration ===", 36);
    
    UTLSClientConfigurator configurator;
    
    // Test mit verschiedenen Browser-Fingerprints
    std::vector<BrowserFingerprint> fingerprints = {
        BrowserFingerprint::CHROME_LATEST,
        BrowserFingerprint::FIREFOX_LATEST,
        BrowserFingerprint::SAFARI_LATEST,
        BrowserFingerprint::EDGE_CHROMIUM
    };
    
    for (auto fingerprint : fingerprints) {
        std::string fingerprint_name = UTLSClientConfigurator::fingerprint_to_string(fingerprint);
        std::cout << "Konfiguriere mit Browser-Fingerprint: " << fingerprint_name << std::endl;
        
        bool success = configurator.initialize(fingerprint, "example.com");
        if (success) {
            print_colored("  ✓ Konfiguration erfolgreich", 32);
        } else {
            print_colored("  ✗ Konfiguration fehlgeschlagen", 31);
        }
        
        // Zeige SSL-Verbindungsdetails
        SSL* ssl = configurator.get_ssl_conn();
        if (ssl != nullptr) {
            std::cout << "  - SSL Version: " << SSL_get_version(ssl) << std::endl;
            
            // Holen der Client Hello-Versionsinfo (nur für Demonstrationszwecke)
            std::cout << "  - TLS-Erweiterungen konfiguriert" << std::endl;
        }
        
        std::cout << std::endl;
    }
}

void test_fingerprint_rotator() {
    print_colored("=== Test: Fingerprint-Rotator ===", 36);
    
    // Test der sequentiellen Rotation
    {
        std::cout << "Sequentielle Rotationsstrategie:" << std::endl;
        
        std::vector<BrowserFingerprint> fingerprints = {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST
        };
        
        FingerprintRotator rotator(fingerprints, FingerprintRotator::RotationStrategy::SEQUENTIAL);
        
        for (int i = 0; i < 5; i++) {
            BrowserFingerprint fp = rotator.rotate_to_next();
            std::string fp_name = UTLSClientConfigurator::fingerprint_to_string(fp);
            std::cout << "  Rotation #" << (i+1) << ": " << fp_name << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    // Test der zufälligen Rotation
    {
        std::cout << "Zufällige Rotationsstrategie:" << std::endl;
        
        std::vector<BrowserFingerprint> fingerprints = {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST,
            BrowserFingerprint::EDGE_CHROMIUM
        };
        
        FingerprintRotator rotator(fingerprints, FingerprintRotator::RotationStrategy::RANDOM);
        
        for (int i = 0; i < 5; i++) {
            BrowserFingerprint fp = rotator.rotate_to_next();
            std::string fp_name = UTLSClientConfigurator::fingerprint_to_string(fp);
            std::cout << "  Rotation #" << (i+1) << ": " << fp_name << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    // Test der zeitbasierten Rotation
    {
        std::cout << "Zeitbasierte Rotationsstrategie:" << std::endl;
        
        FingerprintRotator rotator({}, FingerprintRotator::RotationStrategy::TIME_BASED);
        
        for (int i = 0; i < 3; i++) {
            BrowserFingerprint fp = rotator.rotate_to_next();
            std::string fp_name = UTLSClientConfigurator::fingerprint_to_string(fp);
            std::cout << "  Rotation #" << (i+1) << ": " << fp_name << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    // Test der automatischen Rotation
    {
        std::cout << "Automatische Rotation (verkürzte Testversion):" << std::endl;
        
        std::vector<BrowserFingerprint> fingerprints = {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST
        };
        
        // Rotationsintervall auf 2 Sekunden für den Test setzen
        FingerprintRotator rotator(fingerprints, 
                                  FingerprintRotator::RotationStrategy::SEQUENTIAL,
                                  std::chrono::minutes(1));
        
        std::cout << "  Startfingerprint: " 
                  << UTLSClientConfigurator::fingerprint_to_string(rotator.get_current_fingerprint()) 
                  << std::endl;
        
        std::cout << "  Starte automatische Rotation..." << std::endl;
        rotator.start_rotation();
        
        // Manuell einige Rotationen durchführen
        std::cout << "  Führe manuelle Rotationen durch..." << std::endl;
        
        for (int i = 0; i < 3; i++) {
            BrowserFingerprint fp = rotator.rotate_to_next();
            std::string fp_name = UTLSClientConfigurator::fingerprint_to_string(fp);
            std::cout << "    Rotation #" << (i+1) << ": " << fp_name << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        
        std::cout << "  Stoppe automatische Rotation..." << std::endl;
        rotator.stop_rotation();
        
        std::cout << "  Endfingerprint: " 
                  << UTLSClientConfigurator::fingerprint_to_string(rotator.get_current_fingerprint()) 
                  << std::endl;
                  
        std::cout << std::endl;
    }
}

void test_fingerprint_application() {
    print_colored("=== Test: Fingerprint-Anwendung ===", 36);
    
    FingerprintRotator rotator;
    UTLSClientConfigurator configurator;
    
    std::cout << "Anwendung des aktuellen Fingerprints aus dem Rotator:" << std::endl;
    
    BrowserFingerprint current_fp = rotator.get_current_fingerprint();
    std::string fp_name = UTLSClientConfigurator::fingerprint_to_string(current_fp);
    
    std::cout << "  Aktueller Fingerprint: " << fp_name << std::endl;
    
    bool success = rotator.apply_to_configurator(configurator, "example.com");
    if (success) {
        print_colored("  ✓ Konfiguration erfolgreich", 32);
    } else {
        print_colored("  ✗ Konfiguration fehlgeschlagen", 31);
    }
    
    // Zeige SSL-Verbindungsdetails
    SSL* ssl = configurator.get_ssl_conn();
    if (ssl != nullptr) {
        std::cout << "  - SSL Version: " << SSL_get_version(ssl) << std::endl;
        std::cout << "  - TLS-Erweiterungen konfiguriert" << std::endl;
    }
    
    std::cout << std::endl;
}

void test_session_tickets() {
    print_colored("=== Test: Session-Ticket-Verwaltung ===", 36);
    
    // Session-Ticket-Manager Status ausgeben
    SessionTicketManager& manager = SessionTicketManager::getInstance();
    std::cout << "Initial gespeicherte Session-Tickets: " << manager.getSessionCount() << std::endl;
    
    // Saubere Testumgebung
    manager.setMaxTicketsPerDomain(3);
    manager.setMaxTotalTickets(50);
    
    // Test-Konfiguration
    std::vector<std::string> test_domains = {
        "example.com",
        "github.com", 
        "google.de"
    };
    
    // 1. Test: Erste Verbindung zu mehreren Domains (ohne bestehende Session)
    std::cout << "\nSimuliere erste Verbindungen zu verschiedenen Domains:" << std::endl;
    for (const auto& domain : test_domains) {
        UTLSClientConfigurator configurator;
        configurator.initialize(BrowserFingerprint::CHROME_LATEST, domain, nullptr, true);
        
        std::cout << "  Verbindung zu " << domain << " mit CHROME_LATEST-Profil" << std::endl;
        
        // Für den Testfall simulieren wir das Erhalten eines Session-Tickets durch manuelles Speichern
        // In einer realen Anwendung würde dies nach dem TLS-Handshake automatisch geschehen
        SSL* ssl = configurator.get_ssl_conn();
        if (ssl != nullptr) {
            SSL_SESSION* dummy_session = SSL_SESSION_new();
            if (dummy_session) {
                // Setze einige Eigenschaften für die Test-Session
                SSL_SESSION_set_protocol_version(dummy_session, TLS1_3_VERSION);
                SSL_SESSION_set_time(dummy_session, time(NULL));
                
                // Session manuell im Manager speichern
                manager.storeSession(domain, dummy_session);
                
                // Referenzzähler dekrementieren (Manager hat eigene Referenz erhalten)
                SSL_SESSION_free(dummy_session);
                
                std::cout << "    ✓ Session-Ticket für " << domain << " gespeichert" << std::endl;
            }
        }
    }
    
    // Überprüfe den Status nach der ersten Sitzung
    std::cout << "\nSession-Tickets nach erster Verbindung: " << manager.getSessionCount() << std::endl;
    
    // 2. Test: Verbindungswiederaufnahme (mit bestehender Session)
    std::cout << "\nSimuliere Wiederaufnahme von Verbindungen:" << std::endl;
    for (const auto& domain : test_domains) {
        UTLSClientConfigurator configurator;
        configurator.initialize(BrowserFingerprint::CHROME_LATEST, domain, nullptr, true);
        
        std::cout << "  Wiederverbindung zu " << domain << std::endl;
    }
    
    // 3. Test: Session-Ticket-Limits testen
    std::cout << "\nSimuliere Session-Ticket-Limits:" << std::endl;
    
    // Setze niedrigeres Limit für den Test
    manager.setMaxTicketsPerDomain(2);
    std::cout << "  Max Tickets pro Domain auf 2 beschränkt" << std::endl;
    
    // Erstelle 5 Sessions für die gleiche Domain (sollte auf 2 beschränkt werden)
    const std::string test_domain = "limit-test.com";
    for (int i = 0; i < 5; i++) {
        UTLSClientConfigurator configurator;
        configurator.initialize(BrowserFingerprint::CHROME_LATEST, test_domain, nullptr, true);
        
        SSL* ssl = configurator.get_ssl_conn();
        if (ssl != nullptr) {
            SSL_SESSION* dummy_session = SSL_SESSION_new();
            if (dummy_session) {
                // Setze Basiswerte für die Test-Session
                SSL_SESSION_set_protocol_version(dummy_session, TLS1_3_VERSION);
                SSL_SESSION_set_time(dummy_session, time(NULL));
                
                // Session manuell im Manager speichern
                manager.storeSession(test_domain, dummy_session);
                
                // Referenzzähler dekrementieren
                SSL_SESSION_free(dummy_session);
                
                std::cout << "    Session #" << (i+1) << " für " << test_domain << " gespeichert" << std::endl;
            }
        }
    }
    
    // Überprüfe wie viele Sessions für die Domain gespeichert wurden
    // Wir können das nicht direkt zählen, aber wir können die Gesamtanzahl prüfen
    std::cout << "\nSession-Tickets nach Limit-Test: " << manager.getSessionCount() << std::endl;
    
    // 4. Test: Session-Tickets bereinigen
    std::cout << "\nSimuliere Bereinigung abgelaufener Session-Tickets:" << std::endl;
    manager.cleanupExpiredSessions();
    std::cout << "  Session-Tickets nach Bereinigung: " << manager.getSessionCount() << std::endl;
    
    std::cout << std::endl;
}

int main() {
    std::cout << "====================================" << std::endl;
    std::cout << "   QuicSand uTLS Stealth Test" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << std::endl;
    
    // Initialisiere OpenSSL (normalerweise bereits in der Hauptanwendung durchgeführt)
    SSL_library_init();
    SSL_load_error_strings();
    
    test_basic_utls_configuration();
    test_fingerprint_rotator();
    test_fingerprint_application();
    test_session_tickets();
    
    std::cout << "====================================" << std::endl;
    std::cout << "   Test abgeschlossen" << std::endl;
    std::cout << "====================================" << std::endl;
    
    return 0;
}
