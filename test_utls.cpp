#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/asio.hpp>

#include "tls/utls_client_configurator.hpp"
#include "core/quic_connection.hpp"
#include "core/quic.hpp"

using namespace quicsand;

// Hilfsfunktion zum Ausgeben von OpenSSL-Fehlern
void print_ssl_errors() {
    unsigned long err;
    char err_buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "SSL Error: " << err_buf << std::endl;
    }
}

bool test_utls_client_configurator() {
    std::cout << "\n=== Test: UTLSClientConfigurator Funktionalität ===\n" << std::endl;
    
    // Initialisierung von OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    
    try {
        // Erstelle UTLSClientConfigurator
        UTLSClientConfigurator configurator;
        
        // Liste aller Browser-Fingerprints zum Testen
        std::vector<BrowserFingerprint> fingerprints = {
            BrowserFingerprint::CHROME_LATEST,
            BrowserFingerprint::FIREFOX_LATEST,
            BrowserFingerprint::SAFARI_LATEST,
            BrowserFingerprint::EDGE_LATEST,
            BrowserFingerprint::IOS_SAFARI
        };
        
        // Teste jeden Fingerprint
        for (auto fingerprint : fingerprints) {
            std::string hostname = "example.com";
            std::cout << "Testing fingerprint: " 
                     << UTLSClientConfigurator::fingerprint_to_string(fingerprint) 
                     << std::endl;
            
            // Initialisiere mit dem aktuellen Fingerprint
            bool success = configurator.initialize(fingerprint, hostname);
            if (!success) {
                std::cerr << "Failed to initialize with fingerprint: " 
                         << UTLSClientConfigurator::fingerprint_to_string(fingerprint) << std::endl;
                print_ssl_errors();
                return false;
            }
            
            // Prüfe, ob SSL_CTX erstellt wurde
            SSL_CTX* ctx = configurator.get_ssl_context();
            if (ctx == nullptr) {
                std::cerr << "SSL_CTX was not created for fingerprint: " 
                         << UTLSClientConfigurator::fingerprint_to_string(fingerprint) << std::endl;
                return false;
            }
            
            // Prüfe, ob quiche_config erstellt wurde
            quiche_config* quiche_cfg = configurator.get_quiche_config();
            if (quiche_cfg == nullptr) {
                std::cerr << "quiche_config was not created for fingerprint: " 
                         << UTLSClientConfigurator::fingerprint_to_string(fingerprint) << std::endl;
                return false;
            }
            
            std::cout << "Fingerprint " 
                     << UTLSClientConfigurator::fingerprint_to_string(fingerprint) 
                     << " successfully tested!" << std::endl;
        }
        
        std::cout << "\nAll fingerprints successfully tested!" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Exception during UTLSClientConfigurator test: " << e.what() << std::endl;
        print_ssl_errors();
        return false;
    }
}

bool test_quic_connection_with_utls() {
    std::cout << "\n=== Test: QuicConnection mit uTLS Integration ===\n" << std::endl;
    
    try {
        // IO-Context für Boost ASIO
        boost::asio::io_context io_context;
        
        // Basis-Konfiguration für QuicConnection
        QuicConfig config;
        
        // Erstelle QuicConnection mit Standardfingerprint (Chrome Latest)
        std::cout << "Creating QuicConnection with default fingerprint..." << std::endl;
        std::unique_ptr<QuicConnection> conn = std::make_unique<QuicConnection>(io_context, config);
        
        if (!conn->is_using_utls()) {
            std::cerr << "uTLS sollte standardmäßig aktiviert sein!" << std::endl;
            return false;
        }
        
        if (conn->get_browser_fingerprint() != BrowserFingerprint::CHROME_LATEST) {
            std::cerr << "Standardfingerprint sollte Chrome Latest sein!" << std::endl;
            return false;
        }
        
        std::cout << "Default fingerprint test passed!" << std::endl;
        
        // Fingerprint ändern
        std::cout << "Changing fingerprint to Firefox Latest..." << std::endl;
        if (!conn->set_browser_fingerprint(BrowserFingerprint::FIREFOX_LATEST)) {
            std::cerr << "Konnte Fingerprint nicht auf Firefox Latest setzen!" << std::endl;
            return false;
        }
        
        if (conn->get_browser_fingerprint() != BrowserFingerprint::FIREFOX_LATEST) {
            std::cerr << "Fingerprint sollte jetzt Firefox Latest sein!" << std::endl;
            return false;
        }
        
        std::cout << "Fingerprint change test passed!" << std::endl;
        
        // Erstelle QuicConnection mit explizitem Fingerprint
        std::cout << "Creating QuicConnection with explicit Safari Latest fingerprint..." << std::endl;
        std::unique_ptr<QuicConnection> conn2 = std::make_unique<QuicConnection>(
            io_context, config, BrowserFingerprint::SAFARI_LATEST);
        
        if (!conn2->is_using_utls()) {
            std::cerr << "uTLS sollte aktiviert sein!" << std::endl;
            return false;
        }
        
        if (conn2->get_browser_fingerprint() != BrowserFingerprint::SAFARI_LATEST) {
            std::cerr << "Fingerprint sollte Safari Latest sein!" << std::endl;
            return false;
        }
        
        std::cout << "Explicit fingerprint test passed!" << std::endl;
        std::cout << "\nAll QuicConnection tests successfully passed!" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Exception during QuicConnection test: " << e.what() << std::endl;
        return false;
    }
}

int main() {
    std::cout << "===== QuicSand uTLS Integration Test =====\n" << std::endl;
    
    bool utls_configurator_test = test_utls_client_configurator();
    bool quic_connection_test = test_quic_connection_with_utls();
    
    std::cout << "\n===== Test Results =====\n" << std::endl;
    std::cout << "UTLSClientConfigurator Test: " << (utls_configurator_test ? "PASSED" : "FAILED") << std::endl;
    std::cout << "QuicConnection with uTLS Test: " << (quic_connection_test ? "PASSED" : "FAILED") << std::endl;
    
    if (utls_configurator_test && quic_connection_test) {
        std::cout << "\nALL TESTS PASSED!" << std::endl;
        std::cout << "The uTLS integration is working correctly." << std::endl;
        return 0;
    } else {
        std::cout << "\nSome tests FAILED!" << std::endl;
        std::cout << "Please check the error messages above." << std::endl;
        return 1;
    }
}
