#include <gtest/gtest.h>
#include <memory>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/asio.hpp>

#include "../tls/utls_client_configurator.hpp"
#include "../core/quic_connection.hpp"
#include "../core/quic.hpp"
#include <boost/asio.hpp>

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

// Test für die UTLSClientConfigurator-Klasse
TEST(UTLSTests, TestUTLSClientConfigurator) {
    // Initialisierung von OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    
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
        ASSERT_TRUE(configurator.initialize(fingerprint, hostname)) 
            << "Failed to initialize with fingerprint: " 
            << UTLSClientConfigurator::fingerprint_to_string(fingerprint);
        
        // Prüfe, ob SSL_CTX erstellt wurde
        SSL_CTX* ctx = configurator.get_ssl_context();
        ASSERT_NE(ctx, nullptr) << "SSL_CTX was not created for fingerprint: " 
                               << UTLSClientConfigurator::fingerprint_to_string(fingerprint);
        
        // Prüfe, ob quiche_config erstellt wurde
        quiche_config* quiche_cfg = configurator.get_quiche_config();
        ASSERT_NE(quiche_cfg, nullptr) << "quiche_config was not created for fingerprint: " 
                                      << UTLSClientConfigurator::fingerprint_to_string(fingerprint);
    }
}

// Test für die Integration mit QuicConnection
TEST(UTLSTests, TestQuicConnectionWithUTLS) {
    // IO-Context für Boost ASIO
    boost::asio::io_context io_context;
    
    // Basis-Konfiguration für QuicConnection
    QuicConfig config;
    
    // Erstelle QuicConnection mit Standardfingerprint (Chrome Latest)
    std::unique_ptr<QuicConnection> conn = std::make_unique<QuicConnection>(io_context, config);
    ASSERT_TRUE(conn->is_using_utls()) << "uTLS sollte standardmäßig aktiviert sein";
    ASSERT_EQ(conn->get_browser_fingerprint(), BrowserFingerprint::CHROME_LATEST) 
        << "Standardfingerprint sollte Chrome Latest sein";
    
    // Fingerprint ändern
    ASSERT_TRUE(conn->set_browser_fingerprint(BrowserFingerprint::FIREFOX_LATEST)) 
        << "Konnte Fingerprint nicht auf Firefox Latest setzen";
    ASSERT_EQ(conn->get_browser_fingerprint(), BrowserFingerprint::FIREFOX_LATEST) 
        << "Fingerprint sollte jetzt Firefox Latest sein";
    
    // Erstelle QuicConnection mit explizitem Fingerprint
    std::unique_ptr<QuicConnection> conn2 = std::make_unique<QuicConnection>(
        io_context, config, BrowserFingerprint::SAFARI_LATEST);
    
    ASSERT_TRUE(conn2->is_using_utls()) << "uTLS sollte aktiviert sein";
    ASSERT_EQ(conn2->get_browser_fingerprint(), BrowserFingerprint::SAFARI_LATEST) 
        << "Fingerprint sollte Safari Latest sein";
}

// Überprüft mögliche Verbindung zu einem QUIC/HTTP3-Server
// Hinweis: Dieser Test erfordert Internetzugang und einen erreichbaren QUIC-Server
// Er wird daher als DISABLED markiert, um nicht automatisch zu laufen
TEST(UTLSTests, DISABLED_TestQuicConnectionToRealServer) {
    // IO-Context für Boost ASIO
    boost::asio::io_context io_context;
    
    // Test-Server (bekannter HTTP/3-Server)
    std::string test_server = "quic.rocks";
    uint16_t test_port = 4433;
    
    // Basis-Konfiguration
    QuicConfig config;
    
    // Verbindungen mit verschiedenen Fingerprints testen
    std::vector<BrowserFingerprint> fingerprints = {
        BrowserFingerprint::CHROME_LATEST,
        BrowserFingerprint::FIREFOX_LATEST
    };
    
    for (auto fingerprint : fingerprints) {
        std::cout << "Testing connection with fingerprint: " 
                 << UTLSClientConfigurator::fingerprint_to_string(fingerprint) 
                 << std::endl;
        
        // Erstelle Verbindung mit dem aktuellen Fingerprint
        std::shared_ptr<QuicConnection> conn = std::make_shared<QuicConnection>(
            io_context, config, fingerprint);
        
        // Status für den async_connect-Callback
        bool connect_completed = false;
        std::error_code connect_ec;
        
        // Verbinde zum Test-Server
        conn->async_connect(test_server, test_port, 
            [&connect_completed, &connect_ec](std::error_code ec) {
                connect_completed = true;
                connect_ec = ec;
            });
        
        // IO-Context starten (mit Timeout)
        io_context.restart();
        io_context.run_for(std::chrono::seconds(10)); // 10 Sekunden Timeout
        
        // Überprüfe, ob Verbindung versucht wurde
        ASSERT_TRUE(connect_completed) << "Connection timeout with fingerprint: " 
                                      << UTLSClientConfigurator::fingerprint_to_string(fingerprint);
        
        // Verbindung kann fehlschlagen, je nach Netzwerk und Server-Verfügbarkeit
        if (!connect_ec) {
            std::cout << "Connection successful with fingerprint: " 
                     << UTLSClientConfigurator::fingerprint_to_string(fingerprint) 
                     << std::endl;
        } else {
            std::cout << "Connection failed with fingerprint: " 
                     << UTLSClientConfigurator::fingerprint_to_string(fingerprint) 
                     << " - Error: " << connect_ec.message() 
                     << std::endl;
        }
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
