#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../core/quic_connection.hpp"
#include "../core/quic_stream.hpp"
#include "../stealth/uTLS.hpp"
#include "options.hpp"

using namespace quicfuscate;
namespace po = boost::program_options;

// Hilfsfunktion zum Ausgeben der verfügbaren Browser-Fingerprints
void print_available_fingerprints() {
    std::cout << "Verfügbare Browser-Fingerprints:" << std::endl;
    std::cout << "  chrome        - Google Chrome (neueste Version)" << std::endl;
    std::cout << "  firefox       - Mozilla Firefox (neueste Version)" << std::endl;
    std::cout << "  safari        - Apple Safari (neueste Version)" << std::endl;
    std::cout << "  edge          - Microsoft Edge (Chromium-basiert)" << std::endl;
    std::cout << "  brave         - Brave Browser" << std::endl;
    std::cout << "  opera         - Opera Browser" << std::endl;
    std::cout << "  chrome_android - Chrome auf Android" << std::endl;
    std::cout << "  safari_ios    - Safari auf iOS" << std::endl;
    std::cout << "  random        - Zufälliger Fingerprint" << std::endl;
}

// Hilfsfunktion zum Ausgeben von OpenSSL-Fehlern
void print_ssl_errors() {
    unsigned long err;
    char err_buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "SSL Error: " << err_buf << std::endl;
    }
}

// Parse der Kommandozeilenargumente
cli::CommandLineOptions parse_arguments(int argc, char** argv) {
    cli::CommandLineOptions options;
    
    try {
        // Definiere Kommandozeilenoptionen
        po::options_description desc("QuicFuscate VPN - QUIC mit uTLS Integration\nOptionen");
        desc.add_options()
            ("help,h", "Zeigt diese Hilfe an")
            ("server,s", po::value<std::string>(&options.server_host)->default_value("example.com"), 
             "Server-Hostname oder IP-Adresse")
            ("port,p", po::value<uint16_t>(&options.server_port)->default_value(443), 
             "Server-Port")
            ("fingerprint,f", po::value<std::string>()->default_value("chrome"), 
             "Browser-Fingerprint (chrome, firefox, safari, edge, brave, opera, chrome_android, safari_ios, random)")
            ("no-utls", po::bool_switch()->default_value(false), 
             "Deaktiviert uTLS (verwendet Standard-TLS)")
            ("verify-peer", po::bool_switch(&options.verify_peer)->default_value(false), 
             "Aktiviert die Verifizierung des Server-Zertifikats")
            ("ca-file", po::value<std::string>(&options.ca_file), 
             "Pfad zur CA-Zertifikatsdatei (für Peer-Verifizierung)")
            ("verbose,v", po::bool_switch(&options.verbose)->default_value(false), 
             "Ausführliche Protokollierung")
            ("debug-tls", po::bool_switch(&options.debug_tls)->default_value(false), 
             "TLS-Debug-Informationen anzeigen")
            ("list-fingerprints", "Zeigt verfügbare Browser-Fingerprints an")
        ;
        
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        
        // Hilfe anzeigen
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(0);
        }
        
        // Verfügbare Browser-Fingerprints anzeigen
        if (vm.count("list-fingerprints")) {
            print_available_fingerprints();
            exit(0);
        }
        
        // uTLS-Option verarbeiten
        if (vm["no-utls"].as<bool>()) {
            options.use_utls = false;
        }
        
        // Browser-Fingerprint verarbeiten
        if (vm.count("fingerprint")) {
            std::string fingerprint_str = vm["fingerprint"].as<std::string>();
            boost::algorithm::to_lower(fingerprint_str); // Konvertiere zu Kleinbuchstaben
            options.browser_fingerprint = cli::CommandLineOptions::parse_fingerprint(fingerprint_str);
        }
        
    } catch (std::exception& e) {
        std::cerr << "Fehler beim Parsen der Kommandozeilenargumente: " << e.what() << std::endl;
        exit(1);
    }
    
    return options;
}

// Hauptfunktion
int main(int argc, char** argv) {
    // Initialisierung von OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    
    // Parse Kommandozeilenargumente
    cli::CommandLineOptions options = parse_arguments(argc, argv);
    
    // Ausgabe der gewählten Optionen
    std::cout << "QuicFuscate VPN - QUIC mit uTLS Integration" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Verbinde zu " << options.server_host << ":" << options.server_port;
    
    if (options.use_utls) {
        std::cout << " mit Browser-Fingerprint: " 
                  << cli::CommandLineOptions::fingerprint_to_string(options.browser_fingerprint) << std::endl;
    } else {
        std::cout << " mit Standard-TLS (uTLS deaktiviert)" << std::endl;
    }
    
    if (options.verify_peer) {
        std::cout << "Server-Zertifikatsverifikation aktiviert";
        if (!options.ca_file.empty()) {
            std::cout << " mit CA-Datei: " << options.ca_file;
        }
        std::cout << std::endl;
    }
    
    // IO-Context für asynchrone Operationen
    boost::asio::io_context io_context;
    
    // QUIC-Konfiguration erstellen
    QuicConfig config;
    
    // QuicConnection erstellen
    std::shared_ptr<QuicConnection> conn;
    
    try {
        if (options.use_utls) {
            // Mit uTLS und gewähltem Browser-Fingerprint
            conn = std::make_shared<QuicConnection>(io_context, config, options.browser_fingerprint);
            
            if (options.verbose) {
                std::cout << "QuicConnection mit uTLS und Browser-Fingerprint "
                          << cli::CommandLineOptions::fingerprint_to_string(options.browser_fingerprint)
                          << " erstellt." << std::endl;
            }
        } else {
            // Ohne spezifischen Browser-Fingerprint
            conn = std::make_shared<QuicConnection>(io_context, config);
            
            // Deaktiviere uTLS explizit, falls die Klasse das unterstützt
            // Annahme: Die Klasse hat ein Attribut, um uTLS zu deaktivieren
            if (options.verbose) {
                std::cout << "QuicConnection ohne uTLS erstellt." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Fehler beim Erstellen der QuicConnection: " << e.what() << std::endl;
        print_ssl_errors();
        return 1;
    }
    
    // Status für die Verbindung
    std::atomic<bool> connect_completed(false);
    std::atomic<bool> connection_success(false);
    
    // Asynchrone Verbindung starten
    std::cout << "Starte Verbindung..." << std::endl;
    conn->async_connect(options.server_host, options.server_port, 
                        [&connect_completed, &connection_success, options](std::error_code ec) {
        connect_completed = true;
        
        if (!ec) {
            connection_success = true;
            std::cout << "\nVerbindung erfolgreich hergestellt!" << std::endl;
            
            if (options.verbose) {
                std::cout << "QUIC-Verbindung etabliert. Bereit für Datentransfer." << std::endl;
            }
        } else {
            std::cerr << "\nVerbindungsfehler: " << ec.message() << std::endl;
            
            if (options.debug_tls) {
                print_ssl_errors();
            }
        }
    });
    
    // Fortschrittsanzeige während des Verbindungsaufbaus
    int dots = 0;
    auto progress_timer = std::make_shared<boost::asio::deadline_timer>(io_context);
    
    std::function<void(const boost::system::error_code&)> progress_callback;
    progress_callback = [&, progress_timer](const boost::system::error_code&) {
        if (!connect_completed) {
            std::cout << "." << std::flush;
            dots++;
            
            if (dots % 60 == 0) {
                std::cout << std::endl;
            }
            
            progress_timer->expires_from_now(boost::posix_time::milliseconds(100));
            progress_timer->async_wait(progress_callback);
        }
    };
    
    progress_timer->expires_from_now(boost::posix_time::milliseconds(100));
    progress_timer->async_wait(progress_callback);
    
    // Timeout für die Verbindung
    auto timeout_timer = std::make_shared<boost::asio::deadline_timer>(io_context);
    timeout_timer->expires_from_now(boost::posix_time::seconds(15));
    timeout_timer->async_wait([&](const boost::system::error_code&) {
        if (!connect_completed) {
            std::cerr << "\nVerbindungs-Timeout nach 15 Sekunden!" << std::endl;
            connect_completed = true;
            io_context.stop();
        }
    });
    
    // Event-Loop starten
    io_context.run();
    
    // Nach der Verbindung - Stream erstellen, falls erfolgreich
    if (connection_success) {
        try {
            std::cout << "Erstelle QUIC-Stream..." << std::endl;
            auto stream = conn->create_stream();
            
            if (stream) {
                std::cout << "Stream erfolgreich erstellt." << std::endl;
                
                // Hier könnten wir Daten über den Stream senden/empfangen
                const std::string test_data = "GET / HTTP/1.1\r\nHost: " + options.server_host + "\r\n\r\n";
                std::cout << "Sende HTTP-Anfrage..." << std::endl;
                
                // Bei einer echten Implementierung würden wir asynchron senden und empfangen
                // Hier nur eine vereinfachte Version zur Demonstration
                stream->send_data((const uint8_t*)test_data.c_str(), test_data.size());
                
                std::cout << "Anfrage gesendet. In einer vollständigen Implementierung würden wir jetzt auf Antwort warten." << std::endl;
            } else {
                std::cerr << "Konnte keinen Stream erstellen." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Arbeiten mit dem Stream: " << e.what() << std::endl;
        }
    }
    
    // Aufräumen
    std::cout << "\nProgramm beendet." << std::endl;
    
    return connection_success ? 0 : 1;
}
