#pragma once

#include <string>
#include <vector>
#include <iostream>
#include "../tls/utls_client_configurator.hpp"

namespace quicsand {
namespace cli {

// Struktur für Kommandozeilenoptionen
struct CommandLineOptions {
    // Verbindungseigenschaften
    std::string server_host = "localhost";
    uint16_t server_port = 8443;
    bool enable_fec = true;
    bool verify_peer = false;
    std::string ca_file;
    
    // uTLS-Einstellungen
    BrowserFingerprint browser_fingerprint = BrowserFingerprint::CHROME_LATEST;
    bool use_utls = true;
    
    // Daten und Streams
    uint32_t stream_count = 1;
    std::string data_file;
    
    // Logging und Debug
    bool verbose = false;
    bool debug_tls = false;
    
    // Helfer-Methode zum Konvertieren von Fingerprint-String zu Enum
    static BrowserFingerprint parse_fingerprint(const std::string& fingerprint_str) {
        if (fingerprint_str == "chrome") return BrowserFingerprint::CHROME_LATEST;
        if (fingerprint_str == "firefox") return BrowserFingerprint::FIREFOX_LATEST;
        if (fingerprint_str == "safari") return BrowserFingerprint::SAFARI_LATEST;
        if (fingerprint_str == "edge") return BrowserFingerprint::EDGE_CHROMIUM;
        if (fingerprint_str == "brave") return BrowserFingerprint::BRAVE_LATEST;
        if (fingerprint_str == "opera") return BrowserFingerprint::OPERA_LATEST;
        if (fingerprint_str == "chrome_android") return BrowserFingerprint::CHROME_ANDROID;
        if (fingerprint_str == "safari_ios") return BrowserFingerprint::SAFARI_IOS;
        if (fingerprint_str == "random") return BrowserFingerprint::RANDOMIZED;
        
        // Standard: Chrome
        std::cout << "Unbekannter Browser-Fingerprint: " << fingerprint_str << ". Verwende Chrome als Standard." << std::endl;
        return BrowserFingerprint::CHROME_LATEST;
    }
    
    // Hilfsmethode zur Konvertierung von Enum zu String für Log-Zwecke
    static std::string fingerprint_to_string(BrowserFingerprint fp) {
        return UTLSClientConfigurator::fingerprint_to_string(fp);
    }
};

} // namespace cli
} // namespace quicsand
