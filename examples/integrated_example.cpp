#include "../core/quic_connection.hpp"
#include "../core/quic_path_mtu_manager.hpp"
#include "../core/error_handling.hpp"
#include "../core/cache_optimizations.hpp"
#include "../core/thread_optimizations.hpp"
#include "../core/energy_optimizations.hpp"
#include "../core/optimizations_integration.hpp"
#include "../core/zero_copy_optimized.hpp"
#include "../stealth/stealth_manager.hpp"
#include "../stealth/sni_hiding.hpp"
#include "../stealth/dpi_evasion.hpp"
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iomanip>

using namespace quicsand;
using namespace quicsand::stealth;

// Hilfsfunktion für Verbindungsaufbau mit allen Optimierungen
Result<std::unique_ptr<QuicConnection>> establish_optimized_connection(
    const std::string& host, 
    uint16_t port,
    StealthLevel stealth_level = StealthLevel::MAXIMUM
) {
    try {
        // 1. Optimierungsmanager initialisieren
        auto config = OptimizationsConfig::create_for_mobile();
        OptimizationsManager opt_manager(config);
        
        // 2. Stealth-Manager initialisieren
        StealthManager stealth_manager;
        stealth_manager.set_stealth_level(stealth_level);
        
        // SNI-Hiding für host konfigurieren
        SniConfig sni_config;
        sni_config.enable_sni_split = true;
        sni_config.enable_domain_fronting = true;
        sni_config.front_domain = "cdn.example.com";  // Beispiel Front-Domain
        sni_config.real_domain = host;
        stealth_manager.set_sni_config(sni_config);
        
        // DPI-Evasion konfigurieren
        DpiConfig dpi_config;
        dpi_config.enable_packet_padding = true;
        dpi_config.enable_timing_jitter = true;
        dpi_config.enable_protocol_obfuscation = true;
        stealth_manager.set_dpi_config(dpi_config);
        
        // 3. QUIC-Verbindung mit Zero-Copy erstellen
        auto connection = std::make_unique<QuicConnection>(true); // true = Zero-Copy aktivieren
        
        // 4. Verbindung optimieren
        opt_manager.optimize_connection(*connection);
        
        // 5. MTU-Manager erstellen und optimieren
        PathMtuManager mtu_manager(*connection);
        opt_manager.optimize_mtu_manager(mtu_manager);
        
        // 6. MTU Discovery aktivieren
        auto mtu_result = mtu_manager.enable_mtu_discovery(true);
        if (!mtu_result) {
            std::cerr << "Warnung: MTU-Discovery konnte nicht aktiviert werden: " 
                      << mtu_result.error().message << std::endl;
            // Wir brechen nicht ab, da dies nicht kritisch ist
        }
        
        // 7. Callbacks für MTU-Änderungen und Blackhole-Erkennung registrieren
        mtu_manager.set_mtu_change_callback([](uint16_t new_mtu) {
            std::cout << "MTU angepasst: " << new_mtu << " Bytes" << std::endl;
        });
        
        mtu_manager.set_blackhole_detection_callback([]() {
            std::cerr << "MTU Blackhole erkannt! Verbindungsprobleme können auftreten." << std::endl;
        });
        
        // 8. Optimierten Zero-Copy-Buffer für die Verbindung vorbereiten
        OptimizedZeroCopyIntegration zero_copy_integration;
        
        // 9. Verbindung herstellen
        std::cout << "Verbindung zu " << host << ":" << port << " wird hergestellt..." << std::endl;
        if (!connection->connect(host, port)) {
            return Result<std::unique_ptr<QuicConnection>>::failure({
                ErrorCategory::NETWORK,
                ErrorCode::CONNECTION_REFUSED,
                "Verbindung zu " + host + ":" + std::to_string(port) + " fehlgeschlagen"
            });
        }
        
        std::cout << "Verbindung erfolgreich hergestellt!" << std::endl;
        return Result<std::unique_ptr<QuicConnection>>::success(std::move(connection));
        
    } catch (const std::exception& e) {
        return Result<std::unique_ptr<QuicConnection>>::failure({
            ErrorCategory::SYSTEM,
            ErrorCode::UNKNOWN_ERROR,
            std::string("Unerwarteter Fehler: ") + e.what()
        });
    }
}

// Beispiel für eine komplette QUIC-VPN-Verbindung mit allen Optimierungen
int main(int argc, char** argv) {
    // Parameter prüfen
    std::string host = "example.com";
    uint16_t port = 443;
    
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = static_cast<uint16_t>(std::stoi(argv[2]));
    }
    
    // Worker-Pool für asynchrone Verarbeitung erstellen
    EnergyConfig energy_config;
    energy_config.thread_mode = ThreadEnergyMode::BALANCED;
    EnergyEfficientWorkerPool worker_pool(2, energy_config.thread_mode);
    
    // Verbindung mit allen Optimierungen herstellen
    auto connection_result = establish_optimized_connection(host, port);
    
    if (!connection_result) {
        std::cerr << "Fehler beim Verbindungsaufbau: " 
                 << connection_result.error().message << std::endl;
        return 1;
    }
    
    auto connection = std::move(connection_result.value());
    
    // Testdaten vorbereiten
    std::vector<uint8_t> test_data(1000);
    for (size_t i = 0; i < test_data.size(); ++i) {
        test_data[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Cache-optimierte Buffer erstellen
    CacheOptimizedVector<uint8_t> optimized_buffer;
    for (auto byte : test_data) {
        optimized_buffer.push_back(byte);
    }
    
    // Prefetching für besseren Cache-Zugriff
    Prefetcher::prefetch_array(optimized_buffer.data(), optimized_buffer.size(), 
                             Prefetcher::PrefetchType::READ);
    
    // Daten mit Zero-Copy senden
    std::cout << "Sende Testdaten..." << std::endl;
    auto send_result = connection->send_packet_zero_copy(
        optimized_buffer.data(), 
        optimized_buffer.size()
    );
    
    if (!send_result) {
        std::cerr << "Fehler beim Senden: " << send_result.error().message << std::endl;
        connection->disconnect();
        return 1;
    }
    
    std::cout << "Gesendet: " << send_result.value() << " Bytes" << std::endl;
    
    // Asynchronen Empfang durchführen
    std::atomic<bool> response_received{false};
    
    worker_pool.enqueue([&]() {
        auto recv_result = connection->receive_data(4096);
        if (recv_result) {
            auto& data = recv_result.value();
            std::cout << "Empfangen: " << data.size() << " Bytes" << std::endl;
            
            // Ersten 16 Bytes zur Überprüfung anzeigen
            std::cout << "Erste Bytes: ";
            for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                         << static_cast<int>(data[i]) << " ";
            }
            std::cout << std::dec << std::endl;
        } else {
            std::cerr << "Fehler beim Empfangen: " << recv_result.error().message << std::endl;
        }
        
        response_received = true;
    });
    
    // Energieeffizientes Warten auf Antwort
    EnergyManager energy_manager(energy_config);
    std::cout << "Warte auf Antwort..." << std::endl;
    
    bool success = energy_manager.wait_efficiently(
        [&]() { return response_received.load(); },
        std::chrono::milliseconds(5000)  // 5 Sekunden Timeout
    );
    
    if (!success) {
        std::cerr << "Timeout beim Warten auf Antwort!" << std::endl;
    }
    
    // Verbindung schließen
    std::cout << "Schließe Verbindung..." << std::endl;
    connection->disconnect();
    
    std::cout << "Beispiel abgeschlossen." << std::endl;
    return 0;
}
