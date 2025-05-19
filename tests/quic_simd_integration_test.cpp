#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <thread>
#include <functional>
#include <cassert>
#include <random>

#include "../core/quic_connection.hpp"
#include "../core/quic_stream.hpp"
#include "../core/simd_optimizations.hpp"
#include "../crypto/aes128gcm_optimized.hpp"
#include "../fec/tetrys_fec_optimized.hpp"

using namespace quicsand;
using namespace std::chrono;

// Hilfsfunktion zur Messung der Ausführungszeit
template<typename Func>
double measure_execution_time(Func&& func) {
    auto start = high_resolution_clock::now();
    func();
    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count();
}

// Testdaten generieren
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return data;
}

// Test für SIMD-Feature-Detection in QuicConnection
void test_simd_feature_detection() {
    std::cout << "\n=== Test: SIMD-Feature-Detection ===" << std::endl;
    
    // Erstelle eine QUIC-Verbindung
    boost::asio::io_context io_context;
    QuicConfig config;
    QuicConnection connection(io_context, config);
    
    // SIMD-Features abrufen und anzeigen
    bool has_simd = connection.has_simd_support();
    std::cout << "SIMD-Unterstützung vorhanden: " << (has_simd ? "Ja" : "Nein") << std::endl;
    
    if (has_simd) {
        uint32_t features = connection.get_supported_simd_features();
        std::cout << "Unterstützte SIMD-Features: " << connection.get_simd_features_string() << std::endl;
        
        // Prüfe, ob NEON vorhanden ist (sollte auf M1/M2 der Fall sein)
        bool has_neon = (features & static_cast<uint32_t>(simd::SIMDSupport::NEON)) != 0;
        std::cout << "NEON-Unterstützung: " << (has_neon ? "Ja" : "Nein") << std::endl;
    }
}

// Test für die optimierte FEC-Integration
void test_optimized_fec_integration() {
    std::cout << "\n=== Test: Optimierte FEC-Integration ===" << std::endl;
    
    // Erstelle eine QUIC-Verbindung
    boost::asio::io_context io_context;
    QuicConfig config;
    QuicConnection connection(io_context, config);
    
    // Prüfe, ob SIMD-Support vorhanden ist
    if (!connection.has_simd_support()) {
        std::cout << "SIMD-Unterstützung nicht vorhanden, Test übersprungen." << std::endl;
        return;
    }
    
    // Standardmodus und optimierter Modus für Vergleich
    std::cout << "Aktiviere Standard-FEC..." << std::endl;
    connection.enable_optimized_fec(false);
    connection.enable_fec(true);
    
    // Testdaten generieren
    const size_t packet_size = 1024;
    const size_t num_packets = 10;
    std::vector<std::vector<uint8_t>> test_packets;
    
    for (size_t i = 0; i < num_packets; i++) {
        test_packets.push_back(generate_random_data(packet_size));
    }
    
    // Standard-FEC Benchmark
    double standard_encoding_time = 0.0;
    double standard_decoding_time = 0.0;
    
    std::cout << "Führe Standard-FEC-Benchmark durch..." << std::endl;
    for (const auto& packet : test_packets) {
        // Encoding-Zeit messen
        standard_encoding_time += measure_execution_time([&]() {
            connection.apply_fec_encoding(packet.data(), packet.size());
        });
        
        // Decoding-Zeit messen (vereinfachter Test)
        standard_decoding_time += measure_execution_time([&]() {
            connection.apply_fec_decoding(packet.data(), packet.size());
        });
    }
    
    standard_encoding_time /= num_packets;
    standard_decoding_time /= num_packets;
    
    // Optimierte FEC aktivieren
    std::cout << "Aktiviere SIMD-optimierte FEC..." << std::endl;
    connection.enable_optimized_fec(true);
    connection.enable_fec(true);
    
    // Optimierte FEC Benchmark
    double optimized_encoding_time = 0.0;
    double optimized_decoding_time = 0.0;
    
    std::cout << "Führe optimierte FEC-Benchmark durch..." << std::endl;
    for (const auto& packet : test_packets) {
        // Encoding-Zeit messen
        optimized_encoding_time += measure_execution_time([&]() {
            connection.apply_fec_encoding(packet.data(), packet.size());
        });
        
        // Decoding-Zeit messen (vereinfachter Test)
        optimized_decoding_time += measure_execution_time([&]() {
            connection.apply_fec_decoding(packet.data(), packet.size());
        });
    }
    
    optimized_encoding_time /= num_packets;
    optimized_decoding_time /= num_packets;
    
    // Ergebnisse anzeigen
    std::cout << "\nFEC-Benchmark-Ergebnisse (" << num_packets << " Pakete, " << packet_size << " Bytes/Paket):" << std::endl;
    std::cout << "Standard-FEC Encoding-Zeit: " << standard_encoding_time << " µs" << std::endl;
    std::cout << "Standard-FEC Decoding-Zeit: " << standard_decoding_time << " µs" << std::endl;
    std::cout << "Optimierte FEC Encoding-Zeit: " << optimized_encoding_time << " µs" << std::endl;
    std::cout << "Optimierte FEC Decoding-Zeit: " << optimized_decoding_time << " µs" << std::endl;
    
    // Speedup berechnen
    double encoding_speedup = standard_encoding_time / optimized_encoding_time;
    double decoding_speedup = standard_decoding_time / optimized_decoding_time;
    
    std::cout << "Encoding Speedup: " << std::fixed << std::setprecision(2) << encoding_speedup << "x" << std::endl;
    std::cout << "Decoding Speedup: " << std::fixed << std::setprecision(2) << decoding_speedup << "x" << std::endl;
}

// Test für die optimierte Kryptografie-Integration
void test_optimized_crypto_integration() {
    std::cout << "\n=== Test: Optimierte Kryptografie-Integration ===" << std::endl;
    
    // Erstelle eine QUIC-Verbindung
    boost::asio::io_context io_context;
    QuicConfig config;
    QuicConnection connection(io_context, config);
    
    // Prüfe, ob SIMD-Support vorhanden ist
    if (!connection.has_simd_support()) {
        std::cout << "SIMD-Unterstützung nicht vorhanden, Test übersprungen." << std::endl;
        return;
    }
    
    // Optimierte Kryptografie aktivieren
    std::cout << "Aktiviere SIMD-optimierte Kryptografie..." << std::endl;
    bool result = connection.enable_optimized_crypto(true);
    std::cout << "Aktivierung erfolgreich: " << (result ? "Ja" : "Nein") << std::endl;
    std::cout << "SIMD-optimierte Kryptografie ist " 
              << (connection.is_optimized_crypto_enabled() ? "aktiviert" : "deaktiviert") << std::endl;
    
    // An dieser Stelle würden wir normalerweise weitere Tests mit der optimierten Kryptografie durchführen,
    // beispielsweise Verschlüsselung und Entschlüsselung von Daten und Vergleich mit der Standard-Implementierung.
    // Da die volle Integration eine Verbindung erfordern würde, beschränken wir uns hier auf den Aktivierungstest.
}

// Haupttest-Funktion
int main() {
    std::cout << "QuicSand SIMD-Integration-Test" << std::endl;
    std::cout << "==============================" << std::endl;
    
    // SIMD-Feature-Detection testen
    test_simd_feature_detection();
    
    // Optimierte FEC testen
    test_optimized_fec_integration();
    
    // Optimierte Kryptografie testen
    test_optimized_crypto_integration();
    
    std::cout << "\nAlle Tests abgeschlossen." << std::endl;
    
    return 0;
}
