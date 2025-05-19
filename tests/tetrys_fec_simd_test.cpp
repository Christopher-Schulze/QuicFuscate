#include "../fec/tetrys_fec_optimized.hpp"
#include "../core/simd_optimizations.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <iomanip>
#include <cassert>

using namespace quicsand;
using namespace std::chrono;

// Hilfsfunktion zur Messung der Ausführungszeit
template<typename Func>
double measure_execution_time(Func&& func, int iterations = 1) {
    auto start = high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        func();
    }
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    return static_cast<double>(duration) / iterations;
}

// Hilfsfunktion zum Erstellen von zufälligen Daten
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(distrib(gen));
    }
    
    return data;
}

// Hilfsfunktion zum Simulieren von Paketverlusten
std::vector<bool> simulate_packet_loss(size_t packet_count, double loss_rate) {
    std::vector<bool> lost_packets(packet_count, false);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> distrib(0.0, 1.0);
    
    for (size_t i = 0; i < packet_count; ++i) {
        if (distrib(gen) < loss_rate) {
            lost_packets[i] = true;
        }
    }
    
    return lost_packets;
}

// Test der SIMD-optimierten XOR-Operation in Tetrys FEC
void test_xor_performance() {
    std::cout << "=== SIMD-optimierte XOR-Operation Test ===" << std::endl;
    
    // Erstelle Testdaten
    std::vector<size_t> sizes = {1024, 8192, 32768, 262144, 1048576}; // 1KB, 8KB, 32KB, 256KB, 1MB
    
    for (auto size : sizes) {
        std::vector<uint8_t> src_buffer = generate_random_data(size);
        std::vector<uint8_t> dst_buffer = generate_random_data(size);
        std::vector<uint8_t> dst_buffer_simd = dst_buffer; // Kopie für SIMD-Test
        
        // Messe nicht-optimierte XOR-Operation
        double standard_time = measure_execution_time([&]() {
            for (size_t i = 0; i < size; ++i) {
                dst_buffer[i] ^= src_buffer[i];
            }
        }, 10);
        
        // Messe optimierte XOR-Operation
        memory_span<uint8_t> dst_span(dst_buffer_simd.data(), dst_buffer_simd.size());
        memory_span<uint8_t> src_span(src_buffer.data(), src_buffer.size());
        
        OptimizedTetrysFEC fec(10, 3); // Dummy-Konfiguration
        double simd_time = measure_execution_time([&]() {
            fec.xor_buffers(dst_span, src_span);
        }, 10);
        
        // Überprüfe, ob beide Implementierungen die gleichen Ergebnisse liefern
        bool results_match = true;
        for (size_t i = 0; i < size; ++i) {
            if (dst_buffer[i] != dst_buffer_simd[i]) {
                results_match = false;
                break;
            }
        }
        
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "Standard XOR Zeit: " << std::fixed << std::setprecision(3) << standard_time << " µs" << std::endl;
        std::cout << "SIMD XOR Zeit: " << std::fixed << std::setprecision(3) << simd_time << " µs" << std::endl;
        std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
                  << (standard_time / simd_time) << "x" << std::endl;
        std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
        std::cout << std::endl;
        
        // Bestätige, dass die Ergebnisse übereinstimmen
        assert(results_match);
    }
}

// Test der Galois-Feld-Operationen in Tetrys FEC
void test_galois_field_operations() {
    std::cout << "\n=== SIMD-optimierte Galois-Feld-Operationen Test ===" << std::endl;
    
    const size_t data_size = 65536; // 64KB
    std::vector<uint8_t> a = generate_random_data(data_size);
    std::vector<uint8_t> b = generate_random_data(data_size);
    std::vector<uint8_t> result_std(data_size);
    std::vector<uint8_t> result_simd(data_size);
    
    // Erstelle eine FEC-Instanz für Galois-Feld-Operationen
    OptimizedTetrysFEC fec(10, 3);
    
    // Test für Galois-Feld-Addition (XOR)
    std::cout << "Galois-Feld-Addition (XOR):" << std::endl;
    
    // Standard-Implementierung
    double std_add_time = measure_execution_time([&]() {
        for (size_t i = 0; i < data_size; ++i) {
            result_std[i] = a[i] ^ b[i];
        }
    }, 10);
    
    // SIMD-optimierte Implementierung
    double simd_add_time = measure_execution_time([&]() {
        fec.gf_add_simd(a.data(), b.data(), result_simd.data(), data_size);
    }, 10);
    
    // Überprüfe Ergebnisse
    bool add_results_match = true;
    for (size_t i = 0; i < data_size; ++i) {
        if (result_std[i] != result_simd[i]) {
            add_results_match = false;
            break;
        }
    }
    
    std::cout << "Standard Addition Zeit: " << std::fixed << std::setprecision(3) << std_add_time << " µs" << std::endl;
    std::cout << "SIMD Addition Zeit: " << std::fixed << std::setprecision(3) << simd_add_time << " µs" << std::endl;
    std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
              << (std_add_time / simd_add_time) << "x" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (add_results_match ? "Ja" : "Nein") << std::endl;
    std::cout << std::endl;
    
    // Test für Galois-Feld-Multiplikation
    std::cout << "Galois-Feld-Multiplikation:" << std::endl;
    
    // Zurücksetzen der Ergebnisse
    std::fill(result_std.begin(), result_std.end(), 0);
    std::fill(result_simd.begin(), result_simd.end(), 0);
    
    // Standard-Implementierung
    double std_mul_time = measure_execution_time([&]() {
        for (size_t i = 0; i < data_size; ++i) {
            result_std[i] = fec.gf_mul(a[i], b[i]);
        }
    }, 5);
    
    // SIMD-optimierte Implementierung
    double simd_mul_time = measure_execution_time([&]() {
        fec.gf_mul_simd(a.data(), b.data(), result_simd.data(), data_size);
    }, 5);
    
    // Überprüfe Ergebnisse
    bool mul_results_match = true;
    for (size_t i = 0; i < data_size; ++i) {
        if (result_std[i] != result_simd[i]) {
            mul_results_match = false;
            break;
        }
    }
    
    std::cout << "Standard Multiplikation Zeit: " << std::fixed << std::setprecision(3) << std_mul_time << " µs" << std::endl;
    std::cout << "SIMD Multiplikation Zeit: " << std::fixed << std::setprecision(3) << simd_mul_time << " µs" << std::endl;
    std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
              << (std_mul_time / simd_mul_time) << "x" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (mul_results_match ? "Ja" : "Nein") << std::endl;
}

// End-to-End-Test mit simuliertem Paketverlust
void test_fec_end_to_end() {
    std::cout << "\n=== Tetrys FEC End-to-End-Test mit SIMD-Optimierungen ===" << std::endl;
    
    // Konfiguration
    const size_t packet_size = 1024;
    const size_t num_packets = 50;
    const double loss_rate = 0.2; // 20% Paketverlust
    
    // Erzeuge Testdaten
    std::vector<std::vector<uint8_t>> data_packets;
    for (size_t i = 0; i < num_packets; ++i) {
        data_packets.push_back(generate_random_data(packet_size));
    }
    
    // Simuliere Paketverlust
    std::vector<bool> lost_packets = simulate_packet_loss(num_packets, loss_rate);
    size_t lost_count = std::count(lost_packets.begin(), lost_packets.end(), true);
    
    std::cout << "Testdaten: " << num_packets << " Pakete, " << packet_size << " Bytes/Paket" << std::endl;
    std::cout << "Simulierter Paketverlust: " << lost_count << " Pakete (" 
              << (lost_count * 100.0 / num_packets) << "%)" << std::endl;
    
    // Erstelle FEC-Instanzen
    OptimizedTetrysFEC::Config config;
    config.window_size = 10;
    config.initial_redundancy = 0.3;
    config.adaptive = true;
    
    OptimizedTetrysFEC fec(config);
    
    // Kodiere und dekodiere mit Zeitmessung
    double encoding_time = measure_execution_time([&]() {
        for (const auto& packet : data_packets) {
            fec.encode_packet(packet);
        }
    });
    
    // Empfange Pakete und dekodiere
    std::vector<OptimizedTetrysFEC::TetrysPacket> encoded_packets;
    for (size_t i = 0; i < num_packets; ++i) {
        auto packets = fec.encode_packet(data_packets[i]);
        encoded_packets.insert(encoded_packets.end(), packets.begin(), packets.end());
    }
    
    // Zweite FEC-Instanz zum Dekodieren
    OptimizedTetrysFEC decoder(config);
    
    // Filtern der verlorenen Pakete
    std::vector<OptimizedTetrysFEC::TetrysPacket> received_packets;
    for (const auto& packet : encoded_packets) {
        if (packet.is_repair || !lost_packets[packet.seq_num % num_packets]) {
            received_packets.push_back(packet);
        }
    }
    
    double decoding_time = measure_execution_time([&]() {
        for (const auto& packet : received_packets) {
            decoder.add_received_packet(packet);
        }
    });
    
    // Ergebnisse auswerten
    auto recovered_data = decoder.get_recovered_data();
    size_t recovered_size = recovered_data.size();
    size_t expected_size = num_packets * packet_size;
    double recovery_ratio = static_cast<double>(recovered_size) / expected_size;
    
    std::cout << "Kodierungszeit: " << std::fixed << std::setprecision(3) << encoding_time << " µs" << std::endl;
    std::cout << "Dekodierungszeit: " << std::fixed << std::setprecision(3) << decoding_time << " µs" << std::endl;
    std::cout << "Wiederhergestellte Daten: " << recovered_size << " / " << expected_size 
              << " Bytes (" << std::fixed << std::setprecision(2) << (recovery_ratio * 100) << "%)" << std::endl;
    std::cout << "Aktuelle Redundanzrate: " << std::fixed << std::setprecision(2) 
              << (fec.get_current_redundancy_rate() * 100) << "%" << std::endl;
}

// Hauptfunktion
int main() {
    // Prüfe, ob SIMD-Unterstützung vorhanden ist
    auto features = simd::detect_cpu_features();
    std::cout << "CPU SIMD-Funktionen: " << simd::features_to_string(features) << std::endl;
    
    // Führe Tests aus
    test_xor_performance();
    test_galois_field_operations();
    test_fec_end_to_end();
    
    std::cout << "\nAlle Tests abgeschlossen!" << std::endl;
    return 0;
}
