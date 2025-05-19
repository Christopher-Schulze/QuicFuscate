#include "../core/cache_optimizations.hpp"
#include "../core/thread_optimizations.hpp"
#include "../core/energy_optimizations.hpp"
#include "../core/optimizations_integration.hpp"
#include "../fec/tetrys_fec.hpp"
#include "../fec/tetrys_fec_optimized.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cassert>
#include <iomanip>

using namespace quicsand;
using namespace quicsand::fec;
using namespace std::chrono;

// Hilfsfunktion für Benchmark
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

// Test für Tetrys FEC mit Cache-Optimierungen
void test_fec_with_cache_optimizations() {
    std::cout << "=== Tetrys FEC mit Cache-Optimierungen Test ===" << std::endl;
    
    const size_t packet_size = 1200; // Typische QUIC-Paketgröße
    const size_t block_size = 10;    // Anzahl der Datenpakete pro Block
    const double redundancy_rate = 0.3; // 30% Redundanz
    
    // Erstelle Testdaten
    std::vector<std::vector<uint8_t>> data_packets;
    for (size_t i = 0; i < block_size; ++i) {
        data_packets.push_back(generate_random_data(packet_size));
    }
    
    // Test mit Standard-Tetrys-FEC
    auto standard_fec_test = [&]() {
        TetrysEncoder encoder(block_size, redundancy_rate);
        TetrysDecoder decoder(block_size);
        
        // Pakete kodieren
        for (const auto& packet : data_packets) {
            encoder.add_source_packet(packet);
        }
        
        // Redundanzpakete generieren
        size_t repair_count = static_cast<size_t>(block_size * redundancy_rate);
        std::vector<std::vector<uint8_t>> repair_packets;
        for (size_t i = 0; i < repair_count; ++i) {
            repair_packets.push_back(encoder.generate_repair_packet());
        }
        
        // Paketverlust simulieren (20%)
        std::vector<bool> lost_packets = simulate_packet_loss(block_size, 0.2);
        
        // Pakete an den Decoder senden (mit Verlusten)
        for (size_t i = 0; i < block_size; ++i) {
            if (!lost_packets[i]) {
                decoder.process_source_packet(data_packets[i], i);
            }
        }
        
        // Repair-Pakete an den Decoder senden
        for (const auto& packet : repair_packets) {
            decoder.process_repair_packet(packet);
        }
        
        // Versuche, verlorene Pakete wiederherzustellen
        size_t recovered = 0;
        for (size_t i = 0; i < block_size; ++i) {
            if (lost_packets[i]) {
                auto recovered_packet = decoder.recover_source_packet(i);
                if (recovered_packet && recovered_packet->size() == packet_size) {
                    recovered++;
                }
            }
        }
        
        return recovered;
    };
    
    // Test mit Cache-optimierter Tetrys-FEC
    auto optimized_fec_test = [&]() {
        TetrysEncoderOptimized encoder(block_size, redundancy_rate);
        TetrysDecoderOptimized decoder(block_size);
        
        // Cache-optimierte Buffer
        std::vector<CacheOptimizedVector<uint8_t>> optimized_data_packets;
        for (const auto& packet : data_packets) {
            CacheOptimizedVector<uint8_t> opt_packet;
            opt_packet.reserve(packet.size());
            for (auto byte : packet) {
                opt_packet.push_back(byte);
            }
            optimized_data_packets.push_back(std::move(opt_packet));
        }
        
        // Pakete kodieren mit Prefetching
        for (auto& packet : optimized_data_packets) {
            Prefetcher::prefetch_array(packet.data(), packet.size());
            encoder.add_source_packet_optimized(packet);
        }
        
        // Redundanzpakete generieren
        size_t repair_count = static_cast<size_t>(block_size * redundancy_rate);
        std::vector<CacheOptimizedVector<uint8_t>> repair_packets;
        for (size_t i = 0; i < repair_count; ++i) {
            repair_packets.push_back(encoder.generate_repair_packet_optimized());
        }
        
        // Paketverlust simulieren (20%)
        std::vector<bool> lost_packets = simulate_packet_loss(block_size, 0.2);
        
        // Pakete an den Decoder senden (mit Verlusten)
        for (size_t i = 0; i < block_size; ++i) {
            if (!lost_packets[i]) {
                Prefetcher::prefetch_array(optimized_data_packets[i].data(), 
                                         optimized_data_packets[i].size());
                decoder.process_source_packet_optimized(optimized_data_packets[i], i);
            }
        }
        
        // Repair-Pakete an den Decoder senden
        for (auto& packet : repair_packets) {
            Prefetcher::prefetch_array(packet.data(), packet.size());
            decoder.process_repair_packet_optimized(packet);
        }
        
        // Versuche, verlorene Pakete wiederherzustellen
        size_t recovered = 0;
        for (size_t i = 0; i < block_size; ++i) {
            if (lost_packets[i]) {
                auto recovered_packet = decoder.recover_source_packet_optimized(i);
                if (recovered_packet && recovered_packet->size() == packet_size) {
                    recovered++;
                }
            }
        }
        
        return recovered;
    };
    
    // Führe Tests aus
    const int iterations = 100;
    double standard_time = measure_execution_time(standard_fec_test, iterations);
    size_t standard_recovered = standard_fec_test();
    
    double optimized_time = measure_execution_time(optimized_fec_test, iterations);
    size_t optimized_recovered = optimized_fec_test();
    
    std::cout << "Standard Tetrys FEC Zeit: " << standard_time << " µs" << std::endl;
    std::cout << "Optimierte Tetrys FEC Zeit: " << optimized_time << " µs" << std::endl;
    std::cout << "Verbesserung: " << std::fixed << std::setprecision(2) 
              << (standard_time / optimized_time) << "x" << std::endl;
    
    std::cout << "Standard wiederhergestellte Pakete: " << standard_recovered << std::endl;
    std::cout << "Optimiert wiederhergestellte Pakete: " << optimized_recovered << std::endl;
    
    assert(optimized_recovered >= standard_recovered);
    std::cout << "Test erfolgreich!" << std::endl;
}

// Test für Tetrys FEC mit Zero-Copy-Optimierungen
void test_fec_with_zero_copy() {
    std::cout << "\n=== Tetrys FEC mit Zero-Copy-Optimierungen Test ===" << std::endl;
    
    const size_t packet_size = 1200; // Typische QUIC-Paketgröße
    const size_t block_size = 10;    // Anzahl der Datenpakete pro Block
    const double redundancy_rate = 0.3; // 30% Redundanz
    
    // Erstelle Testdaten
    std::vector<uint8_t*> data_buffers;
    for (size_t i = 0; i < block_size; ++i) {
        uint8_t* buffer = new uint8_t[packet_size];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        
        for (size_t j = 0; j < packet_size; ++j) {
            buffer[j] = static_cast<uint8_t>(distrib(gen));
        }
        
        data_buffers.push_back(buffer);
    }
    
    // Test mit Standard-Kopieren
    auto copy_fec_test = [&]() {
        TetrysEncoder encoder(block_size, redundancy_rate);
        TetrysDecoder decoder(block_size);
        
        // Pakete kopieren und kodieren
        for (size_t i = 0; i < block_size; ++i) {
            std::vector<uint8_t> packet(data_buffers[i], data_buffers[i] + packet_size);
            encoder.add_source_packet(packet);
        }
        
        // Redundanzpakete generieren
        size_t repair_count = static_cast<size_t>(block_size * redundancy_rate);
        std::vector<std::vector<uint8_t>> repair_packets;
        for (size_t i = 0; i < repair_count; ++i) {
            repair_packets.push_back(encoder.generate_repair_packet());
        }
        
        // Paketverlust simulieren (20%)
        std::vector<bool> lost_packets = simulate_packet_loss(block_size, 0.2);
        
        // Pakete an den Decoder senden (mit Verlusten)
        for (size_t i = 0; i < block_size; ++i) {
            if (!lost_packets[i]) {
                std::vector<uint8_t> packet(data_buffers[i], data_buffers[i] + packet_size);
                decoder.process_source_packet(packet, i);
            }
        }
        
        // Repair-Pakete an den Decoder senden
        for (const auto& packet : repair_packets) {
            decoder.process_repair_packet(packet);
        }
        
        // Versuche, verlorene Pakete wiederherzustellen
        size_t recovered = 0;
        for (size_t i = 0; i < block_size; ++i) {
            if (lost_packets[i]) {
                auto recovered_packet = decoder.recover_source_packet(i);
                if (recovered_packet && recovered_packet->size() == packet_size) {
                    recovered++;
                }
            }
        }
        
        return recovered;
    };
    
    // Test mit Zero-Copy
    auto zero_copy_fec_test = [&]() {
        TetrysEncoderOptimized encoder(block_size, redundancy_rate);
        TetrysDecoderOptimized decoder(block_size);
        
        // Pakete mit Zero-Copy kodieren
        for (size_t i = 0; i < block_size; ++i) {
            encoder.add_source_packet_zero_copy(data_buffers[i], packet_size);
        }
        
        // Redundanzpakete generieren
        size_t repair_count = static_cast<size_t>(block_size * redundancy_rate);
        std::vector<std::vector<uint8_t>> repair_packets;
        for (size_t i = 0; i < repair_count; ++i) {
            repair_packets.push_back(encoder.generate_repair_packet());
        }
        
        // Paketverlust simulieren (20%)
        std::vector<bool> lost_packets = simulate_packet_loss(block_size, 0.2);
        
        // Pakete an den Decoder senden (mit Verlusten)
        for (size_t i = 0; i < block_size; ++i) {
            if (!lost_packets[i]) {
                decoder.process_source_packet_zero_copy(data_buffers[i], packet_size, i);
            }
        }
        
        // Repair-Pakete an den Decoder senden
        for (const auto& packet : repair_packets) {
            decoder.process_repair_packet(packet);
        }
        
        // Versuche, verlorene Pakete wiederherzustellen
        size_t recovered = 0;
        for (size_t i = 0; i < block_size; ++i) {
            if (lost_packets[i]) {
                auto recovered_packet = decoder.recover_source_packet(i);
                if (recovered_packet && recovered_packet->size() == packet_size) {
                    recovered++;
                }
            }
        }
        
        return recovered;
    };
    
    // Führe Tests aus
    const int iterations = 100;
    double copy_time = measure_execution_time(copy_fec_test, iterations);
    size_t copy_recovered = copy_fec_test();
    
    double zero_copy_time = measure_execution_time(zero_copy_fec_test, iterations);
    size_t zero_copy_recovered = zero_copy_fec_test();
    
    std::cout << "Standard-Kopieren Tetrys FEC Zeit: " << copy_time << " µs" << std::endl;
    std::cout << "Zero-Copy Tetrys FEC Zeit: " << zero_copy_time << " µs" << std::endl;
    std::cout << "Verbesserung: " << std::fixed << std::setprecision(2) 
              << (copy_time / zero_copy_time) << "x" << std::endl;
    
    std::cout << "Kopieren wiederhergestellte Pakete: " << copy_recovered << std::endl;
    std::cout << "Zero-Copy wiederhergestellte Pakete: " << zero_copy_recovered << std::endl;
    
    assert(zero_copy_recovered >= copy_recovered);
    std::cout << "Test erfolgreich!" << std::endl;
    
    // Speicher freigeben
    for (auto buffer : data_buffers) {
        delete[] buffer;
    }
}

// Test für Tetrys FEC mit Energy-Optimierungen
void test_fec_with_energy_optimization() {
    std::cout << "\n=== Tetrys FEC mit Energy-Optimierungen Test ===" << std::endl;
    
    const size_t packet_size = 1200; // Typische QUIC-Paketgröße
    const size_t block_size = 10;    // Anzahl der Datenpakete pro Block
    
    // Erstelle Testdaten
    std::vector<std::vector<uint8_t>> data_packets;
    for (size_t i = 0; i < block_size; ++i) {
        data_packets.push_back(generate_random_data(packet_size));
    }
    
    // Teste verschiedene Redundanzraten unter verschiedenen Energiemodi
    auto test_redundancy = [&](double redundancy_rate, ThreadEnergyMode mode) {
        // Konfiguriere Energy-Manager
        EnergyConfig config;
        config.thread_mode = mode;
        EnergyManager energy_manager(config);
        
        // Worker-Pool
        EnergyEfficientWorkerPool pool(2, mode);
        
        // Adaptive Redundanzrate basierend auf Energiemodus
        double effective_rate = redundancy_rate;
        if (mode == ThreadEnergyMode::EFFICIENT || mode == ThreadEnergyMode::ULTRA_EFFICIENT) {
            // Reduziere Redundanz im Energiesparmodus
            effective_rate *= 0.8;
        }
        
        TetrysEncoderOptimized encoder(block_size, effective_rate);
        TetrysDecoderOptimized decoder(block_size);
        
        // Prozessiere Pakete asynchron
        std::atomic<bool> processing_done{false};
        std::atomic<size_t> processed_packets{0};
        
        // Starte asynchrone Verarbeitung
        auto start = high_resolution_clock::now();
        
        pool.enqueue([&]() {
            // Pakete kodieren
            for (const auto& packet : data_packets) {
                encoder.add_source_packet(packet);
                processed_packets++;
            }
            
            // Redundanzpakete generieren
            size_t repair_count = static_cast<size_t>(block_size * effective_rate);
            std::vector<std::vector<uint8_t>> repair_packets;
            for (size_t i = 0; i < repair_count; ++i) {
                repair_packets.push_back(encoder.generate_repair_packet());
            }
            
            // Paketverlust simulieren (20%)
            std::vector<bool> lost_packets = simulate_packet_loss(block_size, 0.2);
            
            // Pakete an den Decoder senden (mit Verlusten)
            for (size_t i = 0; i < block_size; ++i) {
                if (!lost_packets[i]) {
                    decoder.process_source_packet(data_packets[i], i);
                }
            }
            
            // Repair-Pakete an den Decoder senden
            for (const auto& packet : repair_packets) {
                decoder.process_repair_packet(packet);
            }
            
            // Versuche, verlorene Pakete wiederherzustellen
            size_t recovered = 0;
            for (size_t i = 0; i < block_size; ++i) {
                if (lost_packets[i]) {
                    auto recovered_packet = decoder.recover_source_packet(i);
                    if (recovered_packet && recovered_packet->size() == packet_size) {
                        recovered++;
                    }
                }
            }
            
            processing_done = true;
        });
        
        // Warte effizient auf Abschluss
        energy_manager.wait_efficiently([&]() {
            return processing_done.load();
        });
        
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(end - start).count();
        
        return std::make_pair(duration, processed_packets.load());
    };
    
    // Teste verschiedene Energiemodi
    auto performance_result = test_redundancy(0.3, ThreadEnergyMode::PERFORMANCE);
    auto balanced_result = test_redundancy(0.3, ThreadEnergyMode::BALANCED);
    auto efficient_result = test_redundancy(0.3, ThreadEnergyMode::EFFICIENT);
    
    std::cout << "PERFORMANCE Modus: " << performance_result.first << " ms, "
              << performance_result.second << " Pakete verarbeitet" << std::endl;
    std::cout << "BALANCED Modus: " << balanced_result.first << " ms, "
              << balanced_result.second << " Pakete verarbeitet" << std::endl;
    std::cout << "EFFICIENT Modus: " << efficient_result.first << " ms, "
              << efficient_result.second << " Pakete verarbeitet" << std::endl;
    
    std::cout << "Test erfolgreich!" << std::endl;
}

// Hauptfunktion
int main() {
    std::cout << "Tetrys FEC Optimierungen Integrationstest" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    test_fec_with_cache_optimizations();
    test_fec_with_zero_copy();
    test_fec_with_energy_optimization();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    return 0;
}
