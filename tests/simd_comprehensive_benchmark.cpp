#include <iostream>
#include <vector>
#include <chrono>
#include <array>
#include <iomanip>
#include <random>
#include <memory>
#include <algorithm>
#include <functional>

#include "../core/quic_connection.hpp"
#include "../core/simd_optimizations.hpp"
#include "../crypto/aes128gcm_optimized.hpp"
#include "../crypto/aes128gcm.hpp"
#include "../fec/tetrys_fec_optimized.hpp"
#include "../fec/tetrys_fec.hpp"

using namespace quicsand;
using namespace quicsand::crypto;
using namespace std::chrono;

// Utility-Funktionen für Benchmarking
template<typename Func>
double measure_execution_time_ms(Func&& func, size_t iterations = 1) {
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
        func();
    }
    auto end = high_resolution_clock::now();
    double time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
    return time_ms / iterations; // Durchschnittliche Zeit pro Iteration
}

// Zufallsdaten generieren
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

// Benchmark-Header ausgeben
void print_benchmark_header(const std::string& title) {
    std::cout << "\n=========================================" << std::endl;
    std::cout << title << std::endl;
    std::cout << "==========================================" << std::endl;
}

// Benchmark-Ergebnisse ausgeben
void print_benchmark_result(const std::string& name, double standard_time, double optimized_time) {
    double speedup = standard_time / optimized_time;
    std::cout << std::left << std::setw(30) << name << ": " 
              << std::fixed << std::setprecision(3) 
              << std::setw(8) << standard_time << " ms vs. " 
              << std::setw(8) << optimized_time << " ms  "
              << "Speedup: " << std::setw(5) << speedup << "x" << std::endl;
}

// XOR-Benchmark
void benchmark_xor_operations() {
    print_benchmark_header("XOR-Operations Benchmark");
    
    const std::vector<size_t> data_sizes = {1024, 8*1024, 64*1024, 512*1024, 1024*1024};
    
    for (auto size : data_sizes) {
        // Testdaten erstellen
        std::vector<uint8_t> data1 = generate_random_data(size);
        std::vector<uint8_t> data2 = generate_random_data(size);
        std::vector<uint8_t> result_std(size);
        std::vector<uint8_t> result_opt(size);
        
        // Standard-Implementierung
        TetrysFEC fec_std;
        double std_time = measure_execution_time_ms([&]() {
            result_std = data1;
            fec_std.xor_buffers(result_std, data2);
        }, 10);
        
        // Optimierte Implementierung
        OptimizedTetrysFEC fec_opt;
        double opt_time = measure_execution_time_ms([&]() {
            result_opt = data1;
            auto span1 = memory_span<uint8_t>(result_opt.data(), result_opt.size());
            auto span2 = memory_span<uint8_t>(data2.data(), data2.size());
            fec_opt.xor_buffers(span1, span2);
        }, 10);
        
        // Ergebnis ausgeben
        std::string name = "XOR " + std::to_string(size/1024) + " KB";
        print_benchmark_result(name, std_time, opt_time);
        
        // Validate Ergebnisse
        bool results_match = std::equal(result_std.begin(), result_std.end(), result_opt.begin());
        if (!results_match) {
            std::cout << "FEHLER: Ergebnisse stimmen nicht überein!" << std::endl;
        }
    }
}

// AES-GCM-Benchmark
void benchmark_aes_gcm() {
    print_benchmark_header("AES-GCM Encryption/Decryption Benchmark");
    
    const std::vector<size_t> data_sizes = {1024, 8*1024, 64*1024, 256*1024};
    std::array<uint8_t, 16> key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    std::vector<uint8_t> iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    
    for (auto size : data_sizes) {
        // Testdaten erstellen
        std::vector<uint8_t> plaintext = generate_random_data(size);
        std::vector<uint8_t> ciphertext_std(size);
        std::vector<uint8_t> ciphertext_opt(size);
        std::vector<uint8_t> decrypted_std(size);
        std::vector<uint8_t> decrypted_opt(size);
        
        // Standard-Implementierung
        Aes128Gcm aes_std(key, iv);
        
        // Verschlüsselung Standard
        double encrypt_std_time = measure_execution_time_ms([&]() {
            aes_std.encrypt(ciphertext_std.data(), plaintext.data(), plaintext.size());
        }, 5);
        
        // Entschlüsselung Standard
        double decrypt_std_time = measure_execution_time_ms([&]() {
            aes_std.decrypt(decrypted_std.data(), ciphertext_std.data(), ciphertext_std.size());
        }, 5);
        
        // Optimierte Implementierung
        Aes128GcmOptimized aes_opt(key, iv);
        
        // Verschlüsselung Optimiert
        double encrypt_opt_time = measure_execution_time_ms([&]() {
            aes_opt.encrypt(ciphertext_opt.data(), plaintext.data(), plaintext.size());
        }, 5);
        
        // Entschlüsselung Optimiert
        double decrypt_opt_time = measure_execution_time_ms([&]() {
            aes_opt.decrypt(decrypted_opt.data(), ciphertext_opt.data(), ciphertext_opt.size());
        }, 5);
        
        // Ergebnis ausgeben
        std::string encrypt_name = "AES-GCM Encrypt " + std::to_string(size/1024) + " KB";
        std::string decrypt_name = "AES-GCM Decrypt " + std::to_string(size/1024) + " KB";
        
        print_benchmark_result(encrypt_name, encrypt_std_time, encrypt_opt_time);
        print_benchmark_result(decrypt_name, decrypt_std_time, decrypt_opt_time);
        
        // Validiere Ergebnisse
        bool encrypt_results_match = std::equal(decrypted_std.begin(), decrypted_std.end(), plaintext.begin());
        bool decrypt_results_match = std::equal(decrypted_opt.begin(), decrypted_opt.end(), plaintext.begin());
        
        if (!encrypt_results_match || !decrypt_results_match) {
            std::cout << "FEHLER: Ergebnisse stimmen nicht überein!" << std::endl;
        }
    }
}

// FEC-Benchmark
void benchmark_fec() {
    print_benchmark_header("Tetrys FEC Benchmark");
    
    const std::vector<size_t> packet_sizes = {512, 1024, 4*1024};
    const int packet_count = 10;
    
    for (auto size : packet_sizes) {
        // Testpakete generieren
        std::vector<std::vector<uint8_t>> packets;
        for (int i = 0; i < packet_count; i++) {
            packets.push_back(generate_random_data(size));
        }
        
        // Standard-Implementierung
        TetrysFEC fec_std;
        fec_std.set_params(3, 10); // 3 Reparaturpakete für 10 Quellpakete
        
        // Kodierungszeit messen (Standard)
        double encode_std_time = measure_execution_time_ms([&]() {
            for (const auto& packet : packets) {
                fec_std.add_source_packet(packet);
            }
            auto repair_packets = fec_std.generate_repair_packets();
        }, 5);
        
        // FEC-Dekodierung simulieren (Standard)
        double decode_std_time = measure_execution_time_ms([&]() {
            TetrysFEC decoder_std;
            decoder_std.set_params(3, 10);
            
            // Simuliere Paketverlust (2 von 10 Paketen verloren)
            for (int i = 0; i < packet_count; i++) {
                if (i != 2 && i != 5) { // Pakete 2 und 5 gehen "verloren"
                    TetrysFEC::TetrysPacket packet;
                    packet.data = packets[i];
                    packet.seq_num = i;
                    packet.is_repair = false;
                    decoder_std.add_received_packet(packet);
                }
            }
            
            // Reparaturpakete erstellen und zum Decoder hinzufügen
            auto repair_packets = fec_std.generate_repair_packets();
            for (size_t i = 0; i < repair_packets.size(); i++) {
                decoder_std.add_received_packet(repair_packets[i]);
            }
            
            // Versuche Pakete wiederherzustellen
            decoder_std.try_recover_missing_packets();
        }, 3);
        
        // Optimierte Implementierung
        OptimizedTetrysFEC fec_opt;
        fec_opt.set_params(3, 10); // 3 Reparaturpakete für 10 Quellpakete
        
        // Kodierungszeit messen (Optimiert)
        double encode_opt_time = measure_execution_time_ms([&]() {
            for (const auto& packet : packets) {
                auto buffer = std::make_shared<std::vector<uint8_t>>(packet);
                auto span = memory_span<uint8_t>(buffer->data(), buffer->size());
                fec_opt.add_source_packet(span);
            }
            auto repair_packets = fec_opt.generate_repair_packets();
        }, 5);
        
        // FEC-Dekodierung simulieren (Optimiert)
        double decode_opt_time = measure_execution_time_ms([&]() {
            OptimizedTetrysFEC decoder_opt;
            decoder_opt.set_params(3, 10);
            
            // Simuliere Paketverlust (2 von 10 Paketen verloren)
            for (int i = 0; i < packet_count; i++) {
                if (i != 2 && i != 5) { // Pakete 2 und 5 gehen "verloren"
                    OptimizedTetrysFEC::TetrysPacket packet;
                    auto buffer = std::make_shared<std::vector<uint8_t>>(packets[i]);
                    auto span = memory_span<uint8_t>(buffer->data(), buffer->size());
                    packet.seq_num = i;
                    packet.is_repair = false;
                    packet.assign_from_pool(buffer, span);
                    decoder_opt.add_received_packet(packet);
                }
            }
            
            // Reparaturpakete erstellen und zum Decoder hinzufügen
            auto repair_packets = fec_opt.generate_repair_packets();
            for (auto& packet : repair_packets) {
                decoder_opt.add_received_packet(packet);
            }
            
            // Versuche Pakete wiederherzustellen
            decoder_opt.try_recover_missing_packets();
        }, 3);
        
        // Ergebnis ausgeben
        std::string encode_name = "FEC Encode " + std::to_string(size) + " B x " + std::to_string(packet_count);
        std::string decode_name = "FEC Decode " + std::to_string(size) + " B x " + std::to_string(packet_count);
        
        print_benchmark_result(encode_name, encode_std_time, encode_opt_time);
        print_benchmark_result(decode_name, decode_std_time, decode_opt_time);
    }
}

// QUIC-Transportschicht-Test
void benchmark_quic_integration() {
    print_benchmark_header("QUIC Transport SIMD Integration Test");
    
    boost::asio::io_context io_context;
    QuicConfig config;
    QuicConnection connection(io_context, config);
    
    // SIMD-Support prüfen
    bool has_simd = connection.has_simd_support();
    std::cout << "SIMD-Unterstützung: " << (has_simd ? "Ja" : "Nein") << std::endl;
    std::cout << "SIMD-Features: " << connection.get_simd_features_string() << std::endl;
    
    if (!has_simd) {
        std::cout << "SIMD-Tests werden übersprungen, da keine SIMD-Unterstützung vorhanden ist." << std::endl;
        return;
    }
    
    // FEC aktivieren/deaktivieren Benchmark
    const size_t data_size = 1024 * 64; // 64KB Testdaten
    std::vector<uint8_t> test_data = generate_random_data(data_size);
    
    // FEC-Operationen mit Standard-Implementierung
    double fec_std_time = measure_execution_time_ms([&]() {
        connection.enable_optimized_fec(false);
        connection.enable_fec(true);
        std::vector<uint8_t> encoded = connection.apply_fec_encoding(test_data.data(), test_data.size());
        std::vector<uint8_t> decoded = connection.apply_fec_decoding(encoded.data(), encoded.size());
    }, 5);
    
    // FEC-Operationen mit optimierter Implementierung
    double fec_opt_time = measure_execution_time_ms([&]() {
        connection.enable_optimized_fec(true);
        connection.enable_fec(true);
        std::vector<uint8_t> encoded = connection.apply_fec_encoding(test_data.data(), test_data.size());
        std::vector<uint8_t> decoded = connection.apply_fec_decoding(encoded.data(), encoded.size());
    }, 5);
    
    // Ergebnis ausgeben
    print_benchmark_result("QUIC FEC Integration", fec_std_time, fec_opt_time);
    
    // Krypto aktivieren/deaktivieren Benchmark
    bool crypto_result = connection.enable_optimized_crypto(true);
    std::cout << "SIMD-optimierte Kryptografie aktiviert: " << (crypto_result ? "Ja" : "Nein") << std::endl;
}

// Hauptprogramm
int main() {
    std::cout << "QuicSand SIMD-Optimierungen Comprehensive Benchmark" << std::endl;
    std::cout << "===================================================" << std::endl;
    
    // Hardware-Informationen anzeigen
    #ifdef __APPLE__
        std::cout << "Platform: Apple " << 
        #ifdef __aarch64__
            "ARM64" 
        #else
            "x86_64"
        #endif
        << std::endl;
    #else
        std::cout << "Platform: Non-Apple" << std::endl;
    #endif
    
    // SIMD-Unterstützung anzeigen
    std::cout << "SIMD Support: ";
    #ifdef __ARM_NEON
        std::cout << "ARM NEON" << std::endl;
    #elif defined(__AVX2__)
        std::cout << "AVX2" << std::endl;
    #elif defined(__AVX__)
        std::cout << "AVX" << std::endl;
    #elif defined(__SSE4_2__)
        std::cout << "SSE4.2" << std::endl;
    #else
        std::cout << "None" << std::endl;
    #endif
    
    // Alle Benchmarks ausführen
    benchmark_xor_operations();
    benchmark_aes_gcm();
    benchmark_fec();
    benchmark_quic_integration();
    
    std::cout << "\nAlle Benchmarks abgeschlossen!" << std::endl;
    
    return 0;
}
