#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>
#include <memory>
#include <string>
#include <cassert>
#include <functional>

#include "../core/quic_connection.hpp"
#include "../core/quic_stream.hpp"
#include "../core/quic_config.hpp"
#include "../core/simd_optimizations.hpp"
#include "../crypto/aes128gcm_optimized.hpp"
#include "../crypto/aes128gcm.hpp"
#include "../fec/tetrys_fec_optimized.hpp"
#include "../fec/tetrys_fec.hpp"

using namespace quicsand;
using namespace std::chrono;

// Timer-Klasse für Performance-Messungen
class Timer {
private:
    time_point<high_resolution_clock> start_time;
    std::string name;
    
public:
    Timer(const std::string& timer_name) : name(timer_name) {
        start_time = high_resolution_clock::now();
    }
    
    ~Timer() {
        auto end_time = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end_time - start_time).count();
        std::cout << std::setw(30) << std::left << name << ": " 
                  << std::fixed << std::setprecision(3) << (duration / 1000.0) << " ms" << std::endl;
    }
};

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

// Helper-Funktion zum Packen mehrerer Pakete in einen Buffer
std::vector<uint8_t> pack_packets(const std::vector<std::vector<uint8_t>>& packets) {
    size_t total_size = 0;
    for (const auto& packet : packets) {
        total_size += packet.size() + sizeof(uint32_t); // größe + daten
    }
    
    std::vector<uint8_t> result(total_size);
    size_t offset = 0;
    
    for (const auto& packet : packets) {
        uint32_t size = static_cast<uint32_t>(packet.size());
        std::memcpy(result.data() + offset, &size, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        std::memcpy(result.data() + offset, packet.data(), packet.size());
        offset += packet.size();
    }
    
    return result;
}

// Helper-Funktion zum Entpacken von Paketen aus einem Buffer
std::vector<std::vector<uint8_t>> unpack_packets(const std::vector<uint8_t>& data) {
    std::vector<std::vector<uint8_t>> result;
    size_t offset = 0;
    
    while (offset + sizeof(uint32_t) <= data.size()) {
        uint32_t size;
        std::memcpy(&size, data.data() + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        if (offset + size > data.size()) {
            break; // Korrupte Daten
        }
        
        std::vector<uint8_t> packet(data.data() + offset, data.data() + offset + size);
        result.push_back(packet);
        offset += size;
    }
    
    return result;
}

// End-to-End Test für QUIC mit SIMD-Optimierungen
void test_quic_end_to_end() {
    std::cout << "\n======== QUIC End-to-End Test mit SIMD-Optimierungen ========" << std::endl;
    
    // QUIC-Setup
    boost::asio::io_context io_context;
    QuicConfig config;
    QuicConnection connection(io_context, config);
    
    // Prüfe SIMD-Unterstützung
    bool has_simd = connection.has_simd_support();
    std::cout << "SIMD-Unterstützung: " << (has_simd ? "Ja" : "Nein") << std::endl;
    
    if (has_simd) {
        std::cout << "SIMD-Features: " << connection.get_simd_features_string() << std::endl;
    } else {
        std::cout << "Test wird trotzdem fortgesetzt, aber ohne SIMD-Optimierungen." << std::endl;
    }
    
    // Test mit verschiedenen Paketgrößen
    const std::vector<size_t> packet_sizes = {1*1024, 16*1024, 64*1024};
    const int packet_count = 10;
    
    for (auto packet_size : packet_sizes) {
        std::cout << "\nTeste mit Paketgröße: " << packet_size / 1024 << " KB, " 
                  << packet_count << " Pakete" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        
        // Testpakete erstellen
        std::vector<std::vector<uint8_t>> packets;
        for (int i = 0; i < packet_count; i++) {
            packets.push_back(generate_random_data(packet_size));
        }
        
        // End-to-End Test mit Standard-Implementierung
        std::cout << "STANDARD-IMPLEMENTIERUNG:" << std::endl;
        connection.enable_optimized_fec(false);
        connection.enable_optimized_crypto(false);
        connection.enable_fec(true);
        
        std::vector<std::vector<uint8_t>> encoded_packets_std;
        {
            Timer timer("FEC-Kodierung (Standard)");
            for (const auto& packet : packets) {
                auto encoded = connection.apply_fec_encoding(packet.data(), packet.size());
                encoded_packets_std.push_back(encoded);
            }
        }
        
        // Packe alle kodierten Pakete in einen einzigen Buffer
        std::vector<uint8_t> packed_encoded_std = pack_packets(encoded_packets_std);
        
        // Dekodierung
        std::vector<std::vector<uint8_t>> decoded_packets_std;
        {
            Timer timer("FEC-Dekodierung (Standard)");
            auto unpacked = unpack_packets(packed_encoded_std);
            for (const auto& packet : unpacked) {
                auto decoded = connection.apply_fec_decoding(packet.data(), packet.size());
                decoded_packets_std.push_back(decoded);
            }
        }
        
        // End-to-End Test mit SIMD-Optimierungen
        if (has_simd) {
            std::cout << "\nSIMD-OPTIMIERTE IMPLEMENTIERUNG:" << std::endl;
            connection.enable_optimized_fec(true);
            connection.enable_optimized_crypto(true);
            connection.enable_fec(true);
            
            std::vector<std::vector<uint8_t>> encoded_packets_simd;
            {
                Timer timer("FEC-Kodierung (SIMD)");
                for (const auto& packet : packets) {
                    auto encoded = connection.apply_fec_encoding(packet.data(), packet.size());
                    encoded_packets_simd.push_back(encoded);
                }
            }
            
            // Packe alle kodierten Pakete in einen einzigen Buffer
            std::vector<uint8_t> packed_encoded_simd = pack_packets(encoded_packets_simd);
            
            // Dekodierung
            std::vector<std::vector<uint8_t>> decoded_packets_simd;
            {
                Timer timer("FEC-Dekodierung (SIMD)");
                auto unpacked = unpack_packets(packed_encoded_simd);
                for (const auto& packet : unpacked) {
                    auto decoded = connection.apply_fec_decoding(packet.data(), packet.size());
                    decoded_packets_simd.push_back(decoded);
                }
            }
            
            // Verifikation
            bool all_match = true;
            for (size_t i = 0; i < packets.size() && i < decoded_packets_simd.size(); i++) {
                if (packets[i] != decoded_packets_simd[i]) {
                    all_match = false;
                    std::cout << "FEHLER: Paket " << i << " stimmt nicht mit Original überein (SIMD)" << std::endl;
                    break;
                }
            }
            
            if (all_match) {
                std::cout << "Verifikation: Alle SIMD-dekodierten Pakete stimmen mit Originalen überein." << std::endl;
            }
        }
        
        // Verifikation für Standard-Implementierung
        bool all_match_std = true;
        for (size_t i = 0; i < packets.size() && i < decoded_packets_std.size(); i++) {
            if (packets[i] != decoded_packets_std[i]) {
                all_match_std = false;
                std::cout << "FEHLER: Paket " << i << " stimmt nicht mit Original überein (Standard)" << std::endl;
                break;
            }
        }
        
        if (all_match_std) {
            std::cout << "Verifikation: Alle Standard-dekodierten Pakete stimmen mit Originalen überein." << std::endl;
        }
    }
}

// Test für die Optimierte AES-GCM Implementierung
void test_aes_gcm_optimized() {
    std::cout << "\n======== AES-GCM Optimized Test ========" << std::endl;
    
    // Teste mit verschiedenen Datengrößen
    const std::vector<size_t> data_sizes = {1*1024, 16*1024, 64*1024, 256*1024};
    
    // AES-Schlüssel und IV erstellen
    std::array<uint8_t, 16> key;
    std::vector<uint8_t> iv(12);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < 16; i++) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    
    for (size_t i = 0; i < 12; i++) {
        iv[i] = static_cast<uint8_t>(dis(gen));
    }
    
    for (auto data_size : data_sizes) {
        std::cout << "\nTeste mit Datengröße: " << data_size / 1024 << " KB" << std::endl;
        std::cout << std::string(40, '-') << std::endl;
        
        // Testdaten erstellen
        std::vector<uint8_t> plaintext = generate_random_data(data_size);
        
        // Standard AES-GCM
        crypto::Aes128Gcm aes_std(key, iv);
        std::vector<uint8_t> ciphertext_std;
        {
            Timer timer("Verschlüsselung (Standard)");
            ciphertext_std = aes_std.encrypt(plaintext);
        }
        
        std::vector<uint8_t> decrypted_std;
        {
            Timer timer("Entschlüsselung (Standard)");
            decrypted_std = aes_std.decrypt(ciphertext_std);
        }
        
        // Optimierte AES-GCM
        crypto::Aes128GcmOptimized aes_opt(key, iv);
        std::vector<uint8_t> ciphertext_opt;
        {
            Timer timer("Verschlüsselung (SIMD)");
            ciphertext_opt = aes_opt.encrypt(plaintext);
        }
        
        std::vector<uint8_t> decrypted_opt;
        {
            Timer timer("Entschlüsselung (SIMD)");
            decrypted_opt = aes_opt.decrypt(ciphertext_opt);
        }
        
        // Verifikation
        bool std_correct = (plaintext == decrypted_std);
        bool opt_correct = (plaintext == decrypted_opt);
        
        std::cout << "Standard-Version korrekt: " << (std_correct ? "Ja" : "NEIN") << std::endl;
        std::cout << "Optimierte Version korrekt: " << (opt_correct ? "Ja" : "NEIN") << std::endl;
    }
}

// Hauptfunktion
int main() {
    std::cout << "===== QuicSand SIMD End-to-End Test =====" << std::endl;
    std::cout << "Testet alle SIMD-optimierten Komponenten" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    // Hardware-Informationen anzeigen
    std::cout << "Platform: ";
    #ifdef __APPLE__
        #ifdef __aarch64__
            std::cout << "Apple ARM64 (M1/M2)" << std::endl;
        #else
            std::cout << "Apple x86_64" << std::endl;
        #endif
    #else
        std::cout << "Non-Apple" << std::endl;
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
    
    // Teste AES-GCM
    try {
        test_aes_gcm_optimized();
    } catch (const std::exception& e) {
        std::cerr << "AES-GCM Test fehlgeschlagen: " << e.what() << std::endl;
    }
    
    // Teste QUIC End-to-End
    try {
        test_quic_end_to_end();
    } catch (const std::exception& e) {
        std::cerr << "QUIC End-to-End Test fehlgeschlagen: " << e.what() << std::endl;
    }
    
    std::cout << "\n===== Test abgeschlossen =====" << std::endl;
    
    return 0;
}
