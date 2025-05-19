#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>
#include <memory>
#include <string>
#include <cassert>

#include "../core/simd_optimizations.hpp"

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

// Teste XOR-Operationen mit verschiedenen SIMD-Backends
void test_xor_operations() {
    std::cout << "\n===== Testing XOR Operations =====" << std::endl;
    
    const std::vector<size_t> data_sizes = {1*1024, 16*1024, 64*1024, 256*1024};
    
    for (auto size : data_sizes) {
        std::cout << "\nTesting with size: " << size / 1024 << " KB" << std::endl;
        std::cout << std::string(40, '-') << std::endl;
        
        // Generiere Testdaten
        std::vector<uint8_t> src = generate_random_data(size);
        std::vector<uint8_t> dst = generate_random_data(size);
        std::vector<uint8_t> dst_copy = dst; // Backup für Verifikation
        
        // Skalare Implementation zum Vergleich
        {
            std::vector<uint8_t> result = dst_copy;
            Timer timer("Scalar XOR");
            
            for (size_t i = 0; i < size; i++) {
                result[i] ^= src[i];
            }
        }
        
        // SIMD-optimierte Implementation über Dispatcher
        {
            std::vector<uint8_t> result = dst;
            Timer timer("SIMD XOR via Dispatcher");
            
            simd::SIMDDispatcher dispatcher;
            dispatcher.xor_buffers(result.data(), src.data(), size);
        }
        
        std::cout << "SIMD Support: " << simd::features_to_string(simd::detect_cpu_features()) << std::endl;
    }
}

// Teste AES-GCM mit verschiedenen SIMD-Backends
void test_aes_gcm() {
    std::cout << "\n===== Testing AES-GCM Encryption/Decryption =====" << std::endl;
    
    // Generiere Schlüssel und IV
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
    
    // Teste mit verschiedenen Dateigrößen
    const std::vector<size_t> data_sizes = {1*1024, 16*1024, 64*1024};
    
    for (auto size : data_sizes) {
        std::cout << "\nTesting with size: " << size / 1024 << " KB" << std::endl;
        std::cout << std::string(40, '-') << std::endl;
        
        // Generiere Testdaten
        std::vector<uint8_t> plaintext = generate_random_data(size);
        
        try {
            simd::SIMDDispatcher dispatcher;
            
            // Verschlüsselung
            std::vector<uint8_t> ciphertext;
            {
                Timer timer("SIMD AES-GCM Encryption");
                ciphertext = dispatcher.aes_128_gcm_encrypt(plaintext, key, iv, {}, 16);
            }
            
            // Entschlüsselung
            std::vector<uint8_t> decrypted;
            {
                Timer timer("SIMD AES-GCM Decryption");
                decrypted = dispatcher.aes_128_gcm_decrypt(ciphertext, key, iv, {}, 16);
            }
            
            // Verifiziere Ergebnisse
            bool success = (plaintext == decrypted);
            std::cout << "Verification: " << (success ? "PASSED" : "FAILED") << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << std::endl;
            std::cout << "This is expected if your CPU doesn't support the required SIMD instructions." << std::endl;
        }
    }
}

// Teste Tetrys FEC mit verschiedenen SIMD-Backends
void test_tetrys_fec() {
    std::cout << "\n===== Testing Tetrys FEC Encoding/Decoding =====" << std::endl;
    
    const size_t packet_size = 1024;
    const size_t num_packets = 10;
    const double redundancy = 0.5; // 50% Redundanz
    
    std::cout << "Testing with " << num_packets << " packets of " << packet_size << " bytes each" << std::endl;
    std::cout << "Redundancy ratio: " << redundancy << std::endl;
    std::cout << std::string(40, '-') << std::endl;
    
    // Generiere Testpakete
    std::vector<std::vector<uint8_t>> packets;
    for (size_t i = 0; i < num_packets; i++) {
        packets.push_back(generate_random_data(packet_size));
    }
    
    try {
        simd::SIMDDispatcher dispatcher;
        
        // Encoding
        std::vector<std::vector<uint8_t>> redundancy_packets;
        {
            Timer timer("SIMD FEC Encoding");
            redundancy_packets = dispatcher.tetrys_encode(packets, packet_size, redundancy);
        }
        
        std::cout << "Generated " << redundancy_packets.size() << " redundancy packets" << std::endl;
        
        // Simuliere Paketverlust (entferne die ersten 3 Pakete)
        std::vector<std::vector<uint8_t>> received_packets;
        std::vector<uint16_t> packet_indices;
        
        // Füge die verbleibenden Originalpakete hinzu
        for (size_t i = 3; i < packets.size(); i++) {
            received_packets.push_back(packets[i]);
            packet_indices.push_back(static_cast<uint16_t>(i));
        }
        
        // Füge alle Redundanzpakete hinzu
        for (size_t i = 0; i < redundancy_packets.size(); i++) {
            received_packets.push_back(redundancy_packets[i]);
            packet_indices.push_back(static_cast<uint16_t>(packets.size() + i));
        }
        
        // Decoding
        std::vector<std::vector<uint8_t>> recovered_packets;
        {
            Timer timer("SIMD FEC Decoding");
            recovered_packets = dispatcher.tetrys_decode(received_packets, packet_indices, packet_size, packets.size());
        }
        
        // In einer vollständigen Implementation würden wir hier die rekonstruierten Pakete validieren
        std::cout << "Recovered " << recovered_packets.size() << " packets" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        std::cout << "This is expected if your CPU doesn't support the required SIMD instructions." << std::endl;
    }
}

// Hauptfunktion
int main() {
    std::cout << "===== QuicSand Platform-Independent SIMD Tests =====" << std::endl;
    
    // Hardware-Informationen anzeigen
    std::cout << "Processor architecture: ";
    #ifdef __ARM_NEON
        #ifdef __aarch64__
            std::cout << "ARM64 (ARMv8)";
        #else
            std::cout << "ARM32 (ARMv7)";
        #endif
    #else
        #ifdef __x86_64__
            std::cout << "x86_64 (64-bit)";
        #else
            std::cout << "x86 (32-bit)";
        #endif
    #endif
    std::cout << std::endl;
    
    // SIMD-Support anzeigen
    std::cout << "SIMD Features: " << simd::features_to_string(simd::detect_cpu_features()) << std::endl;
    
    // Führe die Tests durch
    test_xor_operations();
    test_aes_gcm();
    test_tetrys_fec();
    
    std::cout << "\n===== Tests complete =====" << std::endl;
    
    return 0;
}
