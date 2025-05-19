#include "../core/simd_optimizations.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <iomanip>

using namespace quicsand::simd;
using namespace std::chrono;

// Hilfsfunktion zur Messung der Ausführungszeit
template<typename Func, typename... Args>
double measure_execution_time(Func func, Args&&... args) {
    auto start = high_resolution_clock::now();
    func(std::forward<Args>(args)...);
    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0;
}

// Funktion zur Erzeugung zufälliger Daten
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

// Funktion zur Erzeugung eines zufälligen Schlüssels
std::array<uint8_t, 16> generate_random_key() {
    std::array<uint8_t, 16> key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < 16; i++) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return key;
}

// Funktion zum Testen der AES-GCM-Verschlüsselung
void test_aes_gcm_performance() {
    std::cout << "\n=== AES-128-GCM Verschlüsselungs-Benchmark ===\n" << std::endl;
    
    // Überprüfe die SIMD-Features
    uint32_t features = detect_cpu_features();
    std::cout << features_to_string(features) << std::endl;
    
    if (!is_feature_supported(SIMDSupport::AESNI)) {
        std::cout << "AES-NI wird von dieser CPU nicht unterstützt, Test wird übersprungen." << std::endl;
        return;
    }
    
    // Erstelle zufällige Testdaten
    std::vector<size_t> sizes = {1024, 8192, 32768, 262144, 1048576}; // 1KB, 8KB, 32KB, 256KB, 1MB
    
    for (auto size : sizes) {
        std::vector<uint8_t> plaintext = generate_random_data(size);
        std::array<uint8_t, 16> key = generate_random_key();
        std::vector<uint8_t> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        
        // Erstelle den SIMDDispatcher für optimale SIMD-Auswahl
        SIMDDispatcher dispatcher;
        
        // Messe die Zeit für die Verschlüsselung
        double encryption_time = measure_execution_time([&]() {
            std::vector<uint8_t> ciphertext = dispatcher.aes_128_gcm_encrypt(plaintext, key, iv);
            // Überprüfe, ob die Verschlüsselung erfolgreich war
            if (ciphertext.empty()) {
                std::cerr << "Fehler: Verschlüsselung fehlgeschlagen." << std::endl;
            }
        });
        
        // Messe die Zeit für eine einfache XOR-Operation als Referenz
        std::vector<uint8_t> output(plaintext.size());
        double xor_time = measure_execution_time([&]() {
            for (size_t i = 0; i < plaintext.size(); i++) {
                output[i] = plaintext[i] ^ key[i % 16];
            }
        });
        
        // Berechne den Durchsatz
        double throughput = (size / 1024.0) / (encryption_time / 1000.0); // MB/s
        
        // Ausgabe der Ergebnisse
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "AES-GCM Zeit: " << std::fixed << std::setprecision(3) << encryption_time << " ms" << std::endl;
        std::cout << "XOR Zeit: " << std::fixed << std::setprecision(3) << xor_time << " ms" << std::endl;
        std::cout << "Durchsatz: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
        std::cout << "Verhältnis (XOR/AES): " << std::fixed << std::setprecision(2) << (encryption_time / xor_time) << std::endl;
        std::cout << std::endl;
    }
}

// Funktion zum Testen der Ascon-Verschlüsselung
void test_ascon_performance() {
    std::cout << "\n=== Ascon-128a Verschlüsselungs-Benchmark ===\n" << std::endl;
    
    // Erstelle zufällige Testdaten
    std::vector<size_t> sizes = {1024, 8192, 32768, 262144, 1048576}; // 1KB, 8KB, 32KB, 256KB, 1MB
    
    for (auto size : sizes) {
        std::vector<uint8_t> plaintext = generate_random_data(size);
        std::array<uint8_t, 16> key = generate_random_key();
        std::array<uint8_t, 16> nonce = generate_random_key(); // Hier verwenden wir einfach einen zweiten Schlüssel als Nonce
        
        // Erstelle den SIMDDispatcher für optimale SIMD-Auswahl
        SIMDDispatcher dispatcher;
        
        // Messe die Zeit für die Verschlüsselung
        double encryption_time = measure_execution_time([&]() {
            std::vector<uint8_t> ciphertext = dispatcher.ascon_128a_encrypt(plaintext, key, nonce);
            // Überprüfe, ob die Verschlüsselung erfolgreich war
            if (ciphertext.empty()) {
                std::cerr << "Fehler: Verschlüsselung fehlgeschlagen." << std::endl;
            }
        });
        
        // Berechne den Durchsatz
        double throughput = (size / 1024.0) / (encryption_time / 1000.0); // MB/s
        
        // Ausgabe der Ergebnisse
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "Ascon-128a Zeit: " << std::fixed << std::setprecision(3) << encryption_time << " ms" << std::endl;
        std::cout << "Durchsatz: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
        std::cout << std::endl;
    }
}

// Funktion zum Testen der Tetrys-FEC-Kodierung
void test_tetrys_fec_performance() {
    std::cout << "\n=== Tetrys-FEC Kodierungs-Benchmark ===\n" << std::endl;
    
    // Definiere Testparameter
    size_t packet_size = 1024; // 1KB Paketgröße
    std::vector<size_t> source_packets_counts = {10, 50, 100, 200, 500}; // Anzahl der Quellpakete
    double redundancy_ratio = 0.2; // 20% Redundanz
    
    for (auto count : source_packets_counts) {
        // Erstelle zufällige Quellpakete
        std::vector<std::vector<uint8_t>> source_packets(count);
        for (auto& packet : source_packets) {
            packet = generate_random_data(packet_size);
        }
        
        // Erstelle den SIMDDispatcher für optimale SIMD-Auswahl
        SIMDDispatcher dispatcher;
        
        // Messe die Zeit für die FEC-Kodierung
        double encoding_time = measure_execution_time([&]() {
            std::vector<std::vector<uint8_t>> redundancy_packets = dispatcher.tetrys_encode(
                source_packets, packet_size, redundancy_ratio);
            // Überprüfe, ob die Kodierung erfolgreich war
            if (redundancy_packets.empty()) {
                std::cerr << "Fehler: FEC-Kodierung fehlgeschlagen." << std::endl;
            }
        });
        
        // Berechne den Durchsatz
        double throughput = (count * packet_size / 1024.0) / (encoding_time / 1000.0); // MB/s
        
        // Ausgabe der Ergebnisse
        std::cout << "Quellpakete: " << std::setw(3) << count << ", Paketgröße: " << packet_size << " Bytes" << std::endl;
        std::cout << "Tetrys-FEC Kodierungszeit: " << std::fixed << std::setprecision(3) << encoding_time << " ms" << std::endl;
        std::cout << "Durchsatz: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
        std::cout << std::endl;
    }
}

int main() {
    // Zeige unterstützte SIMD-Features an
    uint32_t features = detect_cpu_features();
    std::cout << "CPU SIMD-Funktionen Erkennung:" << std::endl;
    std::cout << features_to_string(features) << std::endl;
    
    // Führe die Tests aus
    test_aes_gcm_performance();
    test_ascon_performance();
    test_tetrys_fec_performance();
    
    return 0;
}
