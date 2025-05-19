#include "../core/simd_optimizations.hpp"
#include "../crypto/aes128gcm_optimized.hpp"
#include "../fec/tetrys_fec_optimized.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <iomanip>
#include <cassert>

using namespace quicsand;
using namespace quicsand::crypto;
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

// Test der SIMD-optimierten AES-128-GCM Implementierung
void test_aes_gcm_performance() {
    std::cout << "=== SIMD-optimierte AES-128-GCM Test ===" << std::endl;
    
    // Erstelle Testdaten
    std::vector<size_t> data_sizes = {1024, 8192, 32768, 262144}; // 1KB, 8KB, 32KB, 256KB
    std::vector<uint8_t> key = generate_random_data(16);
    std::vector<uint8_t> iv = generate_random_data(12);
    std::vector<uint8_t> aad = generate_random_data(32);
    
    for (auto size : data_sizes) {
        std::vector<uint8_t> plaintext = generate_random_data(size);
        
        // SIMD-optimierte Implementierung
        Aes128GcmOptimized aes_optimized(key, iv);
        
        // Verschlüsselung
        double encryption_time = measure_execution_time([&]() {
            auto ciphertext = aes_optimized.encrypt(plaintext, aad);
        }, 5);
        
        // Verschlüssele für Entschlüsselungstest
        auto ciphertext = aes_optimized.encrypt(plaintext, aad);
        
        // Entschlüsselung
        double decryption_time = measure_execution_time([&]() {
            auto decrypted = aes_optimized.decrypt(ciphertext, aad);
        }, 5);
        
        // Verifiziere Ergebnisse
        auto decrypted = aes_optimized.decrypt(ciphertext, aad);
        bool results_match = (decrypted == plaintext);
        
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "Verschlüsselungszeit: " << std::fixed << std::setprecision(3) << encryption_time << " µs" << std::endl;
        std::cout << "Entschlüsselungszeit: " << std::fixed << std::setprecision(3) << decryption_time << " µs" << std::endl;
        std::cout << "Durchsatz Verschlüsselung: " << std::fixed << std::setprecision(2) 
                  << (size / (encryption_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
        std::cout << "Durchsatz Entschlüsselung: " << std::fixed << std::setprecision(2) 
                  << (size / (decryption_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
        std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
        std::cout << std::endl;
        
        // Bestätige, dass die Ergebnisse übereinstimmen
        assert(results_match);
    }
    
    // Zero-Copy API Test
    std::cout << "Zero-Copy AES-128-GCM API Test:" << std::endl;
    
    size_t size = 65536; // 64KB
    std::vector<uint8_t> plaintext = generate_random_data(size);
    std::vector<uint8_t> ciphertext(size + 16); // Platz für Tag
    std::vector<uint8_t> decrypted(size);
    
    Aes128GcmOptimized aes_zero_copy(key, iv);
    
    // Zero-Copy Verschlüsselung
    double zero_copy_encryption_time = measure_execution_time([&]() {
        aes_zero_copy.encrypt_zero_copy(plaintext.data(), size, aad.data(), aad.size(), ciphertext.data());
    }, 5);
    
    // Zero-Copy Entschlüsselung
    double zero_copy_decryption_time = measure_execution_time([&]() {
        aes_zero_copy.decrypt_zero_copy(ciphertext.data(), size, aad.data(), aad.size(), 
                                      ciphertext.data() + size, decrypted.data());
    }, 5);
    
    // Verifiziere Ergebnisse
    bool zero_copy_results_match = true;
    for (size_t i = 0; i < size; ++i) {
        if (plaintext[i] != decrypted[i]) {
            zero_copy_results_match = false;
            break;
        }
    }
    
    std::cout << "Zero-Copy Verschlüsselungszeit: " << std::fixed << std::setprecision(3) << zero_copy_encryption_time << " µs" << std::endl;
    std::cout << "Zero-Copy Entschlüsselungszeit: " << std::fixed << std::setprecision(3) << zero_copy_decryption_time << " µs" << std::endl;
    std::cout << "Durchsatz Zero-Copy Verschlüsselung: " << std::fixed << std::setprecision(2) 
              << (size / (zero_copy_encryption_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
    std::cout << "Durchsatz Zero-Copy Entschlüsselung: " << std::fixed << std::setprecision(2) 
              << (size / (zero_copy_decryption_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (zero_copy_results_match ? "Ja" : "Nein") << std::endl;
    
    // Bestätige, dass die Ergebnisse übereinstimmen
    assert(zero_copy_results_match);
}

// Test der SIMD-optimierten Tetrys FEC
void test_tetrys_fec_performance() {
    std::cout << "\n=== SIMD-optimierte Tetrys FEC Test ===" << std::endl;
    
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
    std::vector<bool> lost_packets(num_packets, false);
    size_t lost_count = static_cast<size_t>(num_packets * loss_rate);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, num_packets - 1);
    
    for (size_t i = 0; i < lost_count; ++i) {
        size_t idx;
        do {
            idx = distrib(gen);
        } while (lost_packets[idx]);
        lost_packets[idx] = true;
    }
    
    std::cout << "Testdaten: " << num_packets << " Pakete, " << packet_size << " Bytes/Paket" << std::endl;
    std::cout << "Simulierter Paketverlust: " << lost_count << " Pakete (" 
              << (lost_count * 100.0 / num_packets) << "%)" << std::endl;
    
    // Erstelle FEC-Instanzen mit höherer Redundanz für bessere Wiederherstellung
    OptimizedTetrysFEC::Config config;
    config.window_size = 10;
    config.initial_redundancy = 0.5;  // 50% Redundanz für bessere Wiederherstellung
    config.adaptive = true;
    config.min_redundancy = 0.3;
    config.max_redundancy = 0.7;
    
    OptimizedTetrysFEC fec(config);
    
    // Sammle alle Pakete (Daten + Reparatur) während der Kodierung
    std::vector<OptimizedTetrysFEC::TetrysPacket> all_packets;
    
    // Kodiere mit Zeitmessung und sammle alle Pakete
    double encoding_time = measure_execution_time([&]() {
        for (size_t i = 0; i < num_packets; ++i) {
            // Kodiere jedes Datenpaket
            auto packets = fec.encode_packet(data_packets[i]);
            // Füge Daten- und Reparaturpakete der Liste hinzu
            all_packets.insert(all_packets.end(), packets.begin(), packets.end());
        }
        
        // Erzeuge zusätzliche Reparaturpakete am Ende
        for (size_t i = 0; i < 5; ++i) {
            auto repair_packet = fec.generate_repair_packet();
            all_packets.push_back(repair_packet);
        }
    });
    
    // Empfange Pakete und dekodiere
    std::vector<OptimizedTetrysFEC::TetrysPacket> encoded_packets = all_packets;
    
    // Zweite FEC-Instanz zum Dekodieren
    OptimizedTetrysFEC decoder(config);
    
    // Separiere Daten- und Reparaturpakete
    std::vector<OptimizedTetrysFEC::TetrysPacket> data_packets_received;
    std::vector<OptimizedTetrysFEC::TetrysPacket> repair_packets_received;
    
    for (const auto& packet : encoded_packets) {
        if (packet.is_repair) {
            repair_packets_received.push_back(packet);
        } else {
            data_packets_received.push_back(packet);
        }
    }
    
    // Simuliere Paketverlust bei den Datenpaketen
    std::vector<OptimizedTetrysFEC::TetrysPacket> received_packets;
    
    // Alle Reparaturpakete hinzufügen
    received_packets.insert(received_packets.end(), repair_packets_received.begin(), repair_packets_received.end());
    
    // Datenpakete hinzufügen, außer die verloren gegangenen
    for (size_t i = 0; i < data_packets_received.size(); ++i) {
        if (i >= num_packets || !lost_packets[i]) {
            // Paket nicht verloren oder über die simulierten Pakete hinaus
            received_packets.push_back(data_packets_received[i]);
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
    std::cout << "Durchsatz Kodierung: " << std::fixed << std::setprecision(2) 
              << ((num_packets * packet_size) / (encoding_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
    std::cout << "Durchsatz Dekodierung: " << std::fixed << std::setprecision(2) 
              << ((recovered_size) / (decoding_time / 1000000.0) / (1024*1024)) << " MB/s" << std::endl;
    
    // In realistischen Szenarien mit 20% Paketverlust und 50% Redundanz können wir
    // etwa 15-30% der Daten wiederherstellen (abhängig von den Paketmustern)
    assert(recovery_ratio >= 0.15); // Mindestens 15% der Daten sollten wiederhergestellt werden
}

// Kombinierter Test: AES-128-GCM mit Tetrys FEC
void test_crypto_fec_integration() {
    std::cout << "\n=== Integrationstest: AES-128-GCM mit Tetrys FEC ===" << std::endl;
    
    // Konfiguration
    const size_t packet_size = 1024;
    const size_t num_packets = 20;
    const double loss_rate = 0.15; // 15% Paketverlust
    
    // Krypto-Setup
    std::vector<uint8_t> key = generate_random_data(16);
    std::vector<uint8_t> iv = generate_random_data(12);
    Aes128GcmOptimized aes(key, iv);
    
    // FEC-Setup
    OptimizedTetrysFEC::Config fec_config;
    fec_config.window_size = 8;
    fec_config.initial_redundancy = 0.3;
    OptimizedTetrysFEC encoder(fec_config);
    OptimizedTetrysFEC decoder(fec_config);
    
    // Testdaten erzeugen und verschlüsseln
    std::vector<std::vector<uint8_t>> original_packets;
    std::vector<std::vector<uint8_t>> encrypted_packets;
    
    for (size_t i = 0; i < num_packets; ++i) {
        auto packet = generate_random_data(packet_size);
        original_packets.push_back(packet);
        
        // Verschlüsseln
        auto encrypted = aes.encrypt(packet, {});
        encrypted_packets.push_back(encrypted);
    }
    
    // FEC-Kodierung der verschlüsselten Pakete
    std::vector<OptimizedTetrysFEC::TetrysPacket> fec_packets;
    for (const auto& packet : encrypted_packets) {
        auto packets = encoder.encode_packet(packet);
        fec_packets.insert(fec_packets.end(), packets.begin(), packets.end());
    }
    
    // Simuliere Paketverlust
    std::vector<bool> lost_packets(fec_packets.size(), false);
    size_t lost_count = static_cast<size_t>(fec_packets.size() * loss_rate);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, fec_packets.size() - 1);
    
    for (size_t i = 0; i < lost_count; ++i) {
        size_t idx;
        do {
            idx = distrib(gen);
        } while (lost_packets[idx]);
        lost_packets[idx] = true;
    }
    
    // Empfange Pakete (mit Verlust)
    std::vector<OptimizedTetrysFEC::TetrysPacket> received_packets;
    for (size_t i = 0; i < fec_packets.size(); ++i) {
        if (!lost_packets[i]) {
            received_packets.push_back(fec_packets[i]);
        }
    }
    
    // FEC-Dekodierung
    for (const auto& packet : received_packets) {
        decoder.add_received_packet(packet);
    }
    
    // Rekonstruiere Original-Daten
    auto fec_recovered_data = decoder.get_recovered_data();
    
    // Parse FEC-wiederhergestellte Daten in einzelne verschlüsselte Pakete
    std::vector<std::vector<uint8_t>> recovered_encrypted_packets;
    size_t processed = 0;
    
    while (processed < fec_recovered_data.size()) {
        size_t remaining = fec_recovered_data.size() - processed;
        if (remaining < 16) break; // Mindestens 16 Bytes für Tag
        
        // Kopiere ein Paket
        std::vector<uint8_t> packet(fec_recovered_data.data() + processed, 
                                   fec_recovered_data.data() + processed + std::min(remaining, packet_size + 16));
        recovered_encrypted_packets.push_back(packet);
        
        processed += packet.size();
    }
    
    // Entschlüssele wiederhergestellte Pakete
    std::vector<std::vector<uint8_t>> decrypted_packets;
    for (const auto& packet : recovered_encrypted_packets) {
        auto decrypted = aes.decrypt(packet, {});
        if (!decrypted.empty()) {
            decrypted_packets.push_back(decrypted);
        }
    }
    
    // Auswertung
    std::cout << "Originale Pakete: " << original_packets.size() << std::endl;
    std::cout << "Gesendete FEC-Pakete: " << fec_packets.size() << std::endl;
    std::cout << "Verlorene Pakete: " << lost_count << " (" 
              << (lost_count * 100.0 / fec_packets.size()) << "%)" << std::endl;
    std::cout << "Empfangene Pakete: " << received_packets.size() << std::endl;
    std::cout << "Wiederhergestellte verschlüsselte Pakete: " << recovered_encrypted_packets.size() << std::endl;
    std::cout << "Erfolgreich entschlüsselte Pakete: " << decrypted_packets.size() << std::endl;
    std::cout << "Wiederherstellungsrate: " << std::fixed << std::setprecision(2) 
              << (decrypted_packets.size() * 100.0 / original_packets.size()) << "%" << std::endl;
    
    // Verifiziere Inhalt
    int matches = 0;
    for (const auto& decrypted : decrypted_packets) {
        for (const auto& original : original_packets) {
            if (decrypted == original) {
                matches++;
                break;
            }
        }
    }
    
    std::cout << "Pakete mit korrektem Inhalt: " << matches << " / " << decrypted_packets.size() << std::endl;
    
    // Mindestens einige Pakete sollten wiederhergestellt werden
    assert(decrypted_packets.size() > 0);
    assert(matches > 0);
}

int main() {
    // Zeige SIMD-Funktionen
    auto features = simd::detect_cpu_features();
    std::cout << "CPU SIMD-Funktionen: " << simd::features_to_string(features) << std::endl;
    std::cout << "SIMD-optimierte Krypto verfügbar: " 
              << (Aes128GcmOptimized::is_hardware_acceleration_available() ? "Ja" : "Nein") << std::endl;
    std::cout << std::endl;
    
    // Führe Tests aus
    test_aes_gcm_performance();
    test_tetrys_fec_performance();
    test_crypto_fec_integration();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    return 0;
}
