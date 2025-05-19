#include "../core/zero_copy.hpp"
#include "../core/quic_packet.hpp"
#include "../core/quic_connection.hpp"
#include "../core/optimizations_integration.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>
#include <memory>
#include <algorithm>
#include <numeric>
#include <random>
#include <cstring>

using namespace quicsand;
using namespace std::chrono;

// Hilfsfunktion für Benchmarking
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

// Simulierte Network-Buffer-Klasse für Tests
class NetworkBuffer {
public:
    NetworkBuffer(size_t size) : data_(new uint8_t[size]), size_(size) {
        // Fülle mit zufälligen Daten
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        
        for (size_t i = 0; i < size_; ++i) {
            data_[i] = static_cast<uint8_t>(distrib(gen));
        }
    }
    
    ~NetworkBuffer() {
        delete[] data_;
    }
    
    // Nicht kopierbar
    NetworkBuffer(const NetworkBuffer&) = delete;
    NetworkBuffer& operator=(const NetworkBuffer&) = delete;
    
    // Bewegbar
    NetworkBuffer(NetworkBuffer&& other) noexcept 
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }
    
    NetworkBuffer& operator=(NetworkBuffer&& other) noexcept {
        if (this != &other) {
            delete[] data_;
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }
    
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }

private:
    uint8_t* data_;
    size_t size_;
};

// Test für die grundlegende Zero-Copy-Funktionalität
void test_zero_copy_basics() {
    std::cout << "=== Zero-Copy Basics Test ===" << std::endl;
    
    // Erzeuge einen simulierten Netzwerk-Buffer
    const size_t buffer_size = 1500; // Typische MTU-Größe
    NetworkBuffer network_buffer(buffer_size);
    
    // Erstelle einen Zero-Copy-Buffer, der auf den Netzwerk-Buffer verweist
    ZeroCopyBuffer zero_copy_buffer(network_buffer.data(), buffer_size);
    
    // Überprüfe Grundfunktionen
    assert(zero_copy_buffer.data() == network_buffer.data());
    assert(zero_copy_buffer.size() == buffer_size);
    assert(!zero_copy_buffer.is_owned());
    
    // Erstelle eine Kopie, die ihren eigenen Speicher besitzt
    ZeroCopyBuffer owned_copy = zero_copy_buffer.clone();
    assert(owned_copy.data() != network_buffer.data());
    assert(owned_copy.size() == buffer_size);
    assert(owned_copy.is_owned());
    
    // Überprüfe, ob die Daten korrekt kopiert wurden
    assert(std::memcmp(owned_copy.data(), network_buffer.data(), buffer_size) == 0);
    
    std::cout << "Zero-Copy Basics Test bestanden!" << std::endl;
}

// Test für Zero-Copy mit QuicPacket-Integration
void test_zero_copy_quic_packet() {
    std::cout << "\n=== Zero-Copy QuicPacket Integration Test ===" << std::endl;
    
    // Erzeuge einen simulierten Netzwerk-Buffer mit einem QuicPacket
    const size_t buffer_size = 1500;
    NetworkBuffer network_buffer(buffer_size);
    
    // Performance-Test: Normales Kopieren vs. Zero-Copy
    
    // 1. Test mit Standard-Kopieren
    auto standard_copy_test = [&]() {
        // Simuliere Empfang eines Pakets mit Kopieren der Daten
        std::vector<uint8_t> packet_data(network_buffer.data(), 
                                        network_buffer.data() + buffer_size);
        
        // Erstelle ein QuicPacket mit kopiertem Speicher
        QuicPacket packet;
        packet.set_raw_data(packet_data);
        
        // Simuliere Verarbeitung des Pakets
        size_t sum = 0;
        for (const auto& byte : packet.get_raw_data()) {
            sum += byte;
        }
        return sum;
    };
    
    // 2. Test mit Zero-Copy
    auto zero_copy_test = [&]() {
        // Erstelle einen Zero-Copy-Buffer, der auf den Netzwerk-Buffer verweist
        ZeroCopyBuffer zero_copy_buffer(network_buffer.data(), buffer_size);
        
        // Erstelle ein QuicPacket mit Zero-Copy-Buffer
        QuicPacket packet;
        packet.set_raw_data_zero_copy(zero_copy_buffer);
        
        // Simuliere Verarbeitung des Pakets
        size_t sum = 0;
        for (const auto& byte : packet.get_raw_data()) {
            sum += byte;
        }
        return sum;
    };
    
    // Führe Messungen durch
    const int iterations = 10000;
    double standard_time = measure_execution_time(standard_copy_test, iterations);
    double zero_copy_time = measure_execution_time(zero_copy_test, iterations);
    
    std::cout << "Standard-Kopieren Durchschnittszeit: " << standard_time << " µs" << std::endl;
    std::cout << "Zero-Copy Durchschnittszeit: " << zero_copy_time << " µs" << std::endl;
    
    double performance_ratio = standard_time / zero_copy_time;
    std::cout << "Performance-Verhältnis: " << std::fixed << std::setprecision(2) 
              << performance_ratio << "x" 
              << (performance_ratio > 1.0 ? " (Zero-Copy ist schneller)" : "") 
              << std::endl;
    
    // Zero-Copy sollte schneller sein, da es keine Kopieroperationen durchführt
    assert(performance_ratio > 1.0);
    
    std::cout << "Zero-Copy QuicPacket Integration Test bestanden!" << std::endl;
}

// Test für Zero-Copy mit QuicConnection-Integration
void test_zero_copy_connection() {
    std::cout << "\n=== Zero-Copy Connection Integration Test ===" << std::endl;
    
    // Erstelle eine simulierte QuicConnection mit aktiviertem Zero-Copy
    QuicConnection connection(true); // true = Zero-Copy aktiviert
    
    // Erzeuge einen simulierten Netzwerk-Buffer
    const size_t buffer_size = 1500;
    NetworkBuffer network_buffer(buffer_size);
    
    // Simuliere Empfang eines Pakets über die Verbindung
    connection.process_incoming_packet_zero_copy(network_buffer.data(), buffer_size);
    
    // Überprüfe, ob das Paket korrekt empfangen wurde
    assert(connection.get_received_packet_count() == 1);
    
    // Teste das Senden eines Pakets mit Zero-Copy
    std::vector<uint8_t> payload(500, 0xAB);
    connection.send_packet_zero_copy(payload.data(), payload.size());
    
    // Überprüfe, ob das Paket korrekt gesendet wurde
    assert(connection.get_sent_packet_count() == 1);
    
    std::cout << "Zero-Copy Connection Integration Test bestanden!" << std::endl;
}

// Test für die Integration von Zero-Copy mit Optimierungen
void test_zero_copy_optimizations() {
    std::cout << "\n=== Zero-Copy mit Optimierungen Test ===" << std::endl;
    
    // Erstelle einen OptimizationsManager
    OptimizationsManager opt_manager;
    
    // Erstelle einen Cache-optimierten Buffer für Empfangspakete
    auto receive_buffer = opt_manager.create_optimized_buffer<uint8_t>(2048);
    
    // Fülle den Buffer mit Testdaten
    for (int i = 0; i < 1500; ++i) {
        receive_buffer.push_back(static_cast<uint8_t>(i & 0xFF));
    }
    
    // Erstelle einen Zero-Copy-Buffer, der auf den Cache-optimierten Buffer verweist
    uint8_t* buffer_data = &receive_buffer[0];
    ZeroCopyBuffer zero_copy_buffer(buffer_data, 1500);
    
    // Überprüfe die grundlegende Funktionalität
    assert(zero_copy_buffer.data() == buffer_data);
    assert(zero_copy_buffer.size() == 1500);
    
    // Simuliere Paketverarbeitung mit einem Thread-Pool
    auto worker_pool = opt_manager.create_optimized_worker_pool(2);
    std::atomic<bool> packet_processed{false};
    
    worker_pool->enqueue([&zero_copy_buffer, &packet_processed]() {
        // Simuliere Paketverarbeitung
        size_t sum = 0;
        for (size_t i = 0; i < zero_copy_buffer.size(); ++i) {
            sum += zero_copy_buffer.data()[i];
        }
        
        packet_processed = true;
    });
    
    // Warte, bis die Verarbeitung abgeschlossen ist
    while (!packet_processed.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "Zero-Copy mit Optimierungen Test bestanden!" << std::endl;
}

// Hauptfunktion
int main() {
    std::cout << "Zero-Copy Integration Tests" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // Führe alle Tests aus
    test_zero_copy_basics();
    test_zero_copy_quic_packet();
    test_zero_copy_connection();
    test_zero_copy_optimizations();
    
    std::cout << "\nAlle Zero-Copy-Tests erfolgreich abgeschlossen!" << std::endl;
    
    return 0;
}
