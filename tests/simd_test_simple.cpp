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

// Einfache NEON-optimierte SIMD-Funktion für ARM
void vector_add_neon(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
#ifdef __ARM_NEON
    // Verarbeite 16 Bytes pro Durchlauf mit NEON
    size_t vec_size = size & ~15;
    
    for (size_t i = 0; i < vec_size; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vr = vaddq_u8(va, vb);
        vst1q_u8(result + i, vr);
    }
    
    // Verarbeite den Rest
    for (size_t i = vec_size; i < size; i++) {
        result[i] = a[i] + b[i];
    }
#else
    // Fallback für nicht-ARM-Plattformen
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] + b[i];
    }
#endif
}

// Einfache skalar Funktion zum Vergleich
void vector_add_scalar(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] + b[i];
    }
}

// Einfache NEON-optimierte XOR-Funktion für AES-ähnliche Anwendungen
void vector_xor_neon(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
#ifdef __ARM_NEON
    // Verarbeite 16 Bytes pro Durchlauf mit NEON
    size_t vec_size = size & ~15;
    
    for (size_t i = 0; i < vec_size; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vr = veorq_u8(va, vb);
        vst1q_u8(result + i, vr);
    }
    
    // Verarbeite den Rest
    for (size_t i = vec_size; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
#else
    // Fallback für nicht-ARM-Plattformen
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
#endif
}

// Einfache skalar XOR-Funktion zum Vergleich
void vector_xor_scalar(const uint8_t* a, const uint8_t* b, uint8_t* result, size_t size) {
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// Benchmarking der vektorisierten Funktionen im Vergleich zu skalaren Funktionen
void benchmark_vector_operations() {
    std::cout << "\n=== SIMD Vektor-Operationen Benchmark ===\n" << std::endl;
    
    // Überprüfe die SIMD-Features
    uint32_t features = detect_cpu_features();
    std::cout << features_to_string(features) << std::endl;
    
    // Erstelle zufällige Testdaten
    std::vector<size_t> sizes = {1024, 8192, 32768, 262144, 1048576}; // 1KB, 8KB, 32KB, 256KB, 1MB
    
    std::cout << "Vector Addition (a + b):" << std::endl;
    std::cout << "----------------------------" << std::endl;
    
    for (auto size : sizes) {
        std::vector<uint8_t> a = generate_random_data(size);
        std::vector<uint8_t> b = generate_random_data(size);
        std::vector<uint8_t> result_simd(size);
        std::vector<uint8_t> result_scalar(size);
        
        // Messe die Zeit für SIMD-optimierte Vektoraddition
        double simd_time = measure_execution_time([&]() {
            vector_add_neon(a.data(), b.data(), result_simd.data(), size);
        });
        
        // Messe die Zeit für skalare Vektoraddition
        double scalar_time = measure_execution_time([&]() {
            vector_add_scalar(a.data(), b.data(), result_scalar.data(), size);
        });
        
        // Überprüfe die Ergebnisse
        bool results_match = true;
        for (size_t i = 0; i < size; i++) {
            if (result_simd[i] != result_scalar[i]) {
                results_match = false;
                break;
            }
        }
        
        // Berechne den Speedup
        double speedup = scalar_time / simd_time;
        
        // Ausgabe der Ergebnisse
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "SIMD Zeit: " << std::fixed << std::setprecision(3) << simd_time << " ms" << std::endl;
        std::cout << "Skalar Zeit: " << std::fixed << std::setprecision(3) << scalar_time << " ms" << std::endl;
        std::cout << "Speedup: " << std::fixed << std::setprecision(2) << speedup << "x" << std::endl;
        std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
        std::cout << std::endl;
    }
    
    std::cout << "Vector XOR (a ^ b, AES-like):" << std::endl;
    std::cout << "------------------------------" << std::endl;
    
    for (auto size : sizes) {
        std::vector<uint8_t> a = generate_random_data(size);
        std::vector<uint8_t> b = generate_random_data(size);
        std::vector<uint8_t> result_simd(size);
        std::vector<uint8_t> result_scalar(size);
        
        // Messe die Zeit für SIMD-optimierte Vektor-XOR
        double simd_time = measure_execution_time([&]() {
            vector_xor_neon(a.data(), b.data(), result_simd.data(), size);
        });
        
        // Messe die Zeit für skalare Vektor-XOR
        double scalar_time = measure_execution_time([&]() {
            vector_xor_scalar(a.data(), b.data(), result_scalar.data(), size);
        });
        
        // Überprüfe die Ergebnisse
        bool results_match = true;
        for (size_t i = 0; i < size; i++) {
            if (result_simd[i] != result_scalar[i]) {
                results_match = false;
                break;
            }
        }
        
        // Berechne den Speedup
        double speedup = scalar_time / simd_time;
        
        // Ausgabe der Ergebnisse
        std::cout << "Datengröße: " << std::setw(7) << (size / 1024) << " KB" << std::endl;
        std::cout << "SIMD Zeit: " << std::fixed << std::setprecision(3) << simd_time << " ms" << std::endl;
        std::cout << "Skalar Zeit: " << std::fixed << std::setprecision(3) << scalar_time << " ms" << std::endl;
        std::cout << "Speedup: " << std::fixed << std::setprecision(2) << speedup << "x" << std::endl;
        std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
        std::cout << std::endl;
    }
}

int main() {
    // Zeige unterstützte SIMD-Features an
    uint32_t features = detect_cpu_features();
    std::cout << "CPU SIMD-Funktionen Erkennung:" << std::endl;
    std::cout << features_to_string(features) << std::endl;
    
    // Führe die Benchmarks aus
    benchmark_vector_operations();
    
    return 0;
}
