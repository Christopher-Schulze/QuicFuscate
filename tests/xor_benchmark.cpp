#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <random>
#include <cstring>

#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

using namespace std::chrono;

// Standard XOR-Implementation
void standard_xor(uint8_t* dst, const uint8_t* src, size_t size) {
    for (size_t i = 0; i < size; i++) {
        dst[i] ^= src[i];
    }
}

// Optimierte XOR mit Loop Unrolling
void unrolled_xor(uint8_t* dst, const uint8_t* src, size_t size) {
    const size_t step = 8;
    const size_t vec_size = size & ~(step-1);
    
    for (size_t i = 0; i < vec_size; i += step) {
        dst[i] ^= src[i];
        dst[i+1] ^= src[i+1];
        dst[i+2] ^= src[i+2];
        dst[i+3] ^= src[i+3];
        dst[i+4] ^= src[i+4];
        dst[i+5] ^= src[i+5];
        dst[i+6] ^= src[i+6];
        dst[i+7] ^= src[i+7];
    }
    
    for (size_t i = vec_size; i < size; i++) {
        dst[i] ^= src[i];
    }
}

// SIMD-optimierte XOR mit NEON
void simd_xor(uint8_t* dst, const uint8_t* src, size_t size) {
#ifdef __ARM_NEON
    // Optimale Chunk-Größe für den L1-Cache (64-Byte Cache Line auf M1/M2)
    const size_t CHUNK_SIZE = 64 * 16; // 1024 Bytes pro Chunk
    const size_t vec_size = size & ~63; // Runde auf den nächsten durch 64 teilbaren Wert ab
    
    // Verarbeite große Datenmengen in Chunks für bessere Cache-Lokalität
    for (size_t chunk = 0; chunk < vec_size; chunk += CHUNK_SIZE) {
        const size_t chunk_end = std::min(chunk + CHUNK_SIZE, vec_size);
        
        // Prefetch den nächsten Chunk, falls vorhanden
        if (chunk + CHUNK_SIZE < vec_size) {
            __builtin_prefetch(dst + chunk + CHUNK_SIZE, 1); // 1 = für Schreibzugriff
            __builtin_prefetch(src + chunk + CHUNK_SIZE, 0); // 0 = für Lesezugriff
        }
        
        // Unrolled loop - Verarbeite 64 Bytes pro Iteration (4x16 Bytes)
        for (size_t i = chunk; i < chunk_end; i += 64) {
            // Lade 4 NEON-Register (4x16 Bytes = 64 Bytes)
            uint8x16_t v_dst1 = vld1q_u8(dst + i);
            uint8x16_t v_src1 = vld1q_u8(src + i);
            uint8x16_t v_dst2 = vld1q_u8(dst + i + 16);
            uint8x16_t v_src2 = vld1q_u8(src + i + 16);
            uint8x16_t v_dst3 = vld1q_u8(dst + i + 32);
            uint8x16_t v_src3 = vld1q_u8(src + i + 32);
            uint8x16_t v_dst4 = vld1q_u8(dst + i + 48);
            uint8x16_t v_src4 = vld1q_u8(src + i + 48);
            
            // Führe XOR-Operationen durch
            uint8x16_t result1 = veorq_u8(v_dst1, v_src1);
            uint8x16_t result2 = veorq_u8(v_dst2, v_src2);
            uint8x16_t result3 = veorq_u8(v_dst3, v_src3);
            uint8x16_t result4 = veorq_u8(v_dst4, v_src4);
            
            // Speichere die Ergebnisse zurück
            vst1q_u8(dst + i, result1);
            vst1q_u8(dst + i + 16, result2);
            vst1q_u8(dst + i + 32, result3);
            vst1q_u8(dst + i + 48, result4);
        }
    }
    
    // Handle remaining 16-byte blocks
    for (size_t i = vec_size; i < (size & ~15); i += 16) {
        uint8x16_t v_dst = vld1q_u8(dst + i);
        uint8x16_t v_src = vld1q_u8(src + i);
        uint8x16_t result = veorq_u8(v_dst, v_src);
        vst1q_u8(dst + i, result);
    }
    
    // Verarbeite die übrigen Bytes einzeln
    for (size_t i = (size & ~15); i < size; i++) {
        dst[i] ^= src[i];
    }
#else
    // Fallback für nicht-ARM-Plattformen
    unrolled_xor(dst, src, size);
#endif
}

// Hilfsfunktion zur Messung der Ausführungszeit
template<typename Func>
double measure_execution_time_ms(Func&& func, size_t iterations = 1) {
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
        func();
    }
    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0 / iterations;
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

int main() {
    std::cout << "XOR SIMD Optimierungs-Benchmark" << std::endl;
    std::cout << "===============================" << std::endl;
    
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
    
    print_benchmark_header("XOR-Operations Benchmark");
    
    // Verschiedene Datengrößen testen
    const std::vector<size_t> data_sizes = {
        1*1024,      // 1 KB
        16*1024,     // 16 KB
        64*1024,     // 64 KB
        256*1024,    // 256 KB
        1024*1024,   // 1 MB
        4*1024*1024  // 4 MB
    };
    
    for (auto size : data_sizes) {
        // Testdaten erstellen
        std::vector<uint8_t> data1 = generate_random_data(size);
        std::vector<uint8_t> data2 = generate_random_data(size);
        
        std::vector<uint8_t> result_std(data1);
        std::vector<uint8_t> result_unrolled(data1);
        std::vector<uint8_t> result_simd(data1);
        
        // Standard-Implementierung
        double std_time = measure_execution_time_ms([&]() {
            standard_xor(result_std.data(), data2.data(), size);
        }, 10);
        
        // Unrolled-Implementierung
        double unrolled_time = measure_execution_time_ms([&]() {
            unrolled_xor(result_unrolled.data(), data2.data(), size);
        }, 10);
        
        // SIMD-Implementierung
        double simd_time = measure_execution_time_ms([&]() {
            simd_xor(result_simd.data(), data2.data(), size);
        }, 10);
        
        // Ergebnis ausgeben
        std::string name = "XOR " + std::to_string(size/1024) + " KB";
        print_benchmark_result(name + " (Standard vs Unrolled)", std_time, unrolled_time);
        print_benchmark_result(name + " (Standard vs SIMD)", std_time, simd_time);
        print_benchmark_result(name + " (Unrolled vs SIMD)", unrolled_time, simd_time);
        
        // Validiere Ergebnisse
        bool results_match_unrolled = std::equal(result_std.begin(), result_std.end(), result_unrolled.begin());
        bool results_match_simd = std::equal(result_std.begin(), result_std.end(), result_simd.begin());
        
        if (!results_match_unrolled || !results_match_simd) {
            std::cout << "FEHLER: Ergebnisse stimmen nicht überein!" << std::endl;
        } else {
            std::cout << "Validierung: OK" << std::endl;
        }
        
        std::cout << std::string(40, '-') << std::endl;
    }
    
    std::cout << "\nBenchmark abgeschlossen!" << std::endl;
    
    return 0;
}
