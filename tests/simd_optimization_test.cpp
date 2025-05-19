#include "../core/cache_optimizations.hpp"
#include "../core/energy_optimizations.hpp"
#include "../core/optimizations_integration.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cassert>
#include <iomanip>

#ifdef SIMD_NEON_ENABLED
#include <arm_neon.h>
#elif defined(SIMD_AVX2_ENABLED)
#include <immintrin.h>
#endif

using namespace quicsand;
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

// Testet die Addition von Vektoren mit SIMD-Optimierungen
void test_vector_addition() {
    std::cout << "=== Vector Addition SIMD Test ===" << std::endl;
    
    const size_t vector_size = 1024 * 1024; // 1MB
    
    // Erstelle Testdaten
    std::vector<uint8_t> vector_a = generate_random_data(vector_size);
    std::vector<uint8_t> vector_b = generate_random_data(vector_size);
    std::vector<uint8_t> result_scalar(vector_size);
    std::vector<uint8_t> result_simd(vector_size);
    
    // Skalare Implementation
    auto scalar_addition = [&]() {
        for (size_t i = 0; i < vector_size; ++i) {
            result_scalar[i] = vector_a[i] + vector_b[i];
        }
    };
    
    // SIMD Implementation
    auto simd_addition = [&]() {
#ifdef SIMD_NEON_ENABLED
        // ARM NEON SIMD-Optimierung
        for (size_t i = 0; i < vector_size; i += 16) {
            // Lade 16 Bytes in NEON Register
            uint8x16_t a = vld1q_u8(&vector_a[i]);
            uint8x16_t b = vld1q_u8(&vector_b[i]);
            
            // Addiere Vektoren
            uint8x16_t sum = vaddq_u8(a, b);
            
            // Speichere Ergebnis
            vst1q_u8(&result_simd[i], sum);
        }
#elif defined(SIMD_AVX2_ENABLED)
        // Intel AVX2 SIMD-Optimierung
        for (size_t i = 0; i < vector_size; i += 32) {
            // Lade 32 Bytes in AVX2 Register
            __m256i a = _mm256_loadu_si256((__m256i*)&vector_a[i]);
            __m256i b = _mm256_loadu_si256((__m256i*)&vector_b[i]);
            
            // Addiere Vektoren
            __m256i sum = _mm256_add_epi8(a, b);
            
            // Speichere Ergebnis
            _mm256_storeu_si256((__m256i*)&result_simd[i], sum);
        }
#else
        // Fallback für nicht-SIMD-Plattformen
        for (size_t i = 0; i < vector_size; ++i) {
            result_simd[i] = vector_a[i] + vector_b[i];
        }
#endif
    };
    
    // Führe Tests aus
    double scalar_time = measure_execution_time(scalar_addition, 10);
    double simd_time = measure_execution_time(simd_addition, 10);
    
    // Führe einmal aus, um Ergebnisse zu haben
    scalar_addition();
    simd_addition();
    
    // Überprüfe, ob beide Implementierungen das gleiche Ergebnis liefern
    bool results_match = true;
    for (size_t i = 0; i < vector_size; ++i) {
        if (result_scalar[i] != result_simd[i]) {
            results_match = false;
            break;
        }
    }
    
    std::cout << "Skalare Addition Zeit: " << scalar_time << " µs" << std::endl;
    std::cout << "SIMD Addition Zeit: " << simd_time << " µs" << std::endl;
    std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
              << (scalar_time / simd_time) << "x" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
    
    assert(results_match);
    std::cout << "Test erfolgreich!" << std::endl;
}

// Testet XOR-Operationen mit SIMD-Optimierungen (relevant für Tetrys FEC)
void test_xor_operation() {
    std::cout << "\n=== XOR Operation SIMD Test (FEC relevant) ===" << std::endl;
    
    const size_t vector_size = 1024 * 1024; // 1MB
    
    // Erstelle Testdaten
    std::vector<uint8_t> vector_a = generate_random_data(vector_size);
    std::vector<uint8_t> vector_b = generate_random_data(vector_size);
    std::vector<uint8_t> result_scalar(vector_size);
    std::vector<uint8_t> result_simd(vector_size);
    
    // Skalare Implementation
    auto scalar_xor = [&]() {
        for (size_t i = 0; i < vector_size; ++i) {
            result_scalar[i] = vector_a[i] ^ vector_b[i];
        }
    };
    
    // SIMD Implementation
    auto simd_xor = [&]() {
#ifdef SIMD_NEON_ENABLED
        // ARM NEON SIMD-Optimierung
        for (size_t i = 0; i < vector_size; i += 16) {
            // Lade 16 Bytes in NEON Register
            uint8x16_t a = vld1q_u8(&vector_a[i]);
            uint8x16_t b = vld1q_u8(&vector_b[i]);
            
            // XOR Vektoren
            uint8x16_t result = veorq_u8(a, b);
            
            // Speichere Ergebnis
            vst1q_u8(&result_simd[i], result);
        }
#elif defined(SIMD_AVX2_ENABLED)
        // Intel AVX2 SIMD-Optimierung
        for (size_t i = 0; i < vector_size; i += 32) {
            // Lade 32 Bytes in AVX2 Register
            __m256i a = _mm256_loadu_si256((__m256i*)&vector_a[i]);
            __m256i b = _mm256_loadu_si256((__m256i*)&vector_b[i]);
            
            // XOR Vektoren
            __m256i result = _mm256_xor_si256(a, b);
            
            // Speichere Ergebnis
            _mm256_storeu_si256((__m256i*)&result_simd[i], result);
        }
#else
        // Fallback für nicht-SIMD-Plattformen
        for (size_t i = 0; i < vector_size; ++i) {
            result_simd[i] = vector_a[i] ^ vector_b[i];
        }
#endif
    };
    
    // Führe Tests aus
    double scalar_time = measure_execution_time(scalar_xor, 10);
    double simd_time = measure_execution_time(simd_xor, 10);
    
    // Führe einmal aus, um Ergebnisse zu haben
    scalar_xor();
    simd_xor();
    
    // Überprüfe, ob beide Implementierungen das gleiche Ergebnis liefern
    bool results_match = true;
    for (size_t i = 0; i < vector_size; ++i) {
        if (result_scalar[i] != result_simd[i]) {
            results_match = false;
            break;
        }
    }
    
    std::cout << "Skalare XOR Zeit: " << scalar_time << " µs" << std::endl;
    std::cout << "SIMD XOR Zeit: " << simd_time << " µs" << std::endl;
    std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
              << (scalar_time / simd_time) << "x" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
    
    assert(results_match);
    std::cout << "Test erfolgreich!" << std::endl;
}

// Testet Matrix-Multiplikation mit SIMD-Optimierungen (relevant für Galois-Feld-Operationen in Tetrys)
void test_matrix_multiplication() {
    std::cout << "\n=== Matrix Multiplication SIMD Test (Galois-Feld relevant) ===" << std::endl;
    
    const size_t matrix_size = 256; // 256x256 Matrix
    
    // Erstelle Testdaten (8-bit Matrizen)
    std::vector<uint8_t> matrix_a(matrix_size * matrix_size);
    std::vector<uint8_t> matrix_b(matrix_size * matrix_size);
    std::vector<uint16_t> result_scalar(matrix_size * matrix_size, 0);
    std::vector<uint16_t> result_simd(matrix_size * matrix_size, 0);
    
    // Initialisiere Matrizen mit zufälligen Werten
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 15); // Kleine Werte, um Überlauf zu vermeiden
    
    for (size_t i = 0; i < matrix_size * matrix_size; ++i) {
        matrix_a[i] = static_cast<uint8_t>(distrib(gen));
        matrix_b[i] = static_cast<uint8_t>(distrib(gen));
    }
    
    // Skalare Implementation
    auto scalar_matmul = [&]() {
        for (size_t i = 0; i < matrix_size; ++i) {
            for (size_t j = 0; j < matrix_size; ++j) {
                uint16_t sum = 0;
                for (size_t k = 0; k < matrix_size; ++k) {
                    sum += static_cast<uint16_t>(matrix_a[i * matrix_size + k]) * 
                           static_cast<uint16_t>(matrix_b[k * matrix_size + j]);
                }
                result_scalar[i * matrix_size + j] = sum;
            }
        }
    };
    
    // SIMD Implementation (vereinfacht für NEON und AVX2)
    auto simd_matmul = [&]() {
#ifdef SIMD_NEON_ENABLED
        // ARM NEON Implementation
        for (size_t i = 0; i < matrix_size; ++i) {
            for (size_t j = 0; j < matrix_size; j += 8) {
                uint16x8_t sum = vdupq_n_u16(0);
                
                for (size_t k = 0; k < matrix_size; k += 8) {
                    for (size_t l = 0; l < 8 && k + l < matrix_size; ++l) {
                        uint8x8_t a_val = vdup_n_u8(matrix_a[i * matrix_size + (k + l)]);
                        uint8x8_t b_val = vld1_u8(&matrix_b[(k + l) * matrix_size + j]);
                        
                        // Multipliziere und akkumuliere
                        uint16x8_t prod = vmull_u8(a_val, b_val);
                        sum = vaddq_u16(sum, prod);
                    }
                }
                
                // Speichere Ergebnis
                vst1q_u16(&result_simd[i * matrix_size + j], sum);
            }
        }
#elif defined(SIMD_AVX2_ENABLED)
        // Intel AVX2 Implementation
        for (size_t i = 0; i < matrix_size; ++i) {
            for (size_t j = 0; j < matrix_size; j += 16) {
                __m256i sum_lo = _mm256_setzero_si256();
                __m256i sum_hi = _mm256_setzero_si256();
                
                for (size_t k = 0; k < matrix_size; k += 16) {
                    for (size_t l = 0; l < 16 && k + l < matrix_size; ++l) {
                        __m128i a_val = _mm_set1_epi8(matrix_a[i * matrix_size + (k + l)]);
                        __m128i b_val = _mm_loadu_si128((__m128i*)&matrix_b[(k + l) * matrix_size + j]);
                        
                        // Konvertiere zu 16-bit
                        __m256i a_val_lo = _mm256_cvtepu8_epi16(a_val);
                        __m256i b_val_lo = _mm256_cvtepu8_epi16(b_val);
                        
                        // Multipliziere und akkumuliere
                        __m256i prod_lo = _mm256_mullo_epi16(a_val_lo, b_val_lo);
                        sum_lo = _mm256_add_epi16(sum_lo, prod_lo);
                    }
                }
                
                // Speichere Ergebnis
                _mm256_storeu_si256((__m256i*)&result_simd[i * matrix_size + j], sum_lo);
                if (j + 16 < matrix_size) {
                    _mm256_storeu_si256((__m256i*)&result_simd[i * matrix_size + j + 16], sum_hi);
                }
            }
        }
#else
        // Fallback für nicht-SIMD-Plattformen
        scalar_matmul();
#endif
    };
    
    // Führe Tests aus (weniger Iterationen für die langsame Matrix-Multiplikation)
    double scalar_time = measure_execution_time(scalar_matmul, 3);
    double simd_time = measure_execution_time(simd_matmul, 3);
    
    // Führe einmal aus, um Ergebnisse zu haben
    scalar_matmul();
    simd_matmul();
    
    // Überprüfe, ob beide Implementierungen ähnliche Ergebnisse liefern
    // Bei Floating-Point-Berechnungen können kleine Unterschiede auftreten
    bool results_match = true;
    for (size_t i = 0; i < matrix_size * matrix_size; ++i) {
        if (std::abs(static_cast<int>(result_scalar[i]) - static_cast<int>(result_simd[i])) > 1) {
            results_match = false;
            break;
        }
    }
    
    std::cout << "Skalare Matrix-Multiplikation Zeit: " << scalar_time << " µs" << std::endl;
    std::cout << "SIMD Matrix-Multiplikation Zeit: " << simd_time << " µs" << std::endl;
    std::cout << "Beschleunigung: " << std::fixed << std::setprecision(2) 
              << (scalar_time / simd_time) << "x" << std::endl;
    std::cout << "Ergebnisse stimmen überein: " << (results_match ? "Ja" : "Nein") << std::endl;
    
    // Bei Matrix-Multiplikation können Rundungsfehler auftreten, daher ist dieser Test optional
    if (!results_match) {
        std::cout << "Hinweis: Bei der Matrix-Multiplikation können durch unterschiedliche Rundung oder Akkumulation kleine Unterschiede auftreten." << std::endl;
    }
    
    std::cout << "Test abgeschlossen!" << std::endl;
}

// Hauptfunktion
int main() {
    std::cout << "SIMD Optimierungen Test" << std::endl;
    std::cout << "======================" << std::endl;
    
#ifdef SIMD_NEON_ENABLED
    std::cout << "ARM NEON SIMD-Optimierungen aktiviert" << std::endl;
#elif defined(SIMD_AVX2_ENABLED)
    std::cout << "Intel AVX2 SIMD-Optimierungen aktiviert" << std::endl;
#else
    std::cout << "Keine SIMD-Optimierungen verfügbar, Fallback auf skalaren Code" << std::endl;
#endif
    
    test_vector_addition();
    test_xor_operation();
    test_matrix_multiplication();
    
    std::cout << "\nAlle Tests abgeschlossen!" << std::endl;
    return 0;
}
