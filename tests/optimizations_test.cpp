#include "../core/cache_optimizations.hpp"
#include "../core/thread_optimizations.hpp"
#include "../core/energy_optimizations.hpp"
#include "../core/optimizations_integration.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <iomanip>

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

// Test für CacheOptimizedVector
void test_cache_optimized_vector() {
    std::cout << "=== Cache-Optimized Vector Test ===" << std::endl;
    
    const size_t vector_size = 10000;
    
    // Test mit einem regulären std::vector
    auto std_vector_test = [vector_size]() {
        std::vector<int> vec;
        vec.reserve(vector_size);
        
        for (size_t i = 0; i < vector_size; ++i) {
            vec.push_back(static_cast<int>(i));
        }
        
        // Random access
        int sum = 0;
        for (size_t i = 0; i < vector_size; ++i) {
            sum += vec[i];
        }
        return sum;
    };
    
    // Test mit CacheOptimizedVector
    auto cache_vector_test = [vector_size]() {
        CacheOptimizedVector<int> vec;
        vec.reserve(vector_size);
        
        for (size_t i = 0; i < vector_size; ++i) {
            vec.push_back(static_cast<int>(i));
        }
        
        // Random access
        int sum = 0;
        for (size_t i = 0; i < vector_size; ++i) {
            sum += vec[i];
        }
        return sum;
    };
    
    // Führe Messungen durch
    const int iterations = 100;
    double std_time = measure_execution_time(std_vector_test, iterations);
    double cache_time = measure_execution_time(cache_vector_test, iterations);
    
    std::cout << "Standard std::vector Durchschnittszeit: " << std_time << " µs" << std::endl;
    std::cout << "CacheOptimizedVector Durchschnittszeit: " << cache_time << " µs" << std::endl;
    
    double performance_ratio = std_time / cache_time;
    std::cout << "Performance-Verhältnis: " << std::fixed << std::setprecision(2) 
              << performance_ratio << "x" 
              << (performance_ratio > 1.0 ? " (CacheOptimizedVector ist schneller)" : "") 
              << std::endl;
    
    // Testen der Funktionalität
    CacheOptimizedVector<int> vec;
    for (int i = 0; i < 100; ++i) {
        vec.push_back(i);
    }
    
    assert(vec.size() == 100);
    assert(vec[50] == 50);
    
    vec.resize(200, -1);
    assert(vec.size() == 200);
    assert(vec[150] == -1);
    
    std::cout << "CacheOptimizedVector Funktionalitätstest bestanden!" << std::endl;
}

// Test für False Sharing Elimination
void test_false_sharing_elimination() {
    std::cout << "\n=== False Sharing Elimination Test ===" << std::endl;
    
    const int num_iterations = 10000000;
    const int num_threads = 4;
    
    // Test mit normalen atomaren Zählern (anfällig für False Sharing)
    auto test_normal_counters = [num_iterations, num_threads]() {
        std::vector<std::atomic<int>> counters(num_threads);
        for (int i = 0; i < num_threads; ++i) {
            counters[i] = 0;
        }
        
        std::vector<std::thread> threads;
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([t, &counters, num_iterations]() {
                for (int i = 0; i < num_iterations; ++i) {
                    counters[t].fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
    };
    
    // Test mit cache-aligned atomaren Zählern (verhindert False Sharing)
    auto test_cache_aligned_counters = [num_iterations, num_threads]() {
        std::vector<CacheAlignedAtomic<int>> counters(num_threads);
        for (int i = 0; i < num_threads; ++i) {
            counters[i] = 0;
        }
        
        std::vector<std::thread> threads;
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([t, &counters, num_iterations]() {
                for (int i = 0; i < num_iterations; ++i) {
                    counters[t].fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
    };
    
    double normal_time = measure_execution_time(test_normal_counters);
    double cache_aligned_time = measure_execution_time(test_cache_aligned_counters);
    
    std::cout << "Standard Atomic Counters Zeit: " << normal_time << " µs" << std::endl;
    std::cout << "Cache-Aligned Atomic Counters Zeit: " << cache_aligned_time << " µs" << std::endl;
    
    double performance_ratio = normal_time / cache_aligned_time;
    std::cout << "Performance-Verhältnis: " << std::fixed << std::setprecision(2) 
              << performance_ratio << "x" 
              << (performance_ratio > 1.0 ? " (Cache-Aligned ist schneller)" : "") 
              << std::endl;
    
    // Testen der Funktionalität
    CacheAlignedAtomic<int> counter(0);
    assert(counter.load() == 0);
    
    counter.fetch_add(5, std::memory_order_relaxed);
    assert(counter.load() == 5);
    
    counter.fetch_sub(2, std::memory_order_relaxed);
    assert(counter.load() == 3);
    
    std::cout << "CacheAlignedAtomic Funktionalitätstest bestanden!" << std::endl;
}

// Test für Energieoptimierung
void test_energy_optimizations() {
    std::cout << "\n=== Energy Optimizations Test ===" << std::endl;
    
    // Testen verschiedener Thread-Energiemodi
    auto test_thread_mode = [](ThreadEnergyMode mode) {
        EnergyConfig config;
        config.thread_mode = mode;
        EnergyManager manager(config);
        
        std::atomic<bool> condition{false};
        std::thread test_thread([&]() {
            // Warte 50ms, dann setze die Bedingung
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            condition = true;
        });
        
        auto start = high_resolution_clock::now();
        
        // Verwende den effizienten Wartealgorithmus
        manager.wait_efficiently([&]() { return condition.load(); });
        
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(end - start).count();
        
        test_thread.join();
        
        return duration;
    };
    
    auto performance_duration = test_thread_mode(ThreadEnergyMode::PERFORMANCE);
    auto balanced_duration = test_thread_mode(ThreadEnergyMode::BALANCED);
    auto efficient_duration = test_thread_mode(ThreadEnergyMode::EFFICIENT);
    auto ultra_efficient_duration = test_thread_mode(ThreadEnergyMode::ULTRA_EFFICIENT);
    
    std::cout << "Wartezeit PERFORMANCE-Mode: " << performance_duration << " ms" << std::endl;
    std::cout << "Wartezeit BALANCED-Mode: " << balanced_duration << " ms" << std::endl;
    std::cout << "Wartezeit EFFICIENT-Mode: " << efficient_duration << " ms" << std::endl;
    std::cout << "Wartezeit ULTRA_EFFICIENT-Mode: " << ultra_efficient_duration << " ms" << std::endl;
    
    // Ein effizienterer Modus sollte mehr CPU-Ressourcen sparen, aber etwas langsamer sein
    // Hier nur eine grobe Erwartung, nicht strikt getestet wegen Systemabhängigkeiten
    std::cout << "Hinweis: Effizientere Modi können langsamer sein, sparen aber Energie" << std::endl;
    
    // Test des optimierten Worker-Pools
    EnergyEfficientWorkerPool pool(2, ThreadEnergyMode::BALANCED);
    std::atomic<int> counter{0};
    
    // Füge 10 Aufgaben hinzu
    for (int i = 0; i < 10; ++i) {
        pool.enqueue([&counter]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            counter.fetch_add(1, std::memory_order_relaxed);
        });
    }
    
    // Warte, bis alle Aufgaben abgeschlossen sind
    while (counter.load() < 10) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    assert(counter.load() == 10);
    std::cout << "EnergyEfficientWorkerPool Funktionalitätstest bestanden!" << std::endl;
}

// Test für die integrierte OptimizationsManager-Klasse
void test_optimizations_manager() {
    std::cout << "\n=== Optimizations Manager Integration Test ===" << std::endl;
    
    // Erstelle eine optimierte Konfiguration für Mobile-Geräte
    auto mobile_config = OptimizationsConfig::create_for_mobile();
    
    // Erstelle einen OptimizationsManager mit dieser Konfiguration
    OptimizationsManager manager(mobile_config);
    
    // Teste die Erstellung eines optimierten Buffers
    auto buffer = manager.create_optimized_buffer<uint8_t>(2048);
    for (int i = 0; i < 1000; ++i) {
        buffer.push_back(static_cast<uint8_t>(i & 0xFF));
    }
    
    assert(buffer.size() == 1000);
    assert(buffer[500] == (500 & 0xFF));
    
    // Teste die Erstellung eines Worker-Pools
    auto worker_pool = manager.create_optimized_worker_pool(2);
    std::atomic<int> task_counter{0};
    
    for (int i = 0; i < 5; ++i) {
        worker_pool->enqueue([&task_counter]() {
            task_counter.fetch_add(1, std::memory_order_relaxed);
        });
    }
    
    // Warte, bis alle Aufgaben erledigt sind
    while (task_counter.load() < 5) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    assert(task_counter.load() == 5);
    
    // Wechsle zur Server-Konfiguration
    manager.set_config(OptimizationsConfig::create_for_server());
    
    std::cout << "OptimizationsManager Tests bestanden!" << std::endl;
}

// Hauptfunktion
int main() {
    std::cout << "Optimierungen-Tests" << std::endl;
    std::cout << "===================" << std::endl;
    
    // Führe alle Tests aus
    test_cache_optimized_vector();
    test_false_sharing_elimination();
    test_energy_optimizations();
    test_optimizations_manager();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    
    return 0;
}
