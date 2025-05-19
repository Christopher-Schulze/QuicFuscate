#include "core/memory_pool.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <algorithm>
#include <iomanip>
#include <string>

using namespace quicsand;

// Formatieren von Größen in menschenlesbare Einheiten
std::string format_size(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return ss.str();
}

// Zeitmessung für Operationen
template<typename Func>
std::pair<double, typename std::result_of<Func()>::type> measure_time(Func&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    auto result = func();
    auto end = std::chrono::high_resolution_clock::now();
    
    std::chrono::duration<double, std::milli> duration = end - start;
    return {duration.count(), result};
}

// Standardallokationstest
void test_standard_allocations() {
    std::cout << "\n=== Test: Standard-Allokationen ===" << std::endl;
    
    // Konfiguration
    const int iterations = 10000;
    const int block_size = 1024;
    
    // Test mit Memory Pool
    {
        MemoryPool pool;
        std::vector<MemoryPool::MemoryBlock*> blocks;
        blocks.reserve(iterations);
        
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                auto block = pool.allocate(block_size);
                blocks.push_back(block);
            }
            
            for (auto block : blocks) {
                pool.release(block);
            }
            
            return true;
        });
        
        std::cout << "Memory Pool Allokation/Freigabe für " << iterations 
                  << " Blöcke (" << format_size(iterations * block_size) 
                  << "): " << time << " ms" << std::endl;
    }
    
    // Test mit Standard-Allokation
    {
        std::vector<uint8_t*> blocks;
        blocks.reserve(iterations);
        
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                auto block = new uint8_t[block_size];
                blocks.push_back(block);
            }
            
            for (auto block : blocks) {
                delete[] block;
            }
            
            return true;
        });
        
        std::cout << "Standard Allokation/Freigabe für " << iterations 
                  << " Blöcke (" << format_size(iterations * block_size)
                  << "): " << time << " ms" << std::endl;
    }
}

// Test mit verschiedenen Größen
void test_mixed_size_allocations() {
    std::cout << "\n=== Test: Gemischte Größen ===" << std::endl;
    
    // Konfiguration
    const int iterations = 10000;
    std::vector<size_t> sizes = {64, 128, 256, 512, 1024, 2048, 4096};
    
    // Zufallszahlengenerator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> size_dist(0, sizes.size() - 1);
    
    // Test mit Memory Pool
    {
        MemoryPool pool;
        std::vector<MemoryPool::MemoryBlock*> blocks;
        blocks.reserve(iterations);
        
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                size_t size = sizes[size_dist(gen)];
                auto block = pool.allocate(size);
                blocks.push_back(block);
            }
            
            for (auto block : blocks) {
                pool.release(block);
            }
            
            return true;
        });
        
        std::cout << "Memory Pool mit gemischten Größen: " << time << " ms" << std::endl;
    }
    
    // Test mit Standard-Allokation
    {
        std::vector<std::pair<uint8_t*, size_t>> blocks;
        blocks.reserve(iterations);
        
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                size_t size = sizes[size_dist(gen)];
                auto block = new uint8_t[size];
                blocks.push_back({block, size});
            }
            
            for (auto& [block, size] : blocks) {
                delete[] block;
            }
            
            return true;
        });
        
        std::cout << "Standard-Allokation mit gemischten Größen: " << time << " ms" << std::endl;
    }
}

// Test der PoolBuffer-Klasse
void test_pool_buffer() {
    std::cout << "\n=== Test: PoolBuffer-Klasse ===" << std::endl;
    
    // Konfiguration
    const int iterations = 100000;
    const int buffer_size = 256;
    
    // Test mit PoolBuffer
    {
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                MemoryPool::PoolBuffer<> buffer(buffer_size);
                for (size_t j = 0; j < buffer_size; j++) {
                    buffer[j] = static_cast<uint8_t>(j & 0xFF);
                }
            }
            return true;
        });
        
        std::cout << "PoolBuffer-Operationen für " << iterations 
                  << " Puffer: " << time << " ms" << std::endl;
    }
    
    // Test mit std::vector
    {
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                std::vector<uint8_t> buffer(buffer_size);
                for (size_t j = 0; j < buffer_size; j++) {
                    buffer[j] = static_cast<uint8_t>(j & 0xFF);
                }
            }
            return true;
        });
        
        std::cout << "std::vector-Operationen für " << iterations 
                  << " Puffer: " << time << " ms" << std::endl;
    }
}

// Lasttests mit Reallokationen
void test_reallocation() {
    std::cout << "\n=== Test: Reallokation ===" << std::endl;
    
    // Konfiguration
    const int iterations = 10000;
    const int initial_size = 128;
    const int final_size = 1024;
    
    // Test mit PoolBuffer
    {
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                MemoryPool::PoolBuffer<> buffer(initial_size);
                for (int j = 0; j < 5; j++) {
                    buffer.resize(initial_size * (j + 1));
                }
                buffer.resize(final_size);
            }
            return true;
        });
        
        std::cout << "PoolBuffer Reallokationen: " << time << " ms" << std::endl;
    }
    
    // Test mit std::vector
    {
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                std::vector<uint8_t> buffer(initial_size);
                for (int j = 0; j < 5; j++) {
                    buffer.resize(initial_size * (j + 1));
                }
                buffer.resize(final_size);
            }
            return true;
        });
        
        std::cout << "std::vector Reallokationen: " << time << " ms" << std::endl;
    }
}

// Test für Speicherfragmentierung
void test_fragmentation() {
    std::cout << "\n=== Test: Speicherfragmentierung ===" << std::endl;
    
    // Konfiguration
    const int iterations = 100000;
    std::vector<size_t> sizes = {64, 128, 256, 512, 1024, 2048};
    
    // Zufallszahlengenerator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> size_dist(0, sizes.size() - 1);
    std::uniform_int_distribution<> op_dist(0, 1);  // 0 = Allokieren, 1 = Freigeben
    
    // Test mit Memory Pool
    {
        MemoryPool pool;
        std::vector<MemoryPool::MemoryBlock*> blocks;
        blocks.reserve(iterations / 2);
        
        auto [time, _] = measure_time([&]() {
            for (int i = 0; i < iterations; i++) {
                int op = op_dist(gen);
                
                if (op == 0 || blocks.empty()) {
                    // Allokieren
                    size_t size = sizes[size_dist(gen)];
                    auto block = pool.allocate(size);
                    blocks.push_back(block);
                } else {
                    // Freigeben
                    int index = gen() % blocks.size();
                    pool.release(blocks[index]);
                    blocks.erase(blocks.begin() + index);
                }
            }
            
            // Restliche Blöcke freigeben
            for (auto block : blocks) {
                pool.release(block);
            }
            
            return true;
        });
        
        std::cout << "Memory Pool unter Fragmentierungslast: " << time << " ms" << std::endl;
        
        // Statistiken anzeigen
        auto stats = pool.get_statistics();
        std::cout << "  - Allokationen: " << stats.allocations << std::endl;
        std::cout << "  - Freigaben: " << stats.releases << std::endl;
        std::cout << "  - Cache-Hits: " << stats.cache_hits << std::endl;
        std::cout << "  - Cache-Hit-Rate: " 
                  << (stats.allocations > 0 ? (100.0 * stats.cache_hits / stats.allocations) : 0.0)
                  << "%" << std::endl;
        std::cout << "  - Freie Blöcke: " << stats.total_free_blocks << std::endl;
        
        std::cout << "  - Blöcke pro Größenklasse:" << std::endl;
        for (size_t i = 0; i < stats.free_blocks_per_class.size(); i++) {
            std::cout << "    - " << format_size(stats.size_per_class[i]) << ": " 
                     << stats.free_blocks_per_class[i] << std::endl;
        }
    }
}

int main() {
    std::cout << "===== QuicSand Memory Pool Tests =====" << std::endl;
    
    // Führe alle Tests durch
    test_standard_allocations();
    test_mixed_size_allocations();
    test_pool_buffer();
    test_reallocation();
    test_fragmentation();
    
    std::cout << "\nTests abgeschlossen." << std::endl;
    return 0;
}
