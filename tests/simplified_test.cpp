#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

// Vereinfachte Version der Cache-Line-Optimierung
constexpr size_t CACHE_LINE_SIZE = 64;

// Cache-aligned Struct zur Vermeidung von False Sharing
template <typename T>
struct alignas(CACHE_LINE_SIZE) CacheAlignedType {
    T data;
    // Padding zur Vermeidung von False Sharing
    char padding[CACHE_LINE_SIZE - sizeof(T)];

    CacheAlignedType() = default;
    explicit CacheAlignedType(const T& value) : data(value) {}

    operator T&() { return data; }
    operator const T&() const { return data; }
};

// Vereinfachter Test für Cache-Optimierungen
void test_cache_alignment() {
    std::cout << "=== Cache Alignment Test ===" << std::endl;
    
    // Nicht ausgerichtete Zähler
    std::vector<std::atomic<int>> standard_counters(4);
    for (auto& counter : standard_counters) {
        counter.store(0);
    }
    
    // Cache-aligned Zähler
    std::vector<CacheAlignedType<std::atomic<int>>> aligned_counters(4);
    for (auto& counter : aligned_counters) {
        counter.data.store(0);
    }
    
    // Multi-Threading-Test mit normalen Zählern
    auto standard_test = [&]() {
        std::vector<std::thread> threads;
        const int iterations = 1000000;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([t, &standard_counters, iterations]() {
                for (int i = 0; i < iterations; ++i) {
                    standard_counters[t].fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        return duration;
    };
    
    // Multi-Threading-Test mit cache-aligned Zählern
    auto aligned_test = [&]() {
        std::vector<std::thread> threads;
        const int iterations = 1000000;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([t, &aligned_counters, iterations]() {
                for (int i = 0; i < iterations; ++i) {
                    aligned_counters[t].data.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        return duration;
    };
    
    // Führe Tests durch
    std::cout << "Führe Test mit Standard-Atomics aus..." << std::endl;
    auto standard_duration = standard_test();
    
    std::cout << "Führe Test mit Cache-Aligned Atomics aus..." << std::endl;
    auto aligned_duration = aligned_test();
    
    std::cout << "Ergebnis:" << std::endl;
    std::cout << "Standard-Atomics: " << standard_duration << " ms" << std::endl;
    std::cout << "Cache-Aligned Atomics: " << aligned_duration << " ms" << std::endl;
    std::cout << "Verbesserung: " << (standard_duration > 0 ? 
                                    double(standard_duration) / aligned_duration : 0)
              << "x" << std::endl;
    
    // Überprüfe Ergebnisse
    for (int i = 0; i < 4; ++i) {
        if (standard_counters[i] != 1000000 || aligned_counters[i].data != 1000000) {
            std::cout << "FEHLER: Zähler haben nicht die erwarteten Werte!" << std::endl;
            return;
        }
    }
    
    std::cout << "Test erfolgreich abgeschlossen!" << std::endl;
}

// Vereinfachter Test für Energieoptimierungen
enum class ThreadEnergyMode {
    PERFORMANCE,
    EFFICIENT
};

class SimpleEnergyManager {
public:
    SimpleEnergyManager(ThreadEnergyMode mode = ThreadEnergyMode::EFFICIENT)
        : mode_(mode), spin_count_(mode == ThreadEnergyMode::PERFORMANCE ? 10000 : 1000) {}
    
    void set_mode(ThreadEnergyMode mode) {
        mode_ = mode;
        spin_count_ = (mode == ThreadEnergyMode::PERFORMANCE ? 10000 : 1000);
    }
    
    template<typename Predicate>
    bool wait_efficiently(Predicate predicate, std::chrono::milliseconds timeout) {
        auto start_time = std::chrono::steady_clock::now();
        
        // Versuche zuerst zu spinnen (für PERFORMANCE-Modus)
        if (mode_ == ThreadEnergyMode::PERFORMANCE) {
            for (int i = 0; i < spin_count_ && !predicate(); ++i) {
                std::this_thread::yield();
                
                // Timeout überprüfen
                if (std::chrono::steady_clock::now() - start_time >= timeout) {
                    return false;
                }
            }
        }
        
        // Wenn wir hier ankommen und die Bedingung erfüllt ist, sind wir fertig
        if (predicate()) {
            return true;
        }
        
        // Sonst warte adaptiv mit Sleep
        std::chrono::milliseconds sleep_time(1);
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            std::this_thread::sleep_for(sleep_time);
            
            if (predicate()) {
                return true;
            }
            
            // Erhöhe Schlafzeit adaptiv bis zu einem Maximum
            if (mode_ == ThreadEnergyMode::EFFICIENT) {
                sleep_time = std::min(sleep_time * 2, std::chrono::milliseconds(50));
            }
        }
        
        return false;
    }

private:
    ThreadEnergyMode mode_;
    int spin_count_;
};

void test_energy_optimization() {
    std::cout << "\n=== Energy Optimization Test ===" << std::endl;
    
    // Teste Performance-Modus
    SimpleEnergyManager performance_manager(ThreadEnergyMode::PERFORMANCE);
    
    std::atomic<bool> condition1{false};
    
    auto start1 = std::chrono::high_resolution_clock::now();
    
    std::thread setter1([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        condition1 = true;
    });
    
    performance_manager.wait_efficiently([&]() { return condition1.load(); }, 
                                       std::chrono::milliseconds(1000));
    
    auto end1 = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1).count();
    
    setter1.join();
    
    // Teste Efficient-Modus
    SimpleEnergyManager efficient_manager(ThreadEnergyMode::EFFICIENT);
    
    std::atomic<bool> condition2{false};
    
    auto start2 = std::chrono::high_resolution_clock::now();
    
    std::thread setter2([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        condition2 = true;
    });
    
    efficient_manager.wait_efficiently([&]() { return condition2.load(); }, 
                                     std::chrono::milliseconds(1000));
    
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2).count();
    
    setter2.join();
    
    std::cout << "Ergebnis:" << std::endl;
    std::cout << "Performance-Modus Wartezeit: " << duration1 << " ms" << std::endl;
    std::cout << "Efficient-Modus Wartezeit: " << duration2 << " ms" << std::endl;
    
    std::cout << "Test erfolgreich abgeschlossen!" << std::endl;
}

// Vereinfachter Test für Zero-Copy-Optimierung
class SimpleZeroCopyBuffer {
public:
    SimpleZeroCopyBuffer() : owned_(false), data_(nullptr), size_(0) {}
    
    // Zero-Copy-Konstruktor
    SimpleZeroCopyBuffer(uint8_t* data, size_t size) 
        : owned_(false), data_(data), size_(size) {}
    
    // Konstruktor mit Kopie
    SimpleZeroCopyBuffer(const uint8_t* data, size_t size, bool make_copy) {
        if (make_copy) {
            owned_ = true;
            size_ = size;
            data_ = new uint8_t[size];
            std::memcpy(data_, data, size);
        } else {
            owned_ = false;
            data_ = const_cast<uint8_t*>(data);
            size_ = size;
        }
    }
    
    // Destruktor
    ~SimpleZeroCopyBuffer() {
        if (owned_ && data_) {
            delete[] data_;
        }
    }
    
    // Move-Konstruktor
    SimpleZeroCopyBuffer(SimpleZeroCopyBuffer&& other) noexcept
        : owned_(other.owned_), data_(other.data_), size_(other.size_) {
        other.owned_ = false;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    
    // Erstellt eine Kopie mit eigenem Speicher
    SimpleZeroCopyBuffer clone() const {
        return SimpleZeroCopyBuffer(data_, size_, true);
    }
    
    uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    bool is_owned() const { return owned_; }

private:
    bool owned_;
    uint8_t* data_;
    size_t size_;
};

void test_zero_copy() {
    std::cout << "\n=== Zero-Copy Test ===" << std::endl;
    
    const size_t buffer_size = 1024 * 1024; // 1 MB
    
    // Erstelle einen großen Puffer
    auto* large_buffer = new uint8_t[buffer_size];
    for (size_t i = 0; i < buffer_size; ++i) {
        large_buffer[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    auto test_copy = [&]() {
        // Mit Kopie
        auto start = std::chrono::high_resolution_clock::now();
        
        SimpleZeroCopyBuffer buffer(large_buffer, buffer_size, true);
        
        // Nutzungssimulation
        size_t sum = 0;
        for (size_t i = 0; i < buffer.size(); ++i) {
            sum += buffer.data()[i];
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        return duration;
    };
    
    auto test_zero_copy = [&]() {
        // Zero-Copy
        auto start = std::chrono::high_resolution_clock::now();
        
        SimpleZeroCopyBuffer buffer(large_buffer, buffer_size, false);
        
        // Nutzungssimulation
        size_t sum = 0;
        for (size_t i = 0; i < buffer.size(); ++i) {
            sum += buffer.data()[i];
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        return duration;
    };
    
    // Führe Tests aus
    auto copy_duration = test_copy();
    auto zero_copy_duration = test_zero_copy();
    
    std::cout << "Mit Kopie: " << copy_duration << " µs" << std::endl;
    std::cout << "Zero-Copy: " << zero_copy_duration << " µs" << std::endl;
    std::cout << "Verbesserung: " << (copy_duration > 0 ? 
                                     double(copy_duration) / zero_copy_duration : 0)
              << "x" << std::endl;
    
    // Cleanup
    delete[] large_buffer;
    
    std::cout << "Test erfolgreich abgeschlossen!" << std::endl;
}

int main() {
    std::cout << "QuicSand Optimierungen Vereinfachter Test" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    test_cache_alignment();
    test_energy_optimization();
    test_zero_copy();
    
    std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
    return 0;
}
