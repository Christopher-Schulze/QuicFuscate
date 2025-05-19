#ifndef CACHE_OPTIMIZATIONS_HPP
#define CACHE_OPTIMIZATIONS_HPP

#include <cstdint>
#include <type_traits>
#include <memory>
#include <vector>
#include <array>

namespace quicsand {

/**
 * @brief Deklariert eine Variable als cache-aligned.
 *
 * Dieser Makro richtet eine Variable an der Cache-Linie aus, um Cache-Effizenz zu verbessern
 * und False Sharing zu vermeiden.
 */
#if defined(_MSC_VER)
#define CACHE_ALIGNED __declspec(align(64))
#elif defined(__GNUC__) || defined(__clang__)
#define CACHE_ALIGNED __attribute__((aligned(64)))
#else
#define CACHE_ALIGNED
#endif

/**
 * @brief Standardgröße einer Cache-Linie auf gängigen Prozessoren.
 *
 * Die meisten modernen CPUs verwenden 64-Byte Cache-Linien. ARM-CPUs
 * können zwischen 32-128 Bytes variieren.
 */
constexpr size_t CACHE_LINE_SIZE = 64;

/**
 * @brief Padding zum Vermeiden von False Sharing zwischen Datenstrukturen.
 *
 * Diese Struktur fügt Padding hinzu, um sicherzustellen, dass unterschiedliche
 * Instanzen auf verschiedenen Cache-Linien liegen.
 */
template <typename T>
struct PaddedData {
    T data;
    // Padding um auf Cache-Linien-Größe aufzufüllen
    char padding[CACHE_LINE_SIZE - (sizeof(T) % CACHE_LINE_SIZE)];
    
    PaddedData() = default;
    explicit PaddedData(const T& value) : data(value) {}
    explicit PaddedData(T&& value) : data(std::move(value)) {}
    
    operator T&() { return data; }
    operator const T&() const { return data; }
    
    T* operator&() { return &data; }
    const T* operator&() const { return &data; }
    
    T* operator->() { return &data; }
    const T* operator->() const { return &data; }
};

/**
 * @brief Cache-optimierter Vektor für bessere Lokalität.
 *
 * Diese Klasse verbessert die Cache-Lokalität für Arrays mit kleinen Elementen,
 * indem sie eine Bündelung in Cache-freundlichen Strukturen vornimmt.
 *
 * @tparam T Der Elementtyp
 * @tparam BlockSize Die Anzahl der Elemente pro Block
 */
template <typename T, size_t BlockSize = (CACHE_LINE_SIZE / sizeof(T))>
class CacheOptimizedVector {
public:
    using value_type = T;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    using size_type = std::size_t;
    
    // Konstruktoren
    CacheOptimizedVector() = default;
    
    explicit CacheOptimizedVector(size_type n) {
        reserve(n);
        for (size_type i = 0; i < n; ++i) {
            push_back(T());
        }
    }
    
    CacheOptimizedVector(size_type n, const T& value) {
        reserve(n);
        for (size_type i = 0; i < n; ++i) {
            push_back(value);
        }
    }
    
    // Element-Zugriff
    reference operator[](size_type index) {
        size_type block = index / BlockSize;
        size_type offset = index % BlockSize;
        return blocks_[block][offset];
    }
    
    const_reference operator[](size_type index) const {
        size_type block = index / BlockSize;
        size_type offset = index % BlockSize;
        return blocks_[block][offset];
    }
    
    reference at(size_type index) {
        if (index >= size_) {
            throw std::out_of_range("CacheOptimizedVector::at: index out of range");
        }
        size_type block = index / BlockSize;
        size_type offset = index % BlockSize;
        return blocks_[block][offset];
    }
    
    const_reference at(size_type index) const {
        if (index >= size_) {
            throw std::out_of_range("CacheOptimizedVector::at: index out of range");
        }
        size_type block = index / BlockSize;
        size_type offset = index % BlockSize;
        return blocks_[block][offset];
    }
    
    reference front() {
        return blocks_[0][0];
    }
    
    const_reference front() const {
        return blocks_[0][0];
    }
    
    reference back() {
        size_type block = (size_ - 1) / BlockSize;
        size_type offset = (size_ - 1) % BlockSize;
        return blocks_[block][offset];
    }
    
    const_reference back() const {
        size_type block = (size_ - 1) / BlockSize;
        size_type offset = (size_ - 1) % BlockSize;
        return blocks_[block][offset];
    }
    
    // Kapazitätsverwaltung
    bool empty() const {
        return size_ == 0;
    }
    
    size_type size() const {
        return size_;
    }
    
    void reserve(size_type n) {
        size_type required_blocks = (n + BlockSize - 1) / BlockSize;
        if (required_blocks > blocks_.size()) {
            blocks_.reserve(required_blocks);
            while (blocks_.size() < required_blocks) {
                blocks_.push_back(std::make_unique<Block>());
            }
        }
    }
    
    size_type capacity() const {
        return blocks_.size() * BlockSize;
    }
    
    // Modifikatoren
    void clear() {
        size_ = 0;
    }
    
    void push_back(const T& value) {
        size_type block = size_ / BlockSize;
        size_type offset = size_ % BlockSize;
        
        if (block >= blocks_.size()) {
            blocks_.push_back(std::make_unique<Block>());
        }
        
        (*blocks_[block])[offset] = value;
        ++size_;
    }
    
    void push_back(T&& value) {
        size_type block = size_ / BlockSize;
        size_type offset = size_ % BlockSize;
        
        if (block >= blocks_.size()) {
            blocks_.push_back(std::make_unique<Block>());
        }
        
        (*blocks_[block])[offset] = std::move(value);
        ++size_;
    }
    
    void pop_back() {
        if (size_ > 0) {
            --size_;
        }
    }
    
    void resize(size_type new_size) {
        if (new_size > size_) {
            reserve(new_size);
            while (size_ < new_size) {
                push_back(T());
            }
        } else {
            size_ = new_size;
        }
    }
    
    void resize(size_type new_size, const T& value) {
        if (new_size > size_) {
            reserve(new_size);
            while (size_ < new_size) {
                push_back(value);
            }
        } else {
            size_ = new_size;
        }
    }
    
private:
    using Block = std::array<T, BlockSize>;
    std::vector<std::unique_ptr<Block>> blocks_;
    size_type size_ = 0;
};

/**
 * @brief Hilfsklasse für Prefetching-Operationen.
 *
 * Diese Klasse enthält Hilfsmethoden, um Cache-Prefetching für
 * kritische Datenpfade zu optimieren.
 */
class Prefetcher {
public:
    /**
     * @brief Prefetch-Typen für verschiedene Zugriffsszenarien.
     */
    enum class PrefetchType {
        READ,       // Prefetch für Lesezugriffe
        WRITE       // Prefetch für Schreibzugriffe
    };
    
    /**
     * @brief Prefetch-Lokalität, bestimmt wie bald auf die Daten zugegriffen wird.
     */
    enum class PrefetchLocality {
        NONE,       // Keine Lokalität
        LOW,        // Niedrige Temporal-Lokalität
        MODERATE,   // Mittlere Temporal-Lokalität
        HIGH        // Hohe Temporal-Lokalität
    };
    
    /**
     * @brief Führt einen Prefetch-Befehl für die angegebene Adresse aus.
     *
     * @param addr Die zu prefetchende Speicheradresse
     * @param type Der Typ des Prefetch (Lesen oder Schreiben)
     * @param locality Die Temporal-Lokalität
     */
    static void prefetch(const void* addr, PrefetchType type = PrefetchType::READ, 
                        PrefetchLocality locality = PrefetchLocality::MODERATE) {
        // Verschiedene CPU-Architekturen unterstützen unterschiedliche Prefetch-Befehle
#if defined(__GNUC__) || defined(__clang__)
        // Verwendung von Switch statt direkter Typumwandlung für konstante Werte
        if (type == PrefetchType::READ) {
            switch (locality) {
                case PrefetchLocality::NONE:
                    __builtin_prefetch(addr, 0, 0);
                    break;
                case PrefetchLocality::LOW:
                    __builtin_prefetch(addr, 0, 1);
                    break;
                case PrefetchLocality::MODERATE:
                    __builtin_prefetch(addr, 0, 2);
                    break;
                case PrefetchLocality::HIGH:
                    __builtin_prefetch(addr, 0, 3);
                    break;
            }
        } else {
            switch (locality) {
                case PrefetchLocality::NONE:
                    __builtin_prefetch(addr, 1, 0);
                    break;
                case PrefetchLocality::LOW:
                    __builtin_prefetch(addr, 1, 1);
                    break;
                case PrefetchLocality::MODERATE:
                    __builtin_prefetch(addr, 1, 2);
                    break;
                case PrefetchLocality::HIGH:
                    __builtin_prefetch(addr, 1, 3);
                    break;
            }
        }
#elif defined(_MSC_VER) && defined(_M_IX86)
        // Visual C++ für x86/x64
        (void)addr;
        (void)type;
        (void)locality;
        // MSVC bietet keine direkte intrinsic für Prefetch
#endif
    }
    
    /**
     * @brief Prefetch eines zusammenhängenden Speicherbereichs.
     *
     * @param addr Die Startadresse des Speicherbereichs
     * @param size_bytes Die Größe des Speicherbereichs in Bytes
     * @param type Der Typ des Prefetch (Lesen oder Schreiben)
     * @param locality Die Temporal-Lokalität
     */
    static void prefetch_range(const void* addr, size_t size_bytes, 
                               PrefetchType type = PrefetchType::READ,
                               PrefetchLocality locality = PrefetchLocality::MODERATE) {
        const char* p = static_cast<const char*>(addr);
        const char* end = p + size_bytes;
        
        // Prefetch jede Cache-Linie im Bereich
        for (; p < end; p += CACHE_LINE_SIZE) {
            prefetch(p, type, locality);
        }
    }
    
    /**
     * @brief Prefetch eines Arrays von Elementen.
     *
     * @tparam T Der Elementtyp
     * @param array Der Array von Elementen
     * @param count Die Anzahl der Elemente
     * @param type Der Typ des Prefetch (Lesen oder Schreiben)
     * @param locality Die Temporal-Lokalität
     */
    template <typename T>
    static void prefetch_array(const T* array, size_t count, 
                              PrefetchType type = PrefetchType::READ,
                              PrefetchLocality locality = PrefetchLocality::MODERATE) {
        prefetch_range(array, count * sizeof(T), type, locality);
    }
};

/**
 * @brief Fügt einer Klasse Padding hinzu, um sie an Cache-Linien auszurichten.
 *
 * Dieser Template verhindert False Sharing bei parallel zugreifenden Threads,
 * indem er die Klasse mit Padding auf die Cache-Linien-Größe erweitert.
 *
 * @tparam T Die zu padende Klasse
 */
template <typename T>
class CacheAlignedObject : public T {
private:
    // Padding am Ende der Klasse, um False Sharing zu vermeiden
    char padding_[CACHE_LINE_SIZE - (sizeof(T) % CACHE_LINE_SIZE)];
    
public:
    // Konstruktoren, die alle Konstruktoren von T unterstützen
    template <typename... Args>
    explicit CacheAlignedObject(Args&&... args) : T(std::forward<Args>(args)...) {}
    
    // Stellen Sie sicher, dass die Objekte auch an Cache-Linien ausgerichtet sind
    static void* operator new(std::size_t size) {
        void* ptr = nullptr;
#if defined(_MSC_VER)
        ptr = _aligned_malloc(size, CACHE_LINE_SIZE);
#else
        if (posix_memalign(&ptr, CACHE_LINE_SIZE, size) != 0) {
            throw std::bad_alloc();
        }
#endif
        return ptr;
    }
    
    static void operator delete(void* ptr) {
#if defined(_MSC_VER)
        _aligned_free(ptr);
#else
        free(ptr);
#endif
    }
};

/**
 * @brief Cache-Optimierungs-Konfiguration für verschiedene Komponenten.
 */
struct CacheOptimizationConfig {
    bool enable_data_locality = true;        // Optimiert Data Locality
    bool enable_false_sharing_prevention = true; // Verhindert False Sharing
    bool enable_prefetching = true;          // Aktiviert Prefetching
    
    // Prefetch-Parameter
    size_t prefetch_distance = 2;            // Anzahl der vorausschauenden Cache-Linien
    Prefetcher::PrefetchLocality prefetch_locality = Prefetcher::PrefetchLocality::MODERATE;
};

} // namespace quicsand

#endif // CACHE_OPTIMIZATIONS_HPP
