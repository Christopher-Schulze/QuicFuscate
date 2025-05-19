#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <array>
#include <map>
#include <unordered_map>
#include <queue>
#include <cassert>
#include <type_traits>

namespace quicsand {

/**
 * MemoryPoolConfig - Konfiguration für den Speicherpool
 */
struct MemoryPoolConfig {
    size_t min_block_size;      // Minimale Blockgröße in Bytes
    size_t max_block_size;      // Maximale Blockgröße in Bytes
    size_t size_classes;        // Anzahl verschiedener Größenklassen
    size_t blocks_per_class;    // Anzahl der Blöcke pro Größenklasse
    bool thread_safe;           // Thread-Sicherheit aktivieren
    bool prefetch;              // Speicher vorallokieren

    // Standard-Konfiguration
    MemoryPoolConfig()
        : min_block_size(64),
          max_block_size(8192),
          size_classes(8),
          blocks_per_class(32),
          thread_safe(true),
          prefetch(true) {}
};

/**
 * MemoryBlock - Ein Speicherblock mit Header und Payload
 */
class MemoryBlock {
public:
    // Header für Speicherblöcke
    struct Header {
        size_t size;            // Größe der Nutzlast in Bytes
        size_t capacity;        // Kapazität des Blocks
        bool in_use;            // Block in Verwendung?
        uint32_t size_class;    // Größenklasse des Blocks
        
        Header() : size(0), capacity(0), in_use(false), size_class(0) {}
    };

    // Konstruktor für einen leeren Block
    MemoryBlock() : header_(), data_(nullptr) {}
    
    // Konstruktor mit vorallokiertem Speicher
    MemoryBlock(size_t capacity)
        : header_(), data_(nullptr) {
        header_.capacity = capacity;
        data_ = new uint8_t[capacity];
    }
    
    // Destruktor
    ~MemoryBlock() {
        if (data_) {
            delete[] data_;
        }
    }
    
    // Speicherblock zurücksetzen
    void reset() {
        header_.size = 0;
        header_.in_use = false;
    }
    
    // Daten zuweisen
    void assign(const uint8_t* data, size_t size) {
        assert(size <= header_.capacity);
        header_.size = size;
        header_.in_use = true;
        if (data && size > 0) {
            memcpy(data_, data, size);
        }
    }
    
    // Daten auf eine bestimmte Größe setzen
    void resize(size_t size) {
        assert(size <= header_.capacity);
        header_.size = size;
        header_.in_use = true;
    }
    
    // Getter/Setter
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return header_.size; }
    size_t capacity() const { return header_.capacity; }
    bool in_use() const { return header_.in_use; }
    uint32_t size_class() const { return header_.size_class; }
    void set_size_class(uint32_t size_class) { header_.size_class = size_class; }

private:
    Header header_;
    uint8_t* data_;
    
    // Verbiete Kopier- und Move-Operationen
    MemoryBlock(const MemoryBlock&) = delete;
    MemoryBlock& operator=(const MemoryBlock&) = delete;
    MemoryBlock(MemoryBlock&&) = delete;
    MemoryBlock& operator=(MemoryBlock&&) = delete;
};

/**
 * MemoryPool - Ein effizientes Speicherpool-System für häufig verwendete Puffergrößen
 * 
 * Dieses Speicherpoolsystem reduziert Fragmentierung und Allokationskosten durch
 * Vorallokation und Wiederverwendung von Speicherblöcken verschiedener Größenklassen.
 */
class MemoryPool {
public:
    // Singleton-Instanz
    static MemoryPool& instance() {
        static MemoryPool instance;
        return instance;
    }
    
    // Konstruktor mit Standard-Konfiguration
    MemoryPool()
        : config_(), size_to_class_(), class_to_size_(), free_blocks_(), 
          stats_allocs_(0), stats_releases_(0), stats_cache_hits_(0), 
          mutex_() {
        init_with_config(MemoryPoolConfig());
    }
    
    // Konstruktor mit benutzerdefinierter Konfiguration
    explicit MemoryPool(const MemoryPoolConfig& config)
        : config_(config), size_to_class_(), class_to_size_(), free_blocks_(), 
          stats_allocs_(0), stats_releases_(0), stats_cache_hits_(0), 
          mutex_() {
        init_with_config(config);
    }
    
    // Destruktor
    ~MemoryPool() {
        for (auto& queue : free_blocks_) {
            while (!queue.empty()) {
                auto block = queue.front();
                queue.pop();
                delete block;
            }
        }
    }
    
    // Speicherblock anfordern
    MemoryBlock* allocate(size_t size) {
        if (size > config_.max_block_size) {
            // Zu große Blöcke werden direkt allokiert
            auto block = new MemoryBlock(size);
            block->set_size_class(UINT32_MAX);  // Spezielle Klasse für große Blöcke
            block->resize(size);
            return block;
        }
        
        uint32_t size_class = get_size_class(size);
        size_t actual_size = class_to_size_[size_class];
        
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (config_.thread_safe) {
            lock.lock();
        }
        
        MemoryBlock* block = nullptr;
        
        // Versuche, einen freien Block zu finden
        if (!free_blocks_[size_class].empty()) {
            block = free_blocks_[size_class].front();
            free_blocks_[size_class].pop();
            stats_cache_hits_++;
        } else {
            // Allokiere einen neuen Block
            block = new MemoryBlock(actual_size);
            block->set_size_class(size_class);
        }
        
        block->resize(size);
        stats_allocs_++;
        
        return block;
    }
    
    // Speicherblock freigeben
    void release(MemoryBlock* block) {
        if (!block) return;
        
        uint32_t size_class = block->size_class();
        
        if (size_class == UINT32_MAX) {
            // Große Blöcke werden direkt freigegeben
            delete block;
            return;
        }
        
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (config_.thread_safe) {
            lock.lock();
        }
        
        // Block zurücksetzen und in den Pool geben
        block->reset();
        free_blocks_[size_class].push(block);
        stats_releases_++;
    }
    
    // Buffer-Wrapper mit automatischer Poolzuweisung
    template<typename T = uint8_t>
    class PoolBuffer {
    public:
        // Konstruktor für leeren Puffer
        PoolBuffer() : block_(nullptr), memory_pool_(nullptr) {}
        
        // Konstruktor mit Größe
        explicit PoolBuffer(size_t size, MemoryPool* pool = &MemoryPool::instance())
            : block_(nullptr), memory_pool_(pool) {
            if (size > 0) {
                block_ = memory_pool_->allocate(size * sizeof(T));
            }
        }
        
        // Destruktor
        ~PoolBuffer() {
            if (block_ && memory_pool_) {
                memory_pool_->release(block_);
            }
        }
        
        // Prüfen, ob der Puffer allokiert ist
        bool valid() const { return block_ != nullptr; }
        
        // Größe ändern
        void resize(size_t size) {
            if (!block_) {
                if (memory_pool_) {
                    block_ = memory_pool_->allocate(size * sizeof(T));
                }
                return;
            }
            
            if (size * sizeof(T) <= block_->capacity()) {
                block_->resize(size * sizeof(T));
            } else {
                // Neuen, größeren Block allokieren
                if (memory_pool_) {
                    MemoryBlock* new_block = memory_pool_->allocate(size * sizeof(T));
                    if (block_->size() > 0) {
                        // Daten kopieren
                        memcpy(new_block->data(), block_->data(), block_->size());
                    }
                    memory_pool_->release(block_);
                    block_ = new_block;
                }
            }
        }
        
        // Daten zuweisen
        void assign(const T* data, size_t size) {
            resize(size);
            if (block_ && data) {
                memcpy(block_->data(), data, size * sizeof(T));
            }
        }
        
        // Zugriff auf die Daten
        T* data() { return block_ ? reinterpret_cast<T*>(block_->data()) : nullptr; }
        const T* data() const { return block_ ? reinterpret_cast<const T*>(block_->data()) : nullptr; }
        
        // Größe
        size_t size() const { return block_ ? block_->size() / sizeof(T) : 0; }
        size_t capacity() const { return block_ ? block_->capacity() / sizeof(T) : 0; }
        
        // Operator[] für Datenzugriff
        T& operator[](size_t index) {
            assert(block_ && index < size());
            return reinterpret_cast<T*>(block_->data())[index];
        }
        
        const T& operator[](size_t index) const {
            assert(block_ && index < size());
            return reinterpret_cast<const T*>(block_->data())[index];
        }
        
    private:
        MemoryBlock* block_;
        MemoryPool* memory_pool_;
        
        // Verbiete Kopier- und Move-Operationen
        PoolBuffer(const PoolBuffer&) = delete;
        PoolBuffer& operator=(const PoolBuffer&) = delete;
    };
    
    // Statistik-Struktur
    struct PoolStatistics {
        size_t allocations;      // Gesamtzahl der Allokationen
        size_t releases;         // Gesamtzahl der Freigaben
        size_t cache_hits;       // Gesamtzahl der Cache-Treffer
        size_t active_allocations; // Derzeit aktive Allokationen
        size_t total_free_blocks; // Gesamtzahl freier Blöcke
        std::vector<size_t> free_blocks_per_class; // Freie Blöcke pro Größenklasse
        std::vector<size_t> size_per_class;        // Größe pro Größenklasse
    };
    
    // Statistik abrufen
    PoolStatistics get_statistics() const {
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (config_.thread_safe) {
            lock.lock();
        }
        
        PoolStatistics stats;
        stats.allocations = stats_allocs_;
        stats.releases = stats_releases_;
        stats.cache_hits = stats_cache_hits_;
        stats.active_allocations = stats_allocs_ - stats_releases_;
        stats.total_free_blocks = 0;
        stats.free_blocks_per_class.resize(config_.size_classes, 0);
        stats.size_per_class.resize(config_.size_classes, 0);
        
        for (size_t i = 0; i < config_.size_classes; i++) {
            stats.free_blocks_per_class[i] = free_blocks_[i].size();
            stats.size_per_class[i] = class_to_size_[i];
            stats.total_free_blocks += free_blocks_[i].size();
        }
        
        return stats;
    }
    
    // Rekonfigurieren des Pools
    void reconfigure(const MemoryPoolConfig& config) {
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (config_.thread_safe) {
            lock.lock();
        }
        
        // Alte Pools leeren
        for (auto& queue : free_blocks_) {
            while (!queue.empty()) {
                auto block = queue.front();
                queue.pop();
                delete block;
            }
        }
        
        free_blocks_.clear();
        size_to_class_.clear();
        class_to_size_.clear();
        
        // Neue Konfiguration übernehmen und initialisieren
        config_ = config;
        init_with_config(config);
    }

private:
    // Initialisierung mit Konfiguration
    void init_with_config(const MemoryPoolConfig& config) {
        // Berechne die Größenklassen
        size_to_class_.resize(config.max_block_size + 1, 0);
        class_to_size_.resize(config.size_classes, 0);
        free_blocks_.resize(config.size_classes);
        
        for (size_t i = 0; i < config.size_classes; i++) {
            // Berechne die Größe für diese Klasse (exponentiell wachsend)
            double factor = std::pow(
                static_cast<double>(config.max_block_size) / config.min_block_size,
                static_cast<double>(i) / (config.size_classes - 1)
            );
            size_t size = static_cast<size_t>(config.min_block_size * factor);
            size = (size + 7) & ~7;  // Auf 8-Byte-Grenzen aufrunden
            
            class_to_size_[i] = size;
            
            // Vorallokation durchführen, wenn aktiviert
            if (config.prefetch) {
                for (size_t j = 0; j < config.blocks_per_class; j++) {
                    auto block = new MemoryBlock(size);
                    block->set_size_class(i);
                    free_blocks_[i].push(block);
                }
            }
        }
        
        // Speichergröße zu Größenklasse abbilden
        for (size_t size = 1; size <= config.max_block_size; size++) {
            uint32_t best_class = 0;
            for (size_t i = 0; i < config.size_classes; i++) {
                if (class_to_size_[i] >= size) {
                    best_class = i;
                    break;
                }
            }
            size_to_class_[size] = best_class;
        }
    }
    
    // Bestimme die Größenklasse für eine gegebene Größe
    uint32_t get_size_class(size_t size) const {
        if (size <= config_.max_block_size) {
            return size_to_class_[size];
        }
        return UINT32_MAX;
    }
    
    // Konfiguration
    MemoryPoolConfig config_;
    
    // Abbildung von Größe zu Größenklasse
    std::vector<uint32_t> size_to_class_;
    
    // Abbildung von Größenklasse zu tatsächlicher Blockgröße
    std::vector<size_t> class_to_size_;
    
    // Freie Blöcke pro Größenklasse
    std::vector<std::queue<MemoryBlock*>> free_blocks_;
    
    // Statistiken
    size_t stats_allocs_;
    size_t stats_releases_;
    size_t stats_cache_hits_;
    
    // Mutex für Thread-Sicherheit
    mutable std::mutex mutex_;
};

} // namespace quicsand
