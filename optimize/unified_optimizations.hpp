#ifndef UNIFIED_OPTIMIZATIONS_HPP
#define UNIFIED_OPTIMIZATIONS_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <unordered_map>
#include <chrono>
#include <future>
#include <cstring>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <algorithm>
#include <random>
#include <string>
#include <queue>
#include <deque>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "../core/error_handling.hpp"

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#include <immintrin.h>
#include <wmmintrin.h>
#endif

namespace quicfuscate {
class QuicStream;
}

namespace quicfuscate::optimize {

// ============================================================================
// UNIFIED CPU FEATURE DETECTION
// ============================================================================

enum class CpuFeature : uint64_t {
    NONE = 0ULL,
    // x86/x64 Features
    SSE = 1ULL << 0, SSE2 = 1ULL << 1, SSE3 = 1ULL << 2,
    AVX = 1ULL << 6, AVX2 = 1ULL << 7, AVX512F = 1ULL << 8,
    AES_NI = 1ULL << 14, VAES = 1ULL << 15,
    // ARM Features  
    NEON = 1ULL << 22, ASIMD = 1ULL << 23, SVE = 1ULL << 24,
    CRYPTO = 1ULL << 27, CRC = 1ULL << 28
};

// ============================================================================
// UNIFIED SIMD POLICY SYSTEM
// ============================================================================

template<typename VectorType>
struct UnifiedSIMDPolicy {
    using vector_type = VectorType;
    static vector_type load(const void* ptr);
    static void store(void* ptr, vector_type v);
    static vector_type bitwise_xor(vector_type a, vector_type b);
};

class UnifiedFeatureDetector {
public:
    static uint64_t detect_cpu_features();
    static bool has_feature(CpuFeature feature);
    static std::string get_cpu_name();
};

class UnifiedSIMDDispatcher {
public:
    template<typename Func>
    static auto dispatch(Func&& func) -> decltype(func(std::declval<UnifiedSIMDPolicy<__m128i>>()));
    
    template<typename Func>
    static auto dispatch_or_fallback(Func&& simd_func, Func&& fallback_func) 
        -> decltype(simd_func(std::declval<UnifiedSIMDPolicy<__m128i>>()));
};

// ============================================================================
// UNIFIED MEMORY OPTIMIZATIONS
// ============================================================================

// ============================================================================
// ENHANCED MEMORY POOL SYSTEM (from core/memory_pool.hpp)
// ============================================================================

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
    Result<void> assign(const uint8_t* data, size_t size) {
        if (size > header_.capacity) {
            auto err = MAKE_ERROR(ErrorCategory::RUNTIME, ErrorCode::INVALID_ARGUMENT,
                                  "MemoryBlock assign exceeds capacity");
            report_error(err);
            return err;
        }
        header_.size = size;
        header_.in_use = true;
        if (data && size > 0) {
            memcpy(data_, data, size);
        }
        return success();
    }
    
    // Daten auf eine bestimmte Größe setzen
    Result<void> resize(size_t size) {
        if (size > header_.capacity) {
            auto err = MAKE_ERROR(ErrorCategory::RUNTIME, ErrorCode::INVALID_ARGUMENT,
                                  "MemoryBlock resize exceeds capacity");
            report_error(err);
            return err;
        }
        header_.size = size;
        header_.in_use = true;
        return success();
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
    
    // Speicherblock allokieren
    MemoryBlock* allocate(size_t size) {
        if (size == 0 || size > config_.max_block_size) {
            return nullptr;
        }
        
        uint32_t size_class = get_size_class(size);
        size_t actual_size = class_to_size_[size_class];
        
        if (config_.thread_safe) {
            std::lock_guard<std::mutex> lock(mutex_);
            return allocate_internal(size_class, actual_size);
        } else {
            return allocate_internal(size_class, actual_size);
        }
    }
    
    // Speicherblock freigeben
    void deallocate(MemoryBlock* block) {
        if (!block) return;
        
        block->reset();
        
        if (config_.thread_safe) {
            std::lock_guard<std::mutex> lock(mutex_);
            deallocate_internal(block);
        } else {
            deallocate_internal(block);
        }
    }
    
    // Statistiken abrufen
    struct MemoryStats {
        size_t total_allocations;
        size_t current_allocations;
        size_t peak_memory_usage;
        size_t fragmentation_percent;
        size_t cache_hit_rate;
        size_t free_blocks_count;
    };
    
    MemoryStats get_stats() const {
        if (config_.thread_safe) {
            std::lock_guard<std::mutex> lock(mutex_);
            return get_stats_internal();
        } else {
            return get_stats_internal();
        }
    }
    
private:
    MemoryPoolConfig config_;
    std::unordered_map<size_t, uint32_t> size_to_class_;
    std::vector<size_t> class_to_size_;
    std::vector<std::queue<MemoryBlock*>> free_blocks_;
    
    // Statistiken
    std::atomic<size_t> stats_allocs_;
    std::atomic<size_t> stats_releases_;
    std::atomic<size_t> stats_cache_hits_;
    
    mutable std::mutex mutex_;
    
    void init_with_config(const MemoryPoolConfig& config) {
        config_ = config;
        
        // Größenklassen berechnen
        size_t current_size = config_.min_block_size;
        size_t step = (config_.max_block_size - config_.min_block_size) / config_.size_classes;
        
        for (size_t i = 0; i < config_.size_classes; ++i) {
            class_to_size_.push_back(current_size);
            size_to_class_[current_size] = i;
            current_size += step;
        }
        
        // Freie Block-Queues initialisieren
        free_blocks_.resize(config_.size_classes);
        
        // Vorallokation falls aktiviert
        if (config_.prefetch) {
            prefetch_blocks();
        }
    }
    
    uint32_t get_size_class(size_t size) const {
        // Finde die kleinste Größenklasse, die >= size ist
        for (size_t i = 0; i < class_to_size_.size(); ++i) {
            if (class_to_size_[i] >= size) {
                return i;
            }
        }
        return class_to_size_.size() - 1; // Größte Klasse
    }
    
    MemoryBlock* allocate_internal(uint32_t size_class, size_t actual_size) {
        stats_allocs_++;
        
        // Versuche einen Block aus dem Pool zu holen
        if (!free_blocks_[size_class].empty()) {
            auto block = free_blocks_[size_class].front();
            free_blocks_[size_class].pop();
            stats_cache_hits_++;
            return block;
        }
        
        // Erstelle einen neuen Block
        auto block = new MemoryBlock(actual_size);
        block->set_size_class(size_class);
        return block;
    }
    
    void deallocate_internal(MemoryBlock* block) {
        stats_releases_++;
        uint32_t size_class = block->size_class();
        
        // Füge den Block zurück in den Pool
        if (size_class < free_blocks_.size()) {
            free_blocks_[size_class].push(block);
        } else {
            delete block; // Ungültige Größenklasse
        }
    }
    
    MemoryStats get_stats_internal() const {
        MemoryStats stats;
        stats.total_allocations = stats_allocs_.load();
        stats.current_allocations = stats_allocs_.load() - stats_releases_.load();
        stats.cache_hit_rate = stats_allocs_.load() > 0 ? 
            (stats_cache_hits_.load() * 100) / stats_allocs_.load() : 0;
        
        size_t free_count = 0;
        for (const auto& queue : free_blocks_) {
            free_count += queue.size();
        }
        stats.free_blocks_count = free_count;
        
        // Vereinfachte Fragmentierungsberechnung
        stats.fragmentation_percent = free_count > 0 ? 
            (free_count * 100) / (free_count + stats.current_allocations) : 0;
        
        return stats;
    }
    
    void prefetch_blocks() {
        for (size_t i = 0; i < config_.size_classes; ++i) {
            for (size_t j = 0; j < config_.blocks_per_class; ++j) {
                auto block = new MemoryBlock(class_to_size_[i]);
                block->set_size_class(i);
                free_blocks_[i].push(block);
            }
        }
    }
};

class UnifiedMemoryPool {
public:
    UnifiedMemoryPool(size_t pool_size, size_t block_size);
    ~UnifiedMemoryPool();
    
    void* allocate(size_t size);
    void deallocate(void* ptr);
    
    size_t get_free_space() const;
    size_t get_total_space() const;
    
    struct MemoryStats {
        size_t total_allocations;
        size_t current_allocations;
        size_t peak_memory_usage;
        size_t fragmentation_percent;
    };
    
    MemoryStats get_stats() const;
    
private:
    std::vector<uint8_t> pool_;
    size_t block_size_;
    // Implementation details
};

// ============================================================================
// ENHANCED ZERO-COPY SYSTEM (from core/zero_copy.hpp)
// ============================================================================

/**
 * ZeroCopyBuffer implementiert einen Zero-Copy-Puffer für optimierte Datenübertragungen.
 * Anstatt Daten mehrfach zu kopieren, werden sie direkt aus Quellpuffern in die Socket-Operationen übertragen.
 */
class ZeroCopyBuffer {
public:
    /**
     * Konstruktor
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen (Scatter-Gather-Array-Größe)
     */
    explicit ZeroCopyBuffer(size_t max_iovecs = 16);
    
    /**
     * Destruktor
     */
    ~ZeroCopyBuffer();
    
    /**
     * Fügt einen Datenblock zum Zero-Copy-Puffer hinzu
     * @param data Zeiger auf die Daten
     * @param size Größe des Datenblocks in Bytes
     * @param own_data Falls true, wird eine Kopie der Daten erstellt und verwaltet
     * @return true wenn erfolgreich, false bei Fehler oder wenn max_iovecs erreicht ist
     */
    bool add_buffer(const void* data, size_t size, bool own_data = false);
    
    /**
     * Fügt einen Vektor zum Zero-Copy-Puffer hinzu
     * @param data Vektor mit den Daten
     * @return true wenn erfolgreich, false bei Fehler
     */
    bool add_buffer(const std::vector<uint8_t>& data);
    
    /**
     * Führt eine Zero-Copy-Sendeoperation aus
     * @param fd Socket-Deskriptor
     * @param flags Flags für sendmsg
     * @return Anzahl gesendeter Bytes oder -1 bei Fehler
     */
    ssize_t send(int fd, int flags = 0);
    
    /**
     * Führt eine Zero-Copy-Sendeoperation an eine Zieladresse aus
     * @param fd Socket-Deskriptor
     * @param dest Zieladresse
     * @param flags Flags für sendmsg
     * @return Anzahl gesendeter Bytes oder -1 bei Fehler
     */
    ssize_t sendto(int fd, const struct sockaddr* dest, socklen_t dest_len, int flags = 0);
    
    /**
     * Löscht alle Puffer und setzt den Zustand zurück
     */
    void clear();
    
    /**
     * Gibt die Gesamtgröße aller Puffer zurück
     * @return Summe der Größen aller Puffer in Bytes
     */
    size_t total_size() const;
    
    /**
     * Gibt die Anzahl der aktuell verwendeten iovec-Strukturen zurück
     * @return Anzahl der iovec-Strukturen
     */
    size_t iovec_count() const;
    
    /**
     * Gibt das iovec-Array für direkte Verwendung zurück
     * @return Zeiger auf das iovec-Array
     */
    const struct iovec* iovecs() const;
    
private:
    struct Buffer {
        void* data;
        size_t size;
        bool owned;
        
        Buffer(void* d, size_t s, bool o) : data(d), size(s), owned(o) {}
        ~Buffer() {
            if (owned && data) {
                free(data);
            }
        }
    };
    
    std::vector<struct iovec> iovecs_;
    std::vector<std::unique_ptr<Buffer>> buffers_;
    size_t max_iovecs_;
    size_t total_bytes_;
};

/**
 * ZeroCopyReceiver implementiert eine Zero-Copy-Empfangsfunktionalität.
 * Erlaubt das Lesen von Daten direkt in mehrere vorallokierte Puffer ohne zusätzliche Kopieroperationen.
 */
class ZeroCopyReceiver {
public:
    /**
     * Konstruktor
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen (Scatter-Gather-Array-Größe)
     */
    explicit ZeroCopyReceiver(size_t max_iovecs = 16);
    
    /**
     * Destruktor
     */
    ~ZeroCopyReceiver();
    
    /**
     * Fügt einen Empfangspuffer hinzu
     * @param buffer Zeiger auf den Puffer
     * @param size Größe des Puffers in Bytes
     * @return true wenn erfolgreich, false bei Fehler
     */
    bool add_buffer(void* buffer, size_t size);
    
    /**
     * Führt eine Zero-Copy-Empfangsoperation aus
     * @param fd Socket-Deskriptor
     * @param flags Flags für recvmsg
     * @return Anzahl empfangener Bytes oder -1 bei Fehler
     */
    ssize_t receive(int fd, int flags = 0);
    
    /**
     * Führt eine Zero-Copy-Empfangsoperation aus und gibt die Quelladresse zurück
     * @param fd Socket-Deskriptor
     * @param source Quelladresse (Ausgabeparameter)
     * @param source_len Länge der Quelladresse (Ein- und Ausgabeparameter)
     * @param flags Flags für recvmsg
     * @return Anzahl empfangener Bytes oder -1 bei Fehler
     */
    ssize_t recvfrom(int fd, struct sockaddr* source, socklen_t* source_len, int flags = 0);
    
    /**
     * Löscht alle Puffer und setzt den Zustand zurück
     */
    void clear();
    
    /**
     * Gibt die Gesamtgröße aller Puffer zurück
     * @return Summe der Größen aller Puffer in Bytes
     */
    size_t total_size() const;
    
    /**
     * Gibt die Anzahl der aktuell verwendeten iovec-Strukturen zurück
     * @return Anzahl der iovec-Strukturen
     */
    size_t iovec_count() const;
    
    /**
     * Gibt das iovec-Array für direkte Verwendung zurück
     * @return Zeiger auf das iovec-Array
     */
    const struct iovec* iovecs() const;
    
    /**
     * Gibt die empfangenen Daten als zusammenhängenden Puffer zurück
     * @param output Ausgabepuffer
     * @param max_size Maximale Größe des Ausgabepuffers
     * @return Anzahl der kopierten Bytes
     */
    size_t get_received_data(void* output, size_t max_size) const;
    
private:
    std::vector<struct iovec> iovecs_;
    std::vector<void*> buffers_;
    size_t max_iovecs_;
    size_t total_bytes_;
    size_t received_bytes_;
};

/**
 * ZeroCopyManager verwaltet Zero-Copy-Operationen für eine Verbindung
 */
class ZeroCopyManager {
public:
    ZeroCopyManager();
    ~ZeroCopyManager();
    
    // Sender-Funktionen
    bool queue_send_data(const void* data, size_t size, bool copy_data = false);
    ssize_t flush_send_queue(int fd);
    
    // Receiver-Funktionen
    bool prepare_receive_buffers(size_t buffer_count, size_t buffer_size);
    ssize_t receive_data(int fd);
    size_t get_received_data(void* output, size_t max_size);
    
    // Statistiken
    struct ZeroCopyStats {
        size_t total_bytes_sent;
        size_t total_bytes_received;
        size_t send_operations;
        size_t receive_operations;
        size_t zero_copy_efficiency; // Prozentsatz der Zero-Copy-Operationen
    };
    
    ZeroCopyStats get_stats() const;
    void reset_stats();
    
private:
    std::unique_ptr<ZeroCopyBuffer> send_buffer_;
    std::unique_ptr<ZeroCopyReceiver> receive_buffer_;
    
    // Statistiken
    ZeroCopyStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Interne Puffer für Empfang
    std::vector<std::vector<uint8_t>> receive_buffers_;
};

class UnifiedZeroCopyBuffer {
public:
    UnifiedZeroCopyBuffer(size_t capacity);
    ~UnifiedZeroCopyBuffer();
    
    bool write(const void* data, size_t size);
    ssize_t send_to_socket(int socket_fd);
    
    size_t get_available_space() const;
    size_t get_used_space() const;
    
private:
    std::vector<iovec> iovecs_;
    size_t total_size_;
    // Implementation details
};

// ============================================================================
// UNIFIED CACHE OPTIMIZATIONS
// ============================================================================

template<typename Key, typename Value>
class UnifiedLRUCache {
public:
    explicit UnifiedLRUCache(size_t capacity);
    
    bool put(const Key& key, const Value& value);
    bool get(const Key& key, Value& value);
    bool contains(const Key& key) const;
    void remove(const Key& key);
    
    size_t size() const;
    size_t capacity() const;
    void clear();
    
private:
    // Implementation details
};

class UnifiedPrefetcher {
public:
    UnifiedPrefetcher(size_t window_size);
    
    void record_access(uintptr_t address);
    void prefetch_next();
    
    void enable();
    void disable();
    bool is_enabled() const;
    
private:
    // Implementation details
};

// ============================================================================
// UNIFIED THREADING OPTIMIZATIONS
// ============================================================================

class UnifiedThreadPool {
public:
    explicit UnifiedThreadPool(size_t num_threads);
    ~UnifiedThreadPool();
    
    template<typename Func, typename... Args>
    auto enqueue(Func&& func, Args&&... args) -> std::future<decltype(func(args...))>;
    
    void wait_all();
    size_t get_pending_tasks() const;
    size_t get_thread_count() const;
    
private:
    // Implementation details
};

class UnifiedWorkStealer {
public:
    UnifiedWorkStealer(size_t num_threads);
    
    template<typename Task>
    void add_task(Task&& task);
    
    void start();
    void stop();
    
    size_t get_processed_tasks() const;
    double get_load_balance_factor() const;
    
private:
    // Implementation details
};

// ============================================================================
// UNIFIED QPACK OPTIMIZATIONS
// ============================================================================

class UnifiedQPackEncoder {
public:
    UnifiedQPackEncoder();
    
    std::vector<uint8_t> encode_headers(const std::vector<std::pair<std::string, std::string>>& headers);
    void update_dynamic_table(const std::pair<std::string, std::string>& entry);
    
    size_t get_compression_ratio() const;
    
private:
    // Implementation details
};

class UnifiedQPackDecoder {
public:
    UnifiedQPackDecoder();
    
    std::vector<std::pair<std::string, std::string>> decode_headers(const std::vector<uint8_t>& encoded_data);
    bool process_table_updates(const std::vector<uint8_t>& updates);
    
    size_t get_success_rate() const;
    
private:
    // Implementation details
};

// ============================================================================
// UNIFIED ZERO-RTT OPTIMIZATIONS
// ============================================================================

// ============================================================================
// UNIFIED STREAM OPTIMIZATIONS
// ============================================================================

/**
 * @brief Stream optimization configuration
 */
struct StreamOptimizationConfig {
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_window_size;
    uint32_t stream_buffer_size;
    bool enable_flow_control;
    bool enable_prioritization;
    bool enable_multiplexing;
    double congestion_threshold;
};

/**
 * @brief QUIC stream optimizer
 */
class QuicStreamOptimizer {
public:
    QuicStreamOptimizer();
    ~QuicStreamOptimizer() = default;
    
    /**
     * @brief Initialize with optimization configuration
     */
    bool initialize(const StreamOptimizationConfig& config);
    
    /**
     * @brief Optimize stream for transmission
     */
    bool optimize_stream(std::shared_ptr<QuicStream> stream);
    
    /**
     * @brief Set stream priority
     */
    bool set_stream_priority(uint64_t stream_id, uint8_t priority);
    
    /**
     * @brief Update flow control window
     */
    bool update_flow_control_window(uint64_t stream_id, uint32_t window_size);
    
    /**
     * @brief Check if stream can send data
     */
    bool can_send_data(uint64_t stream_id, uint32_t data_size) const;
    
    /**
     * @brief Get optimal chunk size for stream
     */
    uint32_t get_optimal_chunk_size(uint64_t stream_id) const;
    
    /**
     * @brief Schedule streams for transmission
     */
    std::vector<uint64_t> schedule_streams();
    
private:
    StreamOptimizationConfig config_;
    std::map<uint64_t, uint8_t> stream_priorities_;
    std::map<uint64_t, uint32_t> stream_windows_;
    std::map<uint64_t, uint32_t> stream_buffers_;
    
    std::mutex streams_mutex_;
    
    uint32_t calculate_optimal_window_size(uint64_t stream_id) const;
    bool is_stream_congested(uint64_t stream_id) const;
};

/**
 * ZeroRttConfig - Konfigurationsoptionen für Zero-RTT-Verbindungen
 */
struct ZeroRttConfig {
    bool enabled = true;                      // Zero-RTT aktiviert
    bool require_binding = true;              // Token-Binding erforderlich
    uint32_t max_early_data = 16384;          // Maximale Datenmenge für 0-RTT (16 KB)
    uint32_t max_tokens_per_host = 4;         // Maximale Anzahl Tokens pro Host
    uint32_t max_token_lifetime_s = 7200;     // Max. Lebensdauer eines Tokens (2 Stunden)
    bool reject_if_no_token = false;          // Verbindung ablehnen, wenn kein Token verfügbar
    bool update_keys_after_handshake = true;  // Schlüssel nach Handshake aktualisieren
};

struct UnifiedZeroRTTToken {
    std::string hostname;
    std::vector<uint8_t> token_data;
    std::chrono::system_clock::time_point timestamp;
    uint32_t lifetime_s;
    
    bool is_valid() const {
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count();
        return age < lifetime_s;
    }
};

class UnifiedZeroRTTManager {
public:
    static UnifiedZeroRTTManager& getInstance();
    
    UnifiedZeroRTTToken generateToken(const std::string& hostname, uint32_t lifetime_s = 86400);
    bool validateToken(const UnifiedZeroRTTToken& token, const std::string& hostname);
    
    void storeToken(const std::string& hostname, const UnifiedZeroRTTToken& token);
    UnifiedZeroRTTToken getToken(const std::string& hostname);
    
    void cleanupExpiredTokens();
    
private:
    UnifiedZeroRTTManager() = default;
    
    mutable std::mutex tokens_mutex_;
    std::unordered_map<std::string, UnifiedZeroRTTToken> stored_tokens_;
    std::vector<uint8_t> master_key_;
    
    std::vector<uint8_t> deriveTokenKey(const std::string& hostname);
    std::vector<uint8_t> encryptTokenData(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::vector<uint8_t> decryptTokenData(const std::vector<uint8_t>& encrypted_data, const std::vector<uint8_t>& key);
};

// ============================================================================
// UNIFIED OPTIMIZATION MANAGER
// ============================================================================

struct UnifiedOptimizationConfig {
    // Memory settings
    size_t memory_pool_size = 16 * 1024 * 1024;
    size_t memory_block_size = 4096;
    bool use_zero_copy = true;
    
    // Threading settings
    size_t thread_pool_size = 4;
    bool use_work_stealing = true;
    
    // SIMD settings
    bool enable_simd = true;
    bool auto_detect_features = true;
    uint64_t forced_cpu_features = 0;
    
    // Cache settings
    size_t lru_cache_size = 1024;
    bool enable_prefetching = true;
    
    // QPACK settings
    size_t qpack_dynamic_table_size = 4096;
    bool qpack_use_huffman = true;
    
    // Zero-RTT settings
    bool enable_zero_rtt = true;
    uint32_t zero_rtt_token_lifetime = 86400; // 24 hours
    
    // Network settings
    bool enable_bbr_v2 = true;
    bool enable_burst_buffer = true;
};

struct PerformanceMetrics {
    // Memory metrics
    size_t memory_allocations = 0;
    size_t peak_memory_usage = 0;
    double fragmentation_percent = 0.0;
    
    // Threading metrics
    size_t tasks_processed = 0;
    double thread_efficiency = 0.0;
    double load_balance_factor = 0.0;
    
    // SIMD metrics
    size_t simd_operations = 0;
    double simd_speedup = 0.0;
    
    // Cache metrics
    double cache_hit_rate = 0.0;
    double prefetch_accuracy = 0.0;
    
    // QPACK metrics
    double compression_ratio = 0.0;
    size_t headers_processed = 0;
    
    // Zero-RTT metrics
    size_t zero_rtt_connections = 0;
    double zero_rtt_success_rate = 0.0;
    
    // Network metrics
    double bandwidth_utilization = 0.0;
    double packet_loss_rate = 0.0;
    double average_rtt_ms = 0.0;
};

class UnifiedOptimizationManager {
public:
    static UnifiedOptimizationManager& getInstance();
    
    void configure(const UnifiedOptimizationConfig& config);
    UnifiedOptimizationConfig get_config() const;
    
    UnifiedMemoryPool& get_memory_pool();
    UnifiedThreadPool& get_thread_pool();
    UnifiedZeroRTTManager& get_zero_rtt_manager();
    
    template<typename Key, typename Value>
    UnifiedLRUCache<Key, Value>& get_lru_cache();
    
    PerformanceMetrics get_performance_metrics() const;
    
    // Unified network optimizations
    struct NetworkOptimizations {
        // BBRv2 Congestion Control
        void apply_bbr_v2(int socket_fd);
        
        // Burst Buffer Management
        class BurstBuffer {
        public:
            explicit BurstBuffer(size_t capacity = 64 * 1024);
            bool add_packet(const void* data, size_t size);
            ssize_t flush(int socket_fd);
        private:
            std::vector<uint8_t> buffer_;
            size_t used_size_ = 0;
        };
        
        // Zero-RTT Connection Setup
        bool setup_zero_rtt(const std::string& hostname);
        
        // eBPF/XDP Zero-Copy
        bool enable_ebpf_zero_copy(int socket_fd);
    };
    
    NetworkOptimizations& get_network_optimizations();
    
private:
    UnifiedOptimizationConfig config_;
    PerformanceMetrics metrics_;
    std::unique_ptr<NetworkOptimizations> network_opts_;
};

// ============================================================================
// CONVENIENCE ALIASES FOR BACKWARD COMPATIBILITY
// ============================================================================

namespace simd {
    using UnifiedSIMDDispatcher = ::quicfuscate::optimize::UnifiedSIMDDispatcher;
    using UnifiedFeatureDetector = ::quicfuscate::optimize::UnifiedFeatureDetector;
    using CpuFeature = ::quicfuscate::optimize::CpuFeature;
    
    // Backward compatibility wrapper for existing crypto code
    class FeatureDetector {
    public:
        static FeatureDetector& instance() {
            static FeatureDetector instance_;
            return instance_;
        }
        
        bool has_feature(CpuFeature feature) const {
            return UnifiedFeatureDetector::has_feature(feature);
        }
        
    private:
        FeatureDetector() = default;
    };
}

namespace memory {
    struct MemoryPoolConfig {
        size_t pool_size = 1024 * 1024;
        size_t block_size = 4096;
        bool numa_aware = true;
    };
    
    using UnifiedMemoryPool = ::quicfuscate::optimize::UnifiedMemoryPool;
    using UnifiedZeroCopyBuffer = ::quicfuscate::optimize::UnifiedZeroCopyBuffer;
}

namespace cache {
    template<typename K, typename V>
    using UnifiedLRUCache = ::quicfuscate::optimize::UnifiedLRUCache<K, V>;
    
    using UnifiedPrefetcher = ::quicfuscate::optimize::UnifiedPrefetcher;
}

namespace threading {
    using UnifiedThreadPool = ::quicfuscate::optimize::UnifiedThreadPool;
    using UnifiedWorkStealer = ::quicfuscate::optimize::UnifiedWorkStealer;
}

namespace qpack {
    using UnifiedQPackEncoder = ::quicfuscate::optimize::UnifiedQPackEncoder;
    using UnifiedQPackDecoder = ::quicfuscate::optimize::UnifiedQPackDecoder;
}

// ============================================================================
// NETWORK OPTIMIZATIONS
// ============================================================================

// BBRv2 CONGESTION CONTROL
struct BBRParams {
    double startup_gain = 2.885;
    double drain_gain = 0.75;
    double probe_rtt_gain = 0.75;
    double cwnd_gain = 2.0;
    double startup_cwnd_gain = 2.885;
    
    uint64_t probe_rtt_interval_ms = 10000;
    uint64_t probe_rtt_duration_ms = 200;
    uint64_t min_rtt_window_ms = 10000;
    uint64_t bw_window_length = 10;
    
    double bw_probe_up_gain = 1.25;
    double bw_probe_down_gain = 0.75;
    uint64_t bw_probe_max_rounds = 63;
    
    double inflight_headroom = 0.15;
    uint64_t min_pipe_cwnd = 4 * 1024;
};

class UnifiedBBRv2 {
public:
    enum class State {
        STARTUP,
        DRAIN,
        PROBE_BW,
        PROBE_RTT
    };
    
    static constexpr double kPacingGainCycle[8] = {
        1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
    };
    
    explicit UnifiedBBRv2(const BBRParams& params = BBRParams());
    ~UnifiedBBRv2();
    
    void update(uint64_t rtt_us, double bandwidth_bps, uint64_t bytes_in_flight,
                uint64_t bytes_acked, uint64_t bytes_lost, uint64_t timestamp_us);
    
    double get_pacing_rate() const;
    uint64_t get_congestion_window() const;
    State get_state() const;
    
    struct BBRMetrics {
        double bottleneck_bandwidth = 0.0;
        uint64_t min_rtt_us = 0;
        State current_state = State::STARTUP;
        double pacing_gain = 1.0;
        double cwnd_gain = 1.0;
        uint64_t bytes_in_flight = 0;
    };
    
    BBRMetrics get_metrics() const;
    
private:
    BBRParams params_;
    State state_;
    double bottleneck_bandwidth_;
    uint64_t min_rtt_us_;
    std::deque<double> bandwidth_samples_;
    std::deque<uint64_t> rtt_samples_;
    mutable std::mutex mutex_;
    
    void update_bandwidth_filter(double bandwidth_bps, uint64_t timestamp_us);
    void update_rtt_filter(uint64_t rtt_us, uint64_t timestamp_us);
    void handle_startup_mode(double bandwidth_bps, uint64_t bytes_in_flight, uint64_t timestamp_us);
    void handle_drain_mode(uint64_t bytes_in_flight, uint64_t timestamp_us);
    void handle_probe_bw_mode(uint64_t timestamp_us);
    void handle_probe_rtt_mode(uint64_t bytes_in_flight, uint64_t timestamp_us);
};

// BURST BUFFER MANAGEMENT
enum class BurstFrameType {
    HTTP3_CHUNKED,
    WEBSOCKET,
    MEDIA_STREAMING,
    INTERACTIVE,
    RANDOMIZED
};

struct BurstConfig {
    uint32_t min_burst_interval_ms = 50;
    uint32_t max_burst_interval_ms = 200;
    
    size_t min_burst_size = 512;
    size_t max_burst_size = 4096;
    size_t optimal_burst_size = 1400;
    
    BurstFrameType frame_type = BurstFrameType::HTTP3_CHUNKED;
    bool adaptive_timing = true;
    bool adaptive_sizing = true;
    
    size_t max_buffer_size = 1024 * 1024;
    double target_latency_ms = 100.0;
    
    bool mimic_realistic_patterns = true;
    double jitter_factor = 0.1;
};

struct BurstMetrics {
    double observed_latency_ms = 0.0;
    double packet_loss_rate = 0.0;
    double bandwidth_estimate = 0.0;
    
    size_t total_bursts_sent = 0;
    size_t total_bytes_sent = 0;
    size_t buffer_high_watermark = 0;
    
    std::chrono::system_clock::time_point last_burst_time;
    double average_burst_interval_ms = 100.0;
    double adaptation_score = 1.0;
};

class UnifiedBurstBuffer {
public:
    UnifiedBurstBuffer();
    explicit UnifiedBurstBuffer(const BurstConfig& config);
    ~UnifiedBurstBuffer();
    
    bool add_data(const uint8_t* data, size_t size);
    void set_config(const BurstConfig& config);
    BurstConfig get_config() const;
    
    void start_burst_thread();
    void stop_burst_thread();
    
    void set_send_callback(std::function<bool(const uint8_t*, size_t)> callback);
    void update_network_conditions(double latency_ms, double loss_rate, double bandwidth_bps);
    
    BurstMetrics get_metrics() const;
    size_t get_buffer_size() const;
    bool is_buffer_full() const;
    
private:
    BurstConfig config_;
    BurstMetrics metrics_;
    
    std::vector<uint8_t> buffer_;
    mutable std::mutex buffer_mutex_;
    std::condition_variable buffer_cv_;
    
    std::thread burst_thread_;
    std::atomic<bool> running_;
    std::function<bool(const uint8_t*, size_t)> send_callback_;
    
    std::random_device rd_;
    std::mt19937 gen_;
    
    void burst_worker();
    size_t calculate_burst_size();
    uint32_t calculate_burst_interval();
    void adapt_to_network_conditions();
    std::vector<uint8_t> create_realistic_frame_pattern(const uint8_t* data, size_t size);
};

// SIMD-OPTIMIZED ZERO-RTT
struct SIMDZeroRTTStats {
    size_t simd_operations_performed = 0;
    size_t parallel_sessions_processed = 0;
    double average_processing_time_us = 0.0;
    size_t cache_hits = 0;
    size_t cache_misses = 0;
};

class UnifiedSIMDZeroRTTManager : public UnifiedZeroRTTManager {
public:
    UnifiedSIMDZeroRTTManager(
        bool enable_simd = true,
        bool enable_parallel_processing = true,
        size_t cache_size = 1024
    );
    
    std::vector<uint8_t> generate_session_ticket_simd(
        const std::string& server_name,
        const std::vector<uint8_t>& session_data,
        const std::vector<uint8_t>& key
    );
    
    std::vector<uint8_t> validate_session_ticket_simd(
        const std::vector<uint8_t>& ticket,
        const std::vector<uint8_t>& key
    );
    
    std::vector<uint8_t> generate_client_hello_simd(
        const std::string& server_name,
        const std::vector<std::string>& alpn_protocols,
        const std::vector<uint8_t>& early_data = {}
    );
    
    std::vector<uint8_t> compute_psk_simd(
        const std::vector<uint8_t>& master_secret,
        const std::vector<uint8_t>& nonce,
        const std::string& label
    );
    
    void process_multiple_connections(
        const std::vector<std::string>& server_names,
        std::function<void(const std::string&, const std::vector<uint8_t>&)> callback
    );
    
    SIMDZeroRTTStats getSIMDStats() const;
    
private:
    bool simd_enabled_;
    bool parallel_processing_enabled_;
    size_t cache_size_;
    
    mutable std::mutex simd_mutex_;
    SIMDZeroRTTStats simd_stats_;
    
    // SIMD-optimized crypto operations
    void simd_aes_encrypt(const uint8_t* input, uint8_t* output, const uint8_t* key, size_t blocks);
    void simd_aes_decrypt(const uint8_t* input, uint8_t* output, const uint8_t* key, size_t blocks);
    void simd_sha256_hash(const uint8_t* input, size_t length, uint8_t* output);
    
    // Cache management
    struct CacheEntry {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> session_cache_;
    
    void update_cache(const std::string& key, const std::vector<uint8_t>& data);
    bool get_from_cache(const std::string& key, std::vector<uint8_t>& data);
    void cleanup_cache();
};

// UNIFIED NETWORK OPTIMIZATION MANAGER
struct NetworkOptimizationConfig {
    BBRParams bbr_params;
    BurstConfig burst_config;
    uint32_t zero_rtt_token_lifetime_s = 86400; // 24 hours
    
    bool enable_bbr_v2 = true;
    bool enable_burst_buffer = true;
    bool enable_zero_rtt = true;
    bool enable_simd_optimizations = true;
    
    size_t max_concurrent_connections = 1000;
    double target_latency_ms = 50.0;
    double target_throughput_mbps = 100.0;
};

class UnifiedNetworkOptimizer {
public:
    explicit UnifiedNetworkOptimizer(const NetworkOptimizationConfig& config = NetworkOptimizationConfig());
    ~UnifiedNetworkOptimizer();
    
    // BBRv2 operations
    void update_congestion_control(int connection_id, uint64_t rtt_us, double bandwidth_bps,
                                  uint64_t bytes_in_flight, uint64_t bytes_acked, uint64_t bytes_lost);
    double get_pacing_rate(int connection_id) const;
    uint64_t get_congestion_window(int connection_id) const;
    
    // Burst buffer operations
    bool add_data_to_burst(int connection_id, const uint8_t* data, size_t size);
    void set_burst_send_callback(int connection_id, std::function<bool(const uint8_t*, size_t)> callback);
    
    // Zero-RTT operations
    UnifiedZeroRTTToken generate_zero_rtt_token(const std::string& hostname);
    bool validate_zero_rtt_token(const UnifiedZeroRTTToken& token, const std::string& hostname);
    std::vector<uint8_t> generate_early_data(const std::string& hostname, const std::vector<uint8_t>& data);
    
    // Connection management
    int create_connection(const std::string& hostname);
    void close_connection(int connection_id);
    
    // Performance monitoring
    struct NetworkPerformanceMetrics {
        double average_latency_ms = 0.0;
        double throughput_mbps = 0.0;
        double packet_loss_rate = 0.0;
        size_t active_connections = 0;
        size_t zero_rtt_success_rate = 0.0;
    };
    
    NetworkPerformanceMetrics get_performance_metrics() const;
    
    // Configuration updates
    void update_config(const NetworkOptimizationConfig& config);
    NetworkOptimizationConfig get_config() const;
    
private:
    NetworkOptimizationConfig config_;
    
    // Component instances
    std::unordered_map<int, std::unique_ptr<UnifiedBBRv2>> bbr_instances_;
    std::unordered_map<int, std::unique_ptr<UnifiedBurstBuffer>> burst_buffers_;
    std::unique_ptr<UnifiedSIMDZeroRTTManager> zero_rtt_manager_;
    
    // Connection management
    mutable std::mutex connections_mutex_;
    std::atomic<int> next_connection_id_;
    std::unordered_map<int, std::string> connection_hostnames_;
    
    // Performance tracking
    mutable std::mutex metrics_mutex_;
    NetworkPerformanceMetrics metrics_;
    
    void update_performance_metrics();
};

// CONVENIENCE FUNCTIONS
UnifiedNetworkOptimizer& get_global_network_optimizer();
void setup_optimized_connection(int socket_fd, const std::string& hostname);
void apply_bbr_v2_to_socket(int socket_fd);
bool enable_zero_rtt_for_hostname(const std::string& hostname);

// ============================================================================
// ENERGY OPTIMIZATIONS
// ============================================================================

namespace energy {

class EnergyManager {
public:
    static EnergyManager& getInstance();
    
    void enable_energy_saving_mode();
    void disable_energy_saving_mode();
    bool is_energy_saving_enabled() const;
    
    void set_cpu_frequency_scaling(bool enabled);
    void set_idle_core_parking(bool enabled);
    
    struct EnergyMetrics {
        double estimated_power_consumption_watts;
        double energy_efficiency_score;
        uint64_t active_cores;
        double average_cpu_frequency_mhz;
    };
    
    EnergyMetrics get_metrics() const;
    
private:
    EnergyManager() = default;
    
    bool energy_saving_enabled_ = false;
    bool cpu_freq_scaling_enabled_ = false;
    bool idle_core_parking_enabled_ = false;
    
    EnergyMetrics current_metrics_;
};

class EnergyEfficientWorkerPool {
public:
    explicit EnergyEfficientWorkerPool(size_t max_workers);
    ~EnergyEfficientWorkerPool();
    
    template<typename Func, typename... Args>
    auto enqueue(Func&& func, Args&&... args) -> std::future<decltype(func(args...))>;
    
    void set_power_profile(const std::string& profile);
    void adjust_workers_to_load();
    
    size_t get_active_worker_count() const;
    double get_energy_efficiency_ratio() const;
    
private:
    size_t max_workers_;
    size_t current_workers_;
    std::string power_profile_;
    
    std::atomic<size_t> queued_tasks_;
    std::atomic<size_t> completed_tasks_;
    
    std::vector<std::thread> workers_;
    std::atomic<bool> should_terminate_;
    
    void worker_thread();
    size_t calculate_optimal_worker_count() const;
};

} // namespace energy

} // namespace quicfuscate::optimize

#endif // UNIFIED_OPTIMIZATIONS_HPP
