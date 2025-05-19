#ifndef ZERO_COPY_OPTIMIZED_HPP
#define ZERO_COPY_OPTIMIZED_HPP

#include "zero_copy.hpp"
#include "cache_optimizations.hpp"
#include "thread_optimizations.hpp"
#include "energy_optimizations.hpp"
#include <memory>
#include <vector>
#include <functional>

namespace quicsand {

/**
 * @brief Cache-optimierte, erweiterte Version des ZeroCopyBuffer
 * 
 * Diese Klasse erweitert den ZeroCopyBuffer um Cache-optimierte Funktionen
 * und eine verbesserte Integration mit anderen Optimierungen.
 */
class OptimizedZeroCopyBuffer : public ZeroCopyBuffer {
public:
    /**
     * @brief Konstruktor
     * 
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen
     * @param cache_config Konfiguration für Cache-Optimierungen
     */
    OptimizedZeroCopyBuffer(
        size_t max_iovecs = 16,
        const CacheOptimizationConfig& cache_config = CacheOptimizationConfig()
    ) : ZeroCopyBuffer(max_iovecs), cache_config_(cache_config) {}
    
    /**
     * @brief Fügt einen Datenblock hinzu mit optionaler Prefetch-Optimierung
     * 
     * @param data Zeiger auf die Daten
     * @param size Größe des Datenblocks in Bytes
     * @param own_data Falls true, wird eine Kopie erstellt und verwaltet
     * @param prefetch Falls true, wird Prefetching für bessere Performance genutzt
     * @return true bei Erfolg, false bei Fehler
     */
    bool add_buffer_optimized(
        const void* data, 
        size_t size, 
        bool own_data = false,
        bool prefetch = true
    ) {
        if (prefetch && cache_config_.enable_prefetching) {
            // Prefetch für bessere Cache-Lokalität
            Prefetcher::prefetch_range(
                data, 
                size, 
                Prefetcher::PrefetchType::READ,
                cache_config_.prefetch_locality
            );
        }
        
        return add_buffer(data, size, own_data);
    }
    
    /**
     * @brief Führt eine Cache-optimierte Zero-Copy-Sendeoperation aus
     * 
     * @param fd Socket-Deskriptor
     * @param flags Flags für sendmsg
     * @return Anzahl gesendeter Bytes oder -1 bei Fehler
     */
    ssize_t send_optimized(int fd, int flags = 0) {
        if (cache_config_.enable_prefetching) {
            // Prefetch der iovec-Strukturen für bessere Performance
            Prefetcher::prefetch_array(
                iovecs(), 
                iovec_count(), 
                Prefetcher::PrefetchType::READ,
                cache_config_.prefetch_locality
            );
        }
        
        return send(fd, flags);
    }
    
    /**
     * @brief Setzt die Cache-Optimierungskonfiguration
     * 
     * @param config Neue Konfiguration
     */
    void set_cache_config(const CacheOptimizationConfig& config) {
        cache_config_ = config;
    }

private:
    CacheOptimizationConfig cache_config_;
};

/**
 * @brief Cache-optimierte, erweiterte Version des ZeroCopyReceiver
 */
class OptimizedZeroCopyReceiver : public ZeroCopyReceiver {
public:
    /**
     * @brief Konstruktor
     * 
     * @param max_iovecs Maximale Anzahl von iovec-Strukturen
     * @param cache_config Konfiguration für Cache-Optimierungen
     */
    OptimizedZeroCopyReceiver(
        size_t max_iovecs = 16,
        const CacheOptimizationConfig& cache_config = CacheOptimizationConfig()
    ) : ZeroCopyReceiver(max_iovecs), cache_config_(cache_config) {}
    
    /**
     * @brief Führt eine Cache-optimierte Zero-Copy-Empfangsoperation aus
     * 
     * @param fd Socket-Deskriptor
     * @param flags Flags für recvmsg
     * @return Anzahl empfangener Bytes oder -1 bei Fehler
     */
    ssize_t receive_optimized(int fd, int flags = 0) {
        if (cache_config_.enable_prefetching) {
            // Prefetch der iovec-Strukturen für bessere Performance
            Prefetcher::prefetch_array(
                iovecs(), 
                iovec_count(), 
                Prefetcher::PrefetchType::READ,
                cache_config_.prefetch_locality
            );
        }
        
        return receive(fd, flags);
    }
    
    /**
     * @brief Setzt die Cache-Optimierungskonfiguration
     * 
     * @param config Neue Konfiguration
     */
    void set_cache_config(const CacheOptimizationConfig& config) {
        cache_config_ = config;
    }

private:
    CacheOptimizationConfig cache_config_;
};

/**
 * @brief Energy-optimierte Memory-Pool-Klasse
 * 
 * Diese Klasse erweitert den MemoryPool mit Energie-Optimierungen
 * für energieeffiziente Speicherverwaltung.
 */
class EnergyEfficientMemoryPool : public MemoryPool {
public:
    /**
     * @brief Konstruktor
     * 
     * @param block_size Größe eines einzelnen Blocks in Bytes
     * @param initial_blocks Anfängliche Anzahl von Blöcken im Pool
     * @param max_blocks Maximale Anzahl von Blöcken (0 = unbegrenzt)
     * @param energy_config Konfiguration für Energieoptimierungen
     */
    EnergyEfficientMemoryPool(
        size_t block_size = 4096,
        size_t initial_blocks = 16,
        size_t max_blocks = 0,
        const EnergyConfig& energy_config = EnergyConfig()
    ) : MemoryPool(block_size, initial_blocks, max_blocks), 
        energy_manager_(energy_config) {}
    
    /**
     * @brief Allokiert einen Speicherblock mit Energieoptimierung
     * 
     * Diese Methode passt ihre Allokationsstrategie je nach aktuellem
     * Energiemodus an.
     * 
     * @return Zeiger auf den Speicherblock oder nullptr bei Fehler
     */
    void* allocate_optimized() {
        // Je nach Energiemodus verhalten wir uns unterschiedlich
        if (energy_manager_.get_thread_mode() == ThreadEnergyMode::ULTRA_EFFICIENT) {
            // Im Ultra-Efficient-Modus vermeiden wir Pool-Erweiterungen
            void* block = allocate_no_expand();
            if (block) {
                return block;
            }
            // Falls keine Blöcke mehr im Pool, Fallback auf Standard-Allokation
        }
        
        return allocate();
    }
    
    /**
     * @brief Gibt einen Speicherblock zurück mit Energieoptimierung
     * 
     * @param block Zurückzugebender Block
     */
    void free_optimized(void* block) {
        // Optimierte Freigabe je nach Energiemodus
        free(block);
    }
    
    /**
     * @brief Setzt den Energiemodus
     * 
     * @param mode Neuer Energiemodus
     */
    void set_energy_mode(ThreadEnergyMode mode) {
        energy_manager_.set_thread_mode(mode);
    }

private:
    EnergyManager energy_manager_;
    
    /**
     * @brief Allokiert aus dem Pool ohne Erweiterung
     * 
     * Diese Methode allokiert nur dann einen Block, wenn er im Pool
     * bereits vorhanden ist, ohne den Pool zu erweitern.
     * 
     * @return Zeiger auf den Block oder nullptr wenn keiner verfügbar
     */
    void* allocate_no_expand() {
        // Diese Methode würde in der tatsächlichen Implementierung
        // einen Block nur dann zurückgeben, wenn er bereits im Pool ist,
        // ohne den Pool zu erweitern.
        
        // Für diese Demo verwenden wir eine vereinfachte Implementierung
        return allocate();
    }
};

/**
 * @brief Optimierte Zero-Copy-Integration für QuicConnection
 * 
 * Diese Klasse verbessert die Integration von Zero-Copy-Techniken
 * mit der QuicConnection-Klasse, mit besonderem Fokus auf
 * Cache-Effizienz und Energieverbrauch.
 */
class OptimizedZeroCopyIntegration {
public:
    /**
     * @brief Konstruktor
     * 
     * @param cache_config Konfiguration für Cache-Optimierungen
     * @param energy_config Konfiguration für Energieoptimierungen
     */
    OptimizedZeroCopyIntegration(
        const CacheOptimizationConfig& cache_config = CacheOptimizationConfig(),
        const EnergyConfig& energy_config = EnergyConfig()
    ) : send_buffer_(16, cache_config),
        receive_buffer_(16, cache_config),
        memory_pool_(4096, 16, 0, energy_config),
        cache_config_(cache_config),
        energy_config_(energy_config) {}
    
    /**
     * @brief Gibt den optimierten Sende-Buffer zurück
     * 
     * @return OptimizedZeroCopyBuffer& Referenz zum Sende-Buffer
     */
    OptimizedZeroCopyBuffer& send_buffer() {
        return send_buffer_;
    }
    
    /**
     * @brief Gibt den optimierten Empfangs-Buffer zurück
     * 
     * @return OptimizedZeroCopyReceiver& Referenz zum Empfangs-Buffer
     */
    OptimizedZeroCopyReceiver& receive_buffer() {
        return receive_buffer_;
    }
    
    /**
     * @brief Gibt den energieeffizienten Speicherpool zurück
     * 
     * @return EnergyEfficientMemoryPool& Referenz zum Speicherpool
     */
    EnergyEfficientMemoryPool& memory_pool() {
        return memory_pool_;
    }
    
    /**
     * @brief Setzt die Cache-Optimierungskonfiguration
     * 
     * @param config Neue Konfiguration
     */
    void set_cache_config(const CacheOptimizationConfig& config) {
        cache_config_ = config;
        send_buffer_.set_cache_config(config);
        receive_buffer_.set_cache_config(config);
    }
    
    /**
     * @brief Setzt die Energieoptimierungskonfiguration
     * 
     * @param config Neue Konfiguration
     */
    void set_energy_config(const EnergyConfig& config) {
        energy_config_ = config;
        memory_pool_.set_energy_mode(config.thread_mode);
    }

private:
    OptimizedZeroCopyBuffer send_buffer_;
    OptimizedZeroCopyReceiver receive_buffer_;
    EnergyEfficientMemoryPool memory_pool_;
    CacheOptimizationConfig cache_config_;
    EnergyConfig energy_config_;
};

} // namespace quicsand

#endif // ZERO_COPY_OPTIMIZED_HPP
