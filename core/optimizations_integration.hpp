#ifndef OPTIMIZATIONS_INTEGRATION_HPP
#define OPTIMIZATIONS_INTEGRATION_HPP

#include "cache_optimizations.hpp"
#include "thread_optimizations.hpp"
#include "energy_optimizations.hpp"
#include "quic_connection.hpp"
#include "quic_path_mtu_manager.hpp"
#include <memory>

namespace quicsand {

/**
 * @brief Konfiguration für alle Optimierungen
 * 
 * Diese Struktur vereint alle Konfigurationsoptionen für Cache-, Thread- und 
 * Energieoptimierungen in einer zentralen Konfiguration.
 */
struct OptimizationsConfig {
    CacheOptimizationConfig cache_config;
    ThreadOptimizationConfig thread_config;
    EnergyConfig energy_config;
    
    // Standardkonfiguration für verschiedene Plattformen
    static OptimizationsConfig create_default() {
        OptimizationsConfig config;
        // Standardwerte für universelle Konfiguration
        return config;
    }
    
    static OptimizationsConfig create_for_mobile() {
        OptimizationsConfig config;
        config.energy_config.thread_mode = ThreadEnergyMode::EFFICIENT;
        config.energy_config.enable_arm_specific_optimizations = true;
        return config;
    }
    
    static OptimizationsConfig create_for_server() {
        OptimizationsConfig config;
        config.energy_config.thread_mode = ThreadEnergyMode::PERFORMANCE;
        return config;
    }
};

/**
 * @brief Manager für alle Optimierungen
 * 
 * Diese Klasse integriert alle Optimierungen (Cache, Thread, Energie)
 * und bietet eine einheitliche Schnittstelle für ihre Anwendung auf
 * die verschiedenen Komponenten des QuicSand-Projekts.
 */
class OptimizationsManager {
public:
    explicit OptimizationsManager(const OptimizationsConfig& config = OptimizationsConfig::create_default())
        : config_(config), energy_manager_(config.energy_config) {}
    
    /**
     * @brief Aktualisiert die Konfiguration
     * 
     * @param config Die neue Konfiguration
     */
    void set_config(const OptimizationsConfig& config) {
        config_ = config;
        energy_manager_.configure(config.energy_config);
    }
    
    /**
     * @brief Optimiert einen QuicConnection für bessere Performance
     * 
     * @param connection Die zu optimierende Verbindung
     */
    void optimize_connection(QuicConnection& connection) {
        // Cache-Optimierungen auf Verbindungsbuffer anwenden
        
        // Thread-Optimierungen für Multithreading-Operationen
        
        // Energieoptimierungen für effizientere Verarbeitung
        if (config_.energy_config.enable_arm_specific_optimizations) {
            energy_manager_.optimize_for_arm();
        }
    }
    
    /**
     * @brief Erzeugt einen optimierten Thread-Pool für die Paketverarbeitung
     * 
     * @param num_threads Die Anzahl der Threads (Standard: Anzahl der CPU-Kerne)
     * @return std::unique_ptr<EnergyEfficientWorkerPool> Ein optimierter Thread-Pool
     */
    std::unique_ptr<EnergyEfficientWorkerPool> create_optimized_worker_pool(
        size_t num_threads = std::thread::hardware_concurrency()
    ) {
        return std::make_unique<EnergyEfficientWorkerPool>(
            num_threads, 
            config_.energy_config.thread_mode
        );
    }
    
    /**
     * @brief Optimiert einen PathMtuManager für bessere Performance
     * 
     * @param mtu_manager Der zu optimierende MTU-Manager
     */
    void optimize_mtu_manager(PathMtuManager& mtu_manager) {
        // Beispiel-Integration
        // In einer vollständigen Implementierung würden wir hier
        // interne Buffer und Verarbeitungsroutinen optimieren
    }
    
    /**
     * @brief Liefert eine Referenz zum EnergyManager
     * 
     * @return EnergyManager& Referenz zum internen EnergyManager
     */
    EnergyManager& get_energy_manager() {
        return energy_manager_;
    }
    
    /**
     * @brief Erzeugt Cache-optimierte Container für Paketbuffer
     * 
     * @tparam T Der Elementtyp (üblicherweise uint8_t für Paketdaten)
     * @param initial_capacity Die initiale Kapazität
     * @return CacheOptimizedVector<T> Ein Cache-optimierter Vektor
     */
    template <typename T>
    CacheOptimizedVector<T> create_optimized_buffer(size_t initial_capacity = 1500) {
        CacheOptimizedVector<T> buffer;
        buffer.reserve(initial_capacity);
        return buffer;
    }

private:
    OptimizationsConfig config_;
    EnergyManager energy_manager_;
};

} // namespace quicsand

#endif // OPTIMIZATIONS_INTEGRATION_HPP
