#ifndef SPIN_BIT_RANDOMIZER_HPP
#define SPIN_BIT_RANDOMIZER_HPP

#include <cstdint>
#include <random>
#include <memory>
#include <chrono>
#include <vector>
#include <functional>

namespace quicsand {
namespace stealth {

/**
 * @brief Strategien für die Spin Bit Randomisierung
 */
enum class SpinBitStrategy {
    RANDOM,              // Völlig zufällige Spin Bit Werte
    ALTERNATING,         // Abwechselnde 0 und 1 Werte
    CONSTANT_ZERO,       // Immer 0
    CONSTANT_ONE,        // Immer 1
    TIMING_BASED,        // Basierend auf dem Timing
    MIMICRY              // Imitation eines bestimmten Musters
};

/**
 * @brief Konfiguration für den Spin Bit Randomizer
 */
struct SpinBitConfig {
    bool enabled = true;                          // Aktiviert die Spin Bit Randomisierung
    SpinBitStrategy strategy = SpinBitStrategy::RANDOM;  // Standardstrategie
    double flip_probability = 0.5;                // Wahrscheinlichkeit für einen Bit-Flip bei RANDOM
    uint32_t alternating_interval_ms = 100;       // Interval für ALTERNATING in ms
    std::vector<uint8_t> mimicry_pattern;         // Muster für MIMICRY
};

/**
 * @brief Klasse für die Randomisierung des QUIC Spin Bits
 * 
 * Der QUIC Spin Bit wird für Latenz-Messungen verwendet und kann für 
 * Traffic-Analyse genutzt werden. Diese Klasse implementiert verschiedene
 * Strategien, um den Spin Bit zu randomisieren und so Traffic-Analyse zu erschweren.
 */
class SpinBitRandomizer {
public:
    /**
     * @brief Konstruktor mit Konfiguration
     * @param config Die Spin Bit Randomizer Konfiguration
     */
    explicit SpinBitRandomizer(const SpinBitConfig& config = SpinBitConfig());
    
    /**
     * @brief Destruktor
     */
    ~SpinBitRandomizer() = default;
    
    /**
     * @brief Setzt den Spin Bit in einem QUIC-Paket
     * @param packet Das zu modifizierende QUIC-Paket (wird in-place modifiziert)
     * @param original_bit Der ursprüngliche Spin Bit Wert
     * @return Der neue Spin Bit Wert
     */
    bool set_spin_bit(std::vector<uint8_t>& packet, bool original_bit);
    
    /**
     * @brief Generiert einen randomisierten Spin Bit Wert
     * @param original_bit Der ursprüngliche Spin Bit Wert
     * @return Der randomisierte Spin Bit Wert
     */
    bool generate_spin_bit(bool original_bit);
    
    /**
     * @brief Aktiviert die Spin Bit Randomisierung
     */
    void enable();
    
    /**
     * @brief Deaktiviert die Spin Bit Randomisierung
     */
    void disable();
    
    /**
     * @brief Überprüft, ob die Randomisierung aktiviert ist
     * @return true, wenn aktiviert, sonst false
     */
    bool is_enabled() const;
    
    /**
     * @brief Setzt die Strategie für die Spin Bit Randomisierung
     * @param strategy Die zu verwendende Strategie
     */
    void set_strategy(SpinBitStrategy strategy);
    
    /**
     * @brief Gibt die aktuelle Strategie zurück
     * @return Die aktuelle Strategie
     */
    SpinBitStrategy get_strategy() const;
    
    /**
     * @brief Setzt das Mimicry-Muster
     * @param pattern Das zu imitierende Muster
     */
    void set_mimicry_pattern(const std::vector<uint8_t>& pattern);
    
    /**
     * @brief Setzt die Konfiguration
     * @param config Die neue Konfiguration
     */
    void set_config(const SpinBitConfig& config);
    
    /**
     * @brief Gibt die aktuelle Konfiguration zurück
     * @return Die aktuelle Konfiguration
     */
    SpinBitConfig get_config() const;
    
private:
    SpinBitConfig config_;
    std::mt19937 rng_;
    std::chrono::steady_clock::time_point start_time_;
    size_t pattern_index_ = 0;
    
    // Implementierungen der verschiedenen Strategien
    bool random_strategy(bool original_bit);
    bool alternating_strategy(bool original_bit);
    bool constant_strategy(bool original_bit);
    bool timing_based_strategy(bool original_bit);
    bool mimicry_strategy(bool original_bit);
    
    // Initialisierung
    void init_rng();
};

} // namespace stealth
} // namespace quicsand

#endif // SPIN_BIT_RANDOMIZER_HPP
