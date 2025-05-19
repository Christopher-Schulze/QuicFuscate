#include "spin_bit_randomizer.hpp"
#include <iostream>
#include <random>
#include <chrono>

namespace quicsand {
namespace stealth {

// Konstruktor mit Konfiguration
SpinBitRandomizer::SpinBitRandomizer(const SpinBitConfig& config)
    : config_(config), 
      start_time_(std::chrono::steady_clock::now()) {
    init_rng();
}

// Initialisierung des Zufallsgenerators
void SpinBitRandomizer::init_rng() {
    // Seed aus der aktuellen Zeit
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng_.seed(static_cast<uint32_t>(seed));
}

// Setzt den Spin Bit in einem Paket
bool SpinBitRandomizer::set_spin_bit(std::vector<uint8_t>& packet, bool original_bit) {
    if (!config_.enabled) {
        return original_bit;
    }
    
    if (packet.size() < 5) {
        // Zu kleines Paket, kann kein QUIC-Paket sein
        return original_bit;
    }
    
    // Generiere einen neuen Spin Bit Wert
    bool new_bit = generate_spin_bit(original_bit);
    
    // Setze den Spin Bit in das Paket
    // Bei QUIC ist der Spin Bit das 3. Bit im ersten Header-Byte
    // Das erste Byte hat das Format: 1FPKSS...
    // Wobei S der Spin Bit ist
    
    if ((packet[0] & 0x80) != 0) { // Überprüfe, ob es sich um ein Long-Header QUIC-Paket handelt
        // Long Header hat keinen Spin Bit
        return original_bit;
    }
    
    // Short Header Format: 01SKPPPP
    // Setze oder lösche das Spin Bit (3. Bit)
    if (new_bit) {
        packet[0] |= 0x20; // Setze das 3. Bit
    } else {
        packet[0] &= ~0x20; // Lösche das 3. Bit
    }
    
    return new_bit;
}

// Generiert einen randomisierten Spin Bit
bool SpinBitRandomizer::generate_spin_bit(bool original_bit) {
    if (!config_.enabled) {
        return original_bit;
    }
    
    // Wähle die Strategie basierend auf der Konfiguration
    switch (config_.strategy) {
        case SpinBitStrategy::RANDOM:
            return random_strategy(original_bit);
        case SpinBitStrategy::ALTERNATING:
            return alternating_strategy(original_bit);
        case SpinBitStrategy::CONSTANT_ZERO:
        case SpinBitStrategy::CONSTANT_ONE:
            return constant_strategy(original_bit);
        case SpinBitStrategy::TIMING_BASED:
            return timing_based_strategy(original_bit);
        case SpinBitStrategy::MIMICRY:
            return mimicry_strategy(original_bit);
        default:
            return original_bit;
    }
}

// Aktiviert die Randomisierung
void SpinBitRandomizer::enable() {
    config_.enabled = true;
}

// Deaktiviert die Randomisierung
void SpinBitRandomizer::disable() {
    config_.enabled = false;
}

// Überprüft, ob die Randomisierung aktiviert ist
bool SpinBitRandomizer::is_enabled() const {
    return config_.enabled;
}

// Setzt die Strategie
void SpinBitRandomizer::set_strategy(SpinBitStrategy strategy) {
    config_.strategy = strategy;
}

// Gibt die aktuelle Strategie zurück
SpinBitStrategy SpinBitRandomizer::get_strategy() const {
    return config_.strategy;
}

// Setzt das Mimicry-Muster
void SpinBitRandomizer::set_mimicry_pattern(const std::vector<uint8_t>& pattern) {
    config_.mimicry_pattern = pattern;
    pattern_index_ = 0;
}

// Setzt die Konfiguration
void SpinBitRandomizer::set_config(const SpinBitConfig& config) {
    config_ = config;
    pattern_index_ = 0;
}

// Gibt die aktuelle Konfiguration zurück
SpinBitConfig SpinBitRandomizer::get_config() const {
    return config_;
}

// --- Strategie-Implementierungen ---

// Zufällige Strategie
bool SpinBitRandomizer::random_strategy(bool original_bit) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double random_value = dist(rng_);
    
    if (random_value < config_.flip_probability) {
        return !original_bit; // Bit umkehren
    } else {
        return original_bit; // Bit beibehalten
    }
}

// Alternierende Strategie
bool SpinBitRandomizer::alternating_strategy(bool original_bit) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
    
    // Berechne, wie viele Intervalle seit dem Start vergangen sind
    uint64_t intervals = elapsed / config_.alternating_interval_ms;
    
    // Bei gerader Anzahl Intervalle: 0, bei ungerader Anzahl: 1
    return (intervals % 2) != 0;
}

// Konstante Strategie
bool SpinBitRandomizer::constant_strategy(bool original_bit) {
    if (config_.strategy == SpinBitStrategy::CONSTANT_ZERO) {
        return false;
    } else if (config_.strategy == SpinBitStrategy::CONSTANT_ONE) {
        return true;
    } else {
        return original_bit;
    }
}

// Timing-basierte Strategie
bool SpinBitRandomizer::timing_based_strategy(bool original_bit) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(now - start_time_).count();
    
    // Ändere das Bit basierend auf der Mikrosekunden-Komponente der aktuellen Zeit
    bool time_bit = (elapsed_us % 1000) < 500;
    
    // XOR mit dem originalen Bit, um ein plausibles Timing-Muster zu erzeugen
    return time_bit ^ original_bit;
}

// Mimicry-Strategie
bool SpinBitRandomizer::mimicry_strategy(bool original_bit) {
    if (config_.mimicry_pattern.empty()) {
        return original_bit;
    }
    
    // Verwende das nächste Bit im Muster
    bool pattern_bit = (config_.mimicry_pattern[pattern_index_ / 8] & (1 << (pattern_index_ % 8))) != 0;
    
    // Aktualisiere den Index
    pattern_index_ = (pattern_index_ + 1) % (config_.mimicry_pattern.size() * 8);
    
    return pattern_bit;
}

} // namespace stealth
} // namespace quicsand
