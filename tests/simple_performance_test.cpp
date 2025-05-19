#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <thread>

// Simple Performance Test für QuicSand
// Dieser Test implementiert vereinfachte Versionen der Performance-Komponenten
// und testet sie direkt, ohne Abhängigkeiten zu anderen Modulen.

// ---- Hilfsfunktionen ----

void print_separator(const std::string& title) {
    std::cout << "\n========== " << title << " ==========\n" << std::endl;
}

std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dist(gen));
    }
    
    return data;
}

// ---- Burst Buffer Test ----

class SimpleBurstBuffer {
public:
    struct Config {
        size_t min_burst_size;
        size_t max_burst_size;
        size_t optimal_burst_size;
        uint32_t min_interval_ms;
        uint32_t max_interval_ms;
        bool adaptive_sizing;
        bool adaptive_timing;
        
        Config() : min_burst_size(1024), max_burst_size(8192), optimal_burst_size(4096),
                  min_interval_ms(20), max_interval_ms(100), adaptive_sizing(true),
                  adaptive_timing(true) {}
    };
    
    struct Metrics {
        size_t total_bytes_sent;
        size_t total_bursts_sent;
        double average_burst_size;
        uint32_t average_interval_ms;
        
        Metrics() : total_bytes_sent(0), total_bursts_sent(0), average_burst_size(0),
                   average_interval_ms(0) {}
    };
    
    SimpleBurstBuffer(const Config& config = Config()) : config_(config) {}
    
    void add_data(const std::vector<uint8_t>& data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
    }
    
    void send_burst() {
        if (buffer_.empty()) return;
        
        // Berechne optimale Burstgröße
        size_t burst_size = std::min(config_.optimal_burst_size, buffer_.size());
        
        // Erstelle den Burst
        std::vector<uint8_t> burst(buffer_.begin(), buffer_.begin() + burst_size);
        buffer_.erase(buffer_.begin(), buffer_.begin() + burst_size);
        
        // Aktualisiere Metriken
        metrics_.total_bursts_sent++;
        metrics_.total_bytes_sent += burst_size;
        metrics_.average_burst_size = static_cast<double>(metrics_.total_bytes_sent) / metrics_.total_bursts_sent;
        
        // In einem echten System würden wir hier die Daten senden
        std::cout << "  Burst #" << metrics_.total_bursts_sent << ": " << burst_size 
                 << " bytes gesendet" << std::endl;
    }
    
    Metrics get_metrics() const {
        return metrics_;
    }
    
private:
    Config config_;
    Metrics metrics_;
    std::vector<uint8_t> buffer_;
};

void test_burst_buffer() {
    print_separator("Burst Buffer Test");
    
    // Erstelle einen Burst-Buffer mit angepasster Konfiguration
    SimpleBurstBuffer::Config config;
    config.min_burst_size = 1024;
    config.max_burst_size = 8192;
    config.optimal_burst_size = 4096;
    
    SimpleBurstBuffer buffer(config);
    
    // Sende Daten über einen Zeitraum
    std::cout << "Sende zufällige Daten an den Burst-Buffer..." << std::endl;
    
    const int test_duration_ms = 2000; // 2 Sekunden
    const int iterations = 20;
    const int interval_ms = test_duration_ms / iterations;
    
    for (int i = 0; i < iterations; ++i) {
        // Generiere zufällige Datengröße (512-2048 Bytes)
        size_t data_size = 512 + (std::rand() % 1536);
        auto data = generate_random_data(data_size);
        
        buffer.add_data(data);
        
        std::cout << "  Puffer hinzugefügt: " << data_size << " bytes" << std::endl;
        
        // Sende einen Burst
        buffer.send_burst();
        
        // Kurz warten
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
    
    // Zeige Statistiken
    auto metrics = buffer.get_metrics();
    std::cout << "\nBurst-Buffer-Metriken:" << std::endl;
    std::cout << "  Gesendete Bursts: " << metrics.total_bursts_sent << std::endl;
    std::cout << "  Gesendete Bytes: " << metrics.total_bytes_sent << " bytes" << std::endl;
    std::cout << "  Durchschnittliche Burstgröße: " << metrics.average_burst_size << " bytes" << std::endl;
}

// ---- Zero-Copy Test ----

class SimpleZeroCopyBuffer {
public:
    void add_buffer(const std::vector<uint8_t>& data) {
        // In einer echten Zero-Copy-Implementierung würden wir hier nur einen Pointer speichern
        // Für den Test kopieren wir dennoch die Daten
        buffers_.push_back(data);
    }
    
    size_t total_size() const {
        size_t total = 0;
        for (const auto& buf : buffers_) {
            total += buf.size();
        }
        return total;
    }
    
    void clear() {
        buffers_.clear();
    }
    
private:
    std::vector<std::vector<uint8_t>> buffers_;
};

void test_zero_copy() {
    print_separator("Zero-Copy Test");
    
    // Erstelle einen Zero-Copy-Buffer
    SimpleZeroCopyBuffer buffer;
    
    // Teste verschiedene Datengrößen
    std::vector<size_t> data_sizes = {1024, 4096, 16384, 65536};
    
    std::cout << "Teste Zero-Copy mit verschiedenen Datengrößen..." << std::endl;
    
    for (size_t size : data_sizes) {
        // Generiere Testdaten
        auto data = generate_random_data(size);
        
        // Messe die Zeit für normale Speicheroperationen
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<uint8_t> copy1 = data;
        std::vector<uint8_t> copy2 = copy1;
        std::vector<uint8_t> copy3 = copy2;
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto copy_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        
        // Messe die Zeit für Zero-Copy-Operationen
        start_time = std::chrono::high_resolution_clock::now();
        
        buffer.add_buffer(data);
        size_t total_size = buffer.total_size();
        
        end_time = std::chrono::high_resolution_clock::now();
        auto zero_copy_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        
        // Bereinige den Buffer
        buffer.clear();
        
        std::cout << "Datengröße: " << size << " bytes" << std::endl;
        std::cout << "  Normale Kopierdauer: " << copy_duration << " µs" << std::endl;
        std::cout << "  Zero-Copy-Dauer: " << zero_copy_duration << " µs" << std::endl;
        std::cout << "  Beschleunigung: " << (copy_duration > 0 ? static_cast<double>(copy_duration) / zero_copy_duration : 0) << "x" << std::endl;
    }
}

// ---- BBRv2 Congestion Control Test ----

class SimpleBBRv2 {
public:
    enum class State {
        STARTUP,
        DRAIN,
        PROBE_BW,
        PROBE_RTT
    };
    
    struct Params {
        double startup_gain;
        double drain_gain;
        double probe_rtt_gain;
        double cwnd_gain;
        
        Params() : startup_gain(2.885), drain_gain(0.75), probe_rtt_gain(0.75), cwnd_gain(2.0) {}
    };
    
    SimpleBBRv2(const Params& params = Params()) 
        : params_(params), state_(State::STARTUP), 
          min_rtt_us_(UINT64_MAX), max_bw_bps_(0) {}
    
    void update(uint64_t rtt_us, double bandwidth_bps, uint64_t bytes_in_flight) {
        // Aktualisiere RTT und Bandbreite
        min_rtt_us_ = std::min(min_rtt_us_, rtt_us);
        max_bw_bps_ = std::max(max_bw_bps_, bandwidth_bps);
        
        // Aktualisiere den Zustand
        switch (state_) {
            case State::STARTUP:
                if (bandwidth_bps >= max_bw_bps_ * 0.75) {
                    state_ = State::DRAIN;
                }
                break;
                
            case State::DRAIN:
                if (bytes_in_flight <= target_cwnd()) {
                    state_ = State::PROBE_BW;
                }
                break;
                
            case State::PROBE_BW:
                // In einem echten BBRv2 würden wir hier periodisch probieren
                break;
                
            case State::PROBE_RTT:
                // In einem echten BBRv2 würden wir hier das RTT testen
                state_ = State::PROBE_BW;
                break;
        }
    }
    
    double get_pacing_rate() const {
        double gain;
        
        switch (state_) {
            case State::STARTUP:
                gain = params_.startup_gain;
                break;
            case State::DRAIN:
                gain = params_.drain_gain;
                break;
            case State::PROBE_RTT:
                gain = params_.probe_rtt_gain;
                break;
            case State::PROBE_BW:
            default:
                gain = 1.0;
                break;
        }
        
        return max_bw_bps_ * gain;
    }
    
    uint64_t get_congestion_window() const {
        return target_cwnd();
    }
    
    State get_state() const {
        return state_;
    }
    
private:
    uint64_t target_cwnd() const {
        // Berechne das Ziel-Congestion-Window basierend auf BDP (Bandwidth-Delay-Product)
        return static_cast<uint64_t>((max_bw_bps_ / 8.0) * (min_rtt_us_ / 1e6) * params_.cwnd_gain);
    }
    
    Params params_;
    State state_;
    uint64_t min_rtt_us_;
    double max_bw_bps_;
};

void test_bbr_v2() {
    print_separator("BBRv2 Congestion Control Test");
    
    // Erstelle eine BBRv2-Instanz
    SimpleBBRv2 bbr;
    
    // Simuliere verschiedene Netzwerkbedingungen
    struct NetworkCondition {
        std::string name;
        uint64_t rtt_us;
        double bandwidth_bps;
        uint64_t bytes_in_flight;
    };
    
    std::vector<NetworkCondition> conditions = {
        {"Gute Verbindung", 20000, 10e6, 25000},
        {"Mittlere Verbindung", 100000, 5e6, 62500},
        {"Schlechte Verbindung", 300000, 1e6, 37500}
    };
    
    for (const auto& condition : conditions) {
        std::cout << "Simuliere " << condition.name << ":" << std::endl;
        
        // Simuliere 5 Updates
        for (int i = 0; i < 5; ++i) {
            // Aktualisiere BBRv2
            bbr.update(condition.rtt_us, condition.bandwidth_bps, condition.bytes_in_flight);
            
            // Zeige Ergebnisse
            double pacing_rate = bbr.get_pacing_rate();
            uint64_t cwnd = bbr.get_congestion_window();
            
            std::cout << "  Update #" << (i+1) << ":" << std::endl;
            std::cout << "    Pacing-Rate: " << (pacing_rate / 1e6) << " Mbps" << std::endl;
            std::cout << "    Congestion Window: " << cwnd << " bytes" << std::endl;
            
            // Zeige den aktuellen Zustand
            std::cout << "    Zustand: ";
            switch (bbr.get_state()) {
                case SimpleBBRv2::State::STARTUP:
                    std::cout << "STARTUP";
                    break;
                case SimpleBBRv2::State::DRAIN:
                    std::cout << "DRAIN";
                    break;
                case SimpleBBRv2::State::PROBE_BW:
                    std::cout << "PROBE_BW";
                    break;
                case SimpleBBRv2::State::PROBE_RTT:
                    std::cout << "PROBE_RTT";
                    break;
            }
            std::cout << std::endl;
        }
        
        std::cout << std::endl;
    }
}

// ---- Hauptfunktion ----

int main() {
    std::cout << "========== QuicSand Simple Performance Test ==========" << std::endl;
    
    test_burst_buffer();
    test_zero_copy();
    test_bbr_v2();
    
    std::cout << "\n========== Alle Tests abgeschlossen ==========" << std::endl;
    return 0;
}
