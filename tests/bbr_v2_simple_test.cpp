#include "../core/bbr_v2.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <memory>

using namespace quicsand;
using namespace std::chrono_literals;

// Einfacher Test für BBRv2 ohne externe Testbibliotheken
void test_bbr_initialization() {
    std::cout << "=== Test BBRv2 Initialisierung ===" << std::endl;
    
    // Erstelle BBRv2 mit Standardparametern
    BBRParams params;
    auto bbr = std::make_unique<BBRv2>(params);
    
    // Überprüfe Anfangszustand
    if (bbr->get_state() == BBRv2::State::STARTUP) {
        std::cout << "PASSED: BBRv2 startet im STARTUP-Zustand" << std::endl;
    } else {
        std::cout << "FAILED: BBRv2 startet nicht im STARTUP-Zustand" << std::endl;
    }
    
    // Überprüfe Parameter
    auto current_params = bbr->get_params();
    if (current_params.startup_gain == params.startup_gain) {
        std::cout << "PASSED: Parameter wurden korrekt übernommen" << std::endl;
    } else {
        std::cout << "FAILED: Parameter wurden nicht korrekt übernommen" << std::endl;
    }
}

// Test für BBRv2 Zustandsübergänge und Anpassungen
void test_bbr_adaptation() {
    std::cout << "\n=== Test BBRv2 Anpassungen ===" << std::endl;
    
    // Erstelle BBRv2 mit angepassten Parametern
    BBRParams params;
    params.startup_gain = 2.885;
    params.cwnd_gain = 2.0;
    auto bbr = std::make_unique<BBRv2>(params);
    
    // Simuliere gute Netzwerkbedingungen
    std::cout << "\nSimuliere gute Netzwerkbedingungen (50 Mbps, 20ms RTT)" << std::endl;
    uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // Aktualisiere BBRv2 mit simulierten Werten
    uint64_t rtt_us = 20000; // 20ms
    double bandwidth_bps = 50e6; // 50 Mbps
    uint64_t bytes_in_flight = 32 * 1024; // 32 KB
    uint64_t bytes_acked = 16 * 1024; // 16 KB
    uint64_t bytes_lost = 0;
    
    // Mehrere Updates simulieren
    for (int i = 0; i < 100; i++) {
        bbr->update(rtt_us, bandwidth_bps, bytes_in_flight, bytes_acked, bytes_lost, now_us);
        now_us += 10000; // 10ms fortschreiten
        
        // Variiere Werte leicht
        rtt_us = 20000 + (rand() % 5000); // 20-25ms
        bandwidth_bps = 50e6 * (0.9 + 0.2 * (rand() % 100) / 100.0); // ±10% Variation
        bytes_in_flight = 32 * 1024 + (rand() % 16 * 1024);
        bytes_acked = 16 * 1024 + (rand() % 8 * 1024);
        
        if (i % 10 == 0) {
            // Alle 10 Iterationen Statistiken ausgeben
            std::cout << "CWND: " << bbr->get_congestion_window() / 1024.0 << " KB, "
                      << "Pacing Rate: " << bbr->get_pacing_rate() / 1000000.0 << " Mbps, "
                      << "Min RTT: " << bbr->get_min_rtt() / 1000.0 << " ms, "
                      << "State: " << static_cast<int>(bbr->get_state()) << std::endl;
        }
        
        std::this_thread::sleep_for(1ms);
    }
    
    // Simuliere langsames Netzwerk
    std::cout << "\nSimuliere langsames Netzwerk (5 Mbps, 100ms RTT)" << std::endl;
    rtt_us = 100000; // 100ms
    bandwidth_bps = 5e6; // 5 Mbps
    
    for (int i = 0; i < 100; i++) {
        bbr->update(rtt_us, bandwidth_bps, bytes_in_flight, bytes_acked, bytes_lost, now_us);
        now_us += 10000;
        
        // Variiere Werte leicht
        rtt_us = 100000 + (rand() % 20000);
        bandwidth_bps = 5e6 * (0.9 + 0.2 * (rand() % 100) / 100.0);
        
        if (i % 10 == 0) {
            std::cout << "CWND: " << bbr->get_congestion_window() / 1024.0 << " KB, "
                      << "Pacing Rate: " << bbr->get_pacing_rate() / 1000000.0 << " Mbps, "
                      << "Min RTT: " << bbr->get_min_rtt() / 1000.0 << " ms, "
                      << "State: " << static_cast<int>(bbr->get_state()) << std::endl;
        }
        
        std::this_thread::sleep_for(1ms);
    }
    
    // Simuliere schnelles Netzwerk mit hoher Latenz
    std::cout << "\nSimuliere schnelles Netzwerk mit hoher Latenz (100 Mbps, 150ms RTT)" << std::endl;
    rtt_us = 150000; // 150ms
    bandwidth_bps = 100e6; // 100 Mbps
    
    for (int i = 0; i < 100; i++) {
        bbr->update(rtt_us, bandwidth_bps, bytes_in_flight, bytes_acked, bytes_lost, now_us);
        now_us += 10000;
        
        if (i % 10 == 0) {
            std::cout << "CWND: " << bbr->get_congestion_window() / 1024.0 << " KB, "
                      << "Pacing Rate: " << bbr->get_pacing_rate() / 1000000.0 << " Mbps, "
                      << "Min RTT: " << bbr->get_min_rtt() / 1000.0 << " ms, "
                      << "State: " << static_cast<int>(bbr->get_state()) << std::endl;
        }
        
        std::this_thread::sleep_for(1ms);
    }
}

int main() {
    std::cout << "BBRv2 Einfacher Test" << std::endl;
    std::cout << "====================" << std::endl;
    
    try {
        test_bbr_initialization();
        test_bbr_adaptation();
        
        std::cout << "\nAlle Tests abgeschlossen" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Fehler während des Tests: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
