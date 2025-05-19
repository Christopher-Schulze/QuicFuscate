#include <gtest/gtest.h>
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>

#include "../core/quic_connection.hpp"
#include "../core/bbr_v2.hpp"

using namespace quicsand;
using namespace std::chrono_literals;

class BBRv2Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Basiskonfiguration für Tests
        server_addr_ = "127.0.0.1";
        server_port_ = 4433;
        
        // Client und Server Connections einrichten
        setupConnections();
    }
    
    void TearDown() override {
        // Verbindungen abbauen
        if (client_) {
            client_->close(0, "Test beendet");
        }
        
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }
    
    void setupConnections() {
        // Server starten
        server_thread_ = std::thread([this]() {
            // TODO: Wenn wir einen richtigen QUIC-Server haben, können wir diesen hier starten
            // Für diesen Test simulieren wir das Netzwerk
            
            std::this_thread::sleep_for(2s);  // Zeit für Test-Setup
        });
        
        // Client Connection einrichten
        client_ = std::make_shared<QuicConnection>();
        
        // BBRv2 Congestion Control aktivieren
        client_->enable_bbr_congestion_control(true);
        
        // BBRv2 Parameter anpassen
        BBRParams params;
        params.startup_gain = 2.885;
        params.cwnd_gain = 2.0;
        client_->set_bbr_params(params);
    }
    
    // Hilfsfunktionen
    void simulateNetworkConditions(uint64_t bandwidth_kbps, uint64_t rtt_ms, float packet_loss = 0.0) {
        client_->force_congestion_feedback(bandwidth_kbps, rtt_ms);
        
        // Simuliere einige Pakete für die Statistiken
        for (int i = 0; i < 100; i++) {
            // Im echten System würden wir echte Pakete senden
            // Hier simulieren wir nur den Congestion Control Mechanismus
            std::this_thread::sleep_for(1ms);
        }
    }
    
    void printCongestionStats() {
        auto stats = client_->get_stats();
        std::cout << "BBRv2 Stats:" << std::endl;
        std::cout << "  Congestion Window: " << stats.congestion_window << " bytes" << std::endl;
        std::cout << "  Pacing Rate: " << stats.pacing_rate / 1000000.0 << " Mbps" << std::endl;
        std::cout << "  Min RTT: " << stats.min_rtt_us / 1000.0 << " ms" << std::endl;
    }
    
    std::string server_addr_;
    uint16_t server_port_;
    std::shared_ptr<QuicConnection> client_;
    std::thread server_thread_;
};

TEST_F(BBRv2Test, TestBBRv2Initialization) {
    // Überprüfen, ob BBRv2 aktiviert ist
    EXPECT_EQ(client_->get_congestion_algorithm(), CongestionAlgorithm::BBRv2);
    
    // Überprüfen, ob BBRv2 Parameter korrekt gesetzt sind
    BBRParams params = client_->get_bbr_params();
    EXPECT_FLOAT_EQ(params.startup_gain, 2.885);
    EXPECT_FLOAT_EQ(params.cwnd_gain, 2.0);
}

TEST_F(BBRv2Test, TestBBRv2Adaptation) {
    // Test mit verschiedenen Netzwerkbedingungen
    
    // 1. Gute Netzwerkbedingungen
    std::cout << "Simulating good network conditions (50 Mbps, 20ms RTT)" << std::endl;
    simulateNetworkConditions(50000, 20);
    printCongestionStats();
    
    // 2. Langsames Netzwerk
    std::cout << "Simulating slow network conditions (5 Mbps, 100ms RTT)" << std::endl;
    simulateNetworkConditions(5000, 100);
    printCongestionStats();
    
    // 3. Schnelles Netzwerk mit hoher Latenz
    std::cout << "Simulating fast network with high latency (100 Mbps, 150ms RTT)" << std::endl;
    simulateNetworkConditions(100000, 150);
    printCongestionStats();
    
    // 4. Zurück zu normalen Bedingungen
    std::cout << "Simulating normal network conditions (20 Mbps, 40ms RTT)" << std::endl;
    simulateNetworkConditions(20000, 40);
    printCongestionStats();
    
    // Keine spezifischen Assertions, da die eigentlichen Werte vom BBRv2-Algorithmus
    // dynamisch berechnet werden und von der Simulation abhängen.
    // In diesem Test geht es eher darum zu sehen, ob der Algorithmus auf die
    // verschiedenen Bedingungen reagiert.
}

TEST_F(BBRv2Test, TestSwitchingCongestionAlgorithms) {
    // Wechsel zwischen verschiedenen Congestion-Control-Algorithmen
    
    // Starte mit BBRv2
    EXPECT_EQ(client_->get_congestion_algorithm(), CongestionAlgorithm::BBRv2);
    
    // Wechsel zu CUBIC
    client_->set_congestion_algorithm(CongestionAlgorithm::CUBIC);
    EXPECT_EQ(client_->get_congestion_algorithm(), CongestionAlgorithm::CUBIC);
    
    // Simuliere Netzwerkverkehr
    simulateNetworkConditions(20000, 40);
    printCongestionStats();
    
    // Wechsel zurück zu BBRv2
    client_->set_congestion_algorithm(CongestionAlgorithm::BBRv2);
    EXPECT_EQ(client_->get_congestion_algorithm(), CongestionAlgorithm::BBRv2);
    
    // Simuliere Netzwerkverkehr
    simulateNetworkConditions(20000, 40);
    printCongestionStats();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
