/**
 * http3_masquerading_test.cpp
 * 
 * Unit-Tests für die HTTP/3-Masquerading-Funktionalität von QuicSand.
 */

#include <gtest/gtest.h>
#include "../stealth/http3_masquerading.hpp"
#include "../core/quic_packet.hpp"
#include <vector>
#include <memory>
#include <string>

using namespace quicsand;

// Test-Fixture für HTTP/3-Masquerading-Tests
class Http3MasqueradingTest : public ::testing::Test {
protected:
    void SetUp() override {
        masquerading_ = std::make_unique<Http3Masquerading>();
        
        // Standardkonfiguration für Tests
        std::map<std::string, std::string> config = {
            {"browser_profile", "Chrome_Latest"}
        };
        
        masquerading_->initialize(config);
    }

    std::unique_ptr<Http3Masquerading> masquerading_;
};

// Test: Korrekte Erzeugung eines HTTP/3-Frames
TEST_F(Http3MasqueradingTest, CreateFrameTest) {
    // Einfachen DATA-Frame erstellen
    std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto frame = masquerading_->create_frame(Http3FrameType::DATA, payload);
    
    // Frame sollte nicht leer sein
    ASSERT_FALSE(frame.empty());
    
    // Erstes Byte sollte der Frame-Typ sein (DATA = 0x00)
    EXPECT_EQ(static_cast<uint8_t>(Http3FrameType::DATA), frame[0]);
    
    // Die Frame-Größe sollte größer sein als die Payload-Größe (wegen Header)
    EXPECT_GT(frame.size(), payload.size());
    
    // Die Extrahierung von Frames sollte funktionieren
    std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>> extracted_frames;
    bool success = masquerading_->extract_frames(frame, extracted_frames);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(1, extracted_frames.size());
    
    if (!extracted_frames.empty()) {
        EXPECT_EQ(Http3FrameType::DATA, extracted_frames[0].first);
        EXPECT_EQ(payload, extracted_frames[0].second);
    }
}

// Test: Korrekte Erzeugung einer HTTP/3-Anfrage
TEST_F(Http3MasqueradingTest, CreateRequestTest) {
    // HTTP/3-Anfrage erstellen
    std::string host = "example.com";
    std::string path = "/index.html";
    auto request = masquerading_->create_http3_request(host, path);
    
    // Request sollte nicht leer sein
    ASSERT_FALSE(request.empty());
    
    // Die Extrahierung von Frames sollte funktionieren
    std::vector<std::pair<Http3FrameType, std::vector<uint8_t>>> extracted_frames;
    bool success = masquerading_->extract_frames(request, extracted_frames);
    
    EXPECT_TRUE(success);
    // Eine Anfrage sollte mindestens einen HEADERS-Frame enthalten
    EXPECT_GE(extracted_frames.size(), 1);
    
    // Der erste Frame sollte ein HEADERS-Frame sein
    if (!extracted_frames.empty()) {
        EXPECT_EQ(Http3FrameType::HEADERS, extracted_frames[0].first);
    }
}

// Test: Prozessierung von Paketen
TEST_F(Http3MasqueradingTest, ProcessPacketsTest) {
    // Ein QUIC Initial-Paket erstellen
    auto packet = std::make_shared<QuicPacket>();
    packet->set_packet_type(PacketType::INITIAL);
    
    // Einfache Payload setzen
    std::vector<uint8_t> payload = {'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a'};
    packet->set_payload(payload);
    
    // Paket prozessieren
    bool success = masquerading_->process_outgoing_packet(packet);
    
    // Prozessierung sollte erfolgreich sein
    EXPECT_TRUE(success);
    
    // Die neue Payload sollte länger sein als die ursprüngliche (wegen HTTP/3-Headers)
    EXPECT_GT(packet->payload().size(), payload.size());
    
    // Entgegengesetzte Richtung testen
    auto incoming_packet = std::make_shared<QuicPacket>(*packet);
    success = masquerading_->process_incoming_packet(incoming_packet);
    
    // Prozessierung sollte erfolgreich sein
    EXPECT_TRUE(success);
}

// Test: Verschiedene Browser-Profile
TEST_F(Http3MasqueradingTest, BrowserProfilesTest) {
    // Chrome-Profil testen (bereits in SetUp eingestellt)
    std::string host = "example.com";
    std::string path = "/index.html";
    auto chrome_request = masquerading_->create_http3_request(host, path);
    
    // Auf Firefox wechseln
    masquerading_->set_browser_profile("Firefox_Latest");
    EXPECT_EQ("Firefox_Latest", masquerading_->get_browser_profile());
    
    auto firefox_request = masquerading_->create_http3_request(host, path);
    
    // Auf Safari wechseln
    masquerading_->set_browser_profile("Safari_Latest");
    EXPECT_EQ("Safari_Latest", masquerading_->get_browser_profile());
    
    auto safari_request = masquerading_->create_http3_request(host, path);
    
    // Die Anfragen sollten unterschiedlich sein
    EXPECT_NE(chrome_request, firefox_request);
    EXPECT_NE(chrome_request, safari_request);
    EXPECT_NE(firefox_request, safari_request);
}

// Hauptfunktion für den Test
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
