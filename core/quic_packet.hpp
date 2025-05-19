#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

namespace quicsand {

// QUIC Packet-Typen gemäß RFC 9000
enum class PacketType {
    INITIAL,          // Initial Packet (0x00)
    ZERO_RTT,         // 0-RTT Packet (0x01)
    HANDSHAKE,        // Handshake Packet (0x02)
    RETRY,            // Retry Packet (0x03)
    ONE_RTT,          // 1-RTT Packet (0x...)
    VERSION_NEGOTIATION, // Version Negotiation
    UNKNOWN           // Unbekannter Typ
};

// QUIC Packet Header
struct QuicPacketHeader {
    PacketType type;
    uint32_t version;      // 32-bit Version
    uint64_t connection_id; // Connection ID
    uint64_t packet_number; // Packet Number
    
    // Standardkonstruktor
    QuicPacketHeader()
        : type(PacketType::UNKNOWN), 
          version(0), 
          connection_id(0), 
          packet_number(0) {}
          
    // Konstruktor mit Parametern
    QuicPacketHeader(PacketType type, uint32_t version, 
                     uint64_t connection_id, uint64_t packet_number)
        : type(type), 
          version(version), 
          connection_id(connection_id), 
          packet_number(packet_number) {}
};

// QUIC Packet Klasse
class QuicPacket {
public:
    // Konstruktoren
    QuicPacket();
    QuicPacket(const QuicPacketHeader& header);
    QuicPacket(PacketType type, uint32_t version = 0x00000001);
    
    // Kopier- und Move-Konstruktor/Zuweisung
    QuicPacket(const QuicPacket& other);
    QuicPacket& operator=(const QuicPacket& other);
    QuicPacket(QuicPacket&& other) noexcept;
    QuicPacket& operator=(QuicPacket&& other) noexcept;
    
    // Destruktor
    ~QuicPacket() = default;
    
    // Getter für Header und Payload
    const QuicPacketHeader& header() const;
    const std::vector<uint8_t>& payload() const;
    
    // Setter für Header und Payload
    void set_header(const QuicPacketHeader& header);
    void set_payload(const std::vector<uint8_t>& payload);
    
    // Setter für Paket-Typ
    void set_packet_type(PacketType type);
    
    // Helper-Methoden für Paket-Typ
    bool is_initial() const;
    bool is_handshake() const;
    bool is_stream() const;
    bool is_one_rtt() const;
    
    // Serialisieren/Deserialisieren für Netzwerkübertragung
    std::vector<uint8_t> serialize() const;
    static std::shared_ptr<QuicPacket> deserialize(const std::vector<uint8_t>& data);
    
    // Hilfsmethode: Paket-Größe
    size_t size() const;
    
    // Konvertierung von/zu String-Darstellung (für Debugging)
    std::string to_string() const;
    
private:
    QuicPacketHeader header_;
    std::vector<uint8_t> payload_;
};

} // namespace quicsand
