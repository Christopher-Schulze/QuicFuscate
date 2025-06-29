/**
 * quic_packet.cpp
 * 
 * Implementierung der QuicPacket-Klasse für das QuicFuscate-Projekt.
 */

#include "quic_core_types.hpp"
#include <sstream>
#include <iomanip>

namespace quicfuscate {

// Standardkonstruktor
QuicPacket::QuicPacket() : header_() {}

// Konstruktor mit Header
QuicPacket::QuicPacket(const QuicPacketHeader& header) : header_(header) {}

// Konstruktor mit Paket-Typ und Version
QuicPacket::QuicPacket(PacketType type, uint32_t version) {
    header_.type = type;
    header_.version = version;
    header_.connection_id = 0;
    header_.packet_number = 0;
}

// Kopier-Konstruktor
QuicPacket::QuicPacket(const QuicPacket& other) : 
    header_(other.header_), 
    payload_(other.payload_) {}

// Kopier-Zuweisungsoperator
QuicPacket& QuicPacket::operator=(const QuicPacket& other) {
    if (this != &other) {
        header_ = other.header_;
        payload_ = other.payload_;
    }
    return *this;
}

// Move-Konstruktor
QuicPacket::QuicPacket(QuicPacket&& other) noexcept :
    header_(std::move(other.header_)),
    payload_(std::move(other.payload_)) {}

// Move-Zuweisungsoperator
QuicPacket& QuicPacket::operator=(QuicPacket&& other) noexcept {
    if (this != &other) {
        header_ = std::move(other.header_);
        payload_ = std::move(other.payload_);
    }
    return *this;
}

// Getter für Header
const QuicPacketHeader& QuicPacket::header() const {
    return header_;
}

// Getter für Payload
const std::vector<uint8_t>& QuicPacket::payload() const {
    return payload_;
}

// Setter für Header
void QuicPacket::set_header(const QuicPacketHeader& header) {
    header_ = header;
}

// Setter für Payload
void QuicPacket::set_payload(const std::vector<uint8_t>& payload) {
    payload_ = payload;
}

// Setter für Paket-Typ
void QuicPacket::set_packet_type(PacketType type) {
    header_.type = type;
}

// Prüfung auf Initial-Paket
bool QuicPacket::is_initial() const {
    return header_.type == PacketType::INITIAL;
}

// Prüfung auf Handshake-Paket
bool QuicPacket::is_handshake() const {
    return header_.type == PacketType::HANDSHAKE;
}

// Prüfung auf Stream-Paket (1-RTT)
bool QuicPacket::is_stream() const {
    return header_.type == PacketType::ONE_RTT;
}

// Prüfung auf 1-RTT-Paket
bool QuicPacket::is_one_rtt() const {
    return header_.type == PacketType::ONE_RTT;
}

// Serialisierung für Netzwerkübertragung
std::vector<uint8_t> QuicPacket::serialize() const {
    std::vector<uint8_t> packet;
    
    // Einfache Serialisierung für Testzwecke
    // In einer vollständigen Implementierung würde hier die korrekte
    // QUIC-Paketformat-Codierung nach RFC 9000 erfolgen
    
    // 1. Type (1 Byte)
    packet.push_back(static_cast<uint8_t>(header_.type));
    
    // 2. Version (4 Bytes, big-endian)
    packet.push_back((header_.version >> 24) & 0xFF);
    packet.push_back((header_.version >> 16) & 0xFF);
    packet.push_back((header_.version >> 8) & 0xFF);
    packet.push_back(header_.version & 0xFF);
    
    // 3. Connection ID (simplified, 8 bytes)
    for (int i = 7; i >= 0; i--) {
        packet.push_back((header_.connection_id >> (i * 8)) & 0xFF);
    }
    
    // 4. Packet Number (simplified, 4 bytes)
    packet.push_back((header_.packet_number >> 24) & 0xFF);
    packet.push_back((header_.packet_number >> 16) & 0xFF);
    packet.push_back((header_.packet_number >> 8) & 0xFF);
    packet.push_back(header_.packet_number & 0xFF);
    
    // 5. Payload
    packet.insert(packet.end(), payload_.begin(), payload_.end());
    
    return packet;
}

// Deserialisierung von Netzwerkdaten
std::shared_ptr<QuicPacket> QuicPacket::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 17) { // Mindestens Header-Größe
        return nullptr;
    }
    
    auto packet = std::make_shared<QuicPacket>();
    
    // 1. Type (1 Byte)
    packet->header_.type = static_cast<PacketType>(data[0]);
    
    // 2. Version (4 Bytes, big-endian)
    packet->header_.version = (static_cast<uint32_t>(data[1]) << 24) |
                             (static_cast<uint32_t>(data[2]) << 16) |
                             (static_cast<uint32_t>(data[3]) << 8) |
                              static_cast<uint32_t>(data[4]);
    
    // 3. Connection ID (simplified, 8 bytes)
    packet->header_.connection_id = 0;
    for (int i = 0; i < 8; i++) {
        packet->header_.connection_id |= static_cast<uint64_t>(data[5 + i]) << ((7 - i) * 8);
    }
    
    // 4. Packet Number (simplified, 4 bytes)
    packet->header_.packet_number = (static_cast<uint32_t>(data[13]) << 24) |
                                   (static_cast<uint32_t>(data[14]) << 16) |
                                   (static_cast<uint32_t>(data[15]) << 8) |
                                    static_cast<uint32_t>(data[16]);
    
    // 5. Payload
    if (data.size() > 17) {
        packet->payload_.assign(data.begin() + 17, data.end());
    }
    
    return packet;
}

// Paket-Größe berechnen
size_t QuicPacket::size() const {
    // Header-Größe + Payload-Größe
    return 17 + payload_.size(); // 17 Bytes für Header in dieser vereinfachten Implementierung
}

// String-Darstellung für Debugging
std::string QuicPacket::to_string() const {
    std::stringstream ss;
    
    ss << "QuicPacket[type=";
    
    switch (header_.type) {
        case PacketType::INITIAL: ss << "INITIAL"; break;
        case PacketType::ZERO_RTT: ss << "ZERO_RTT"; break;
        case PacketType::HANDSHAKE: ss << "HANDSHAKE"; break;
        case PacketType::RETRY: ss << "RETRY"; break;
        case PacketType::ONE_RTT: ss << "ONE_RTT"; break;
        case PacketType::VERSION_NEGOTIATION: ss << "VERSION_NEGOTIATION"; break;
        default: ss << "UNKNOWN"; break;
    }
    
    ss << ", version=0x" << std::hex << std::setw(8) << std::setfill('0') << header_.version
       << ", conn_id=0x" << std::hex << std::setw(16) << std::setfill('0') << header_.connection_id
       << ", pkt_num=" << std::dec << header_.packet_number
       << ", payload_size=" << payload_.size()
       << "]";
    
    return ss.str();
}

} // namespace quicfuscate
