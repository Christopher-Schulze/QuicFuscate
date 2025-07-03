#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    OneRtt = 0x04,
    VersionNegotiation = 0x05,
}

impl From<u8> for PacketType {
    fn from(v: u8) -> Self {
        match v {
            0x00 => PacketType::Initial,
            0x01 => PacketType::ZeroRtt,
            0x02 => PacketType::Handshake,
            0x03 => PacketType::Retry,
            0x04 => PacketType::OneRtt,
            0x05 => PacketType::VersionNegotiation,
            _ => PacketType::Initial,
        }
    }
}

impl From<PacketType> for u8 {
    fn from(pt: PacketType) -> u8 {
        pt as u8
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicPacketHeader {
    pub packet_type: PacketType,
    pub version: u32,
    pub connection_id: u64,
    pub packet_number: u64,
}

impl Default for QuicPacketHeader {
    fn default() -> Self {
        Self {
            packet_type: PacketType::Initial,
            version: 0x0000_0001,
            connection_id: 0,
            packet_number: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicPacket {
    pub header: QuicPacketHeader,
    pub payload: Vec<u8>,
}

impl QuicPacket {
    pub fn new() -> Self {
        Self {
            header: QuicPacketHeader::default(),
            payload: Vec::new(),
        }
    }

    pub fn with_header(header: QuicPacketHeader) -> Self {
        Self {
            header,
            payload: Vec::new(),
        }
    }

    pub fn with_type(packet_type: PacketType, version: u32) -> Self {
        Self {
            header: QuicPacketHeader {
                packet_type,
                version,
                ..Default::default()
            },
            payload: Vec::new(),
        }
    }

    pub fn is_initial(&self) -> bool {
        self.header.packet_type == PacketType::Initial
    }
    pub fn is_handshake(&self) -> bool {
        self.header.packet_type == PacketType::Handshake
    }
    pub fn is_stream(&self) -> bool {
        self.header.packet_type == PacketType::OneRtt
    }
    pub fn is_one_rtt(&self) -> bool {
        self.header.packet_type == PacketType::OneRtt
    }

    pub fn set_packet_type(&mut self, t: PacketType) {
        self.header.packet_type = t;
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17 + self.payload.len());
        out.push(self.header.packet_type.into());
        out.extend_from_slice(&self.header.version.to_be_bytes());
        out.extend_from_slice(&self.header.connection_id.to_be_bytes());
        out.extend_from_slice(&(self.header.packet_number as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 17 {
            return None;
        }
        let packet_type = PacketType::from(data[0]);
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let mut conn_bytes = [0u8; 8];
        conn_bytes.copy_from_slice(&data[5..13]);
        let connection_id = u64::from_be_bytes(conn_bytes);
        let pn = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let payload = if data.len() > 17 {
            data[17..].to_vec()
        } else {
            Vec::new()
        };
        Some(Self {
            header: QuicPacketHeader {
                packet_type,
                version,
                connection_id,
                packet_number: pn as u64,
            },
            payload,
        })
    }

    pub fn size(&self) -> usize {
        17 + self.payload.len()
    }

    pub fn to_string(&self) -> String {
        format!(
            "QuicPacket[type={:?}, version=0x{:08x}, conn_id=0x{:016x}, pkt_num={}, payload_size={}]",
            self.header.packet_type,
            self.header.version,
            self.header.connection_id,
            self.header.packet_number,
            self.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut pkt = QuicPacket::with_type(PacketType::Handshake, 0x11223344);
        pkt.header.connection_id = 0xdead_beef_dead_beef;
        pkt.header.packet_number = 42;
        pkt.payload = b"hello".to_vec();
        let bytes = pkt.serialize();
        let dec = QuicPacket::deserialize(&bytes).unwrap();
        assert_eq!(pkt, dec);
    }
}
