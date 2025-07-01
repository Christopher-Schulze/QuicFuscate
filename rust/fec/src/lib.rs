pub struct FECConfig;

pub struct FECPacket;

pub struct NetworkMetrics;

pub struct FECModule;

impl FECModule {
    pub fn new(_config: FECConfig) -> Self { Self }

    pub fn encode_packet(&self, _data: &[u8]) -> Vec<FECPacket> {
        Vec::new()
    }

    pub fn decode(&self, _packets: &[FECPacket]) -> Vec<u8> {
        Vec::new()
    }

    pub fn update_network_metrics(&self, _metrics: NetworkMetrics) {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
