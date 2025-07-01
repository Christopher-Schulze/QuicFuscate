use fec::{FECModule, FECConfig, NetworkMetrics};

#[test]
fn adaptive_redundancy_changes() {
    let mut module = FECModule::new(FECConfig::default());
    let mut pkts = module.encode_packet(b"hi", 1);
    assert_eq!(pkts.len(), 2); // one repair at default 0.1 -> ceil(1) =>1 repair
    module.update_network_metrics(NetworkMetrics { packet_loss_rate: 0.4 });
    pkts = module.encode_packet(b"hi", 2);
    assert!(pkts.len() > 2);
}
