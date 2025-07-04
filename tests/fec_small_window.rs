use quicfuscate::fec::{Encoder, Decoder, Packet};
use quicfuscate::optimize::MemoryPool;
use std::sync::Arc;

#[test]
fn fec_encode_decode_small_window() {
    // Create small memory pool for packets
    let mem_pool = Arc::new(MemoryPool::new(4, 16));
    let mut encoder = Encoder::new(2, 3);

    // Prepare two source packets
    let mut data1 = mem_pool.alloc();
    data1[..4].copy_from_slice(&[1, 2, 3, 4]);
    let pkt1 = Packet { id: 0, data: data1, len: 4, is_systematic: true, coefficients: None };

    let mut data2 = mem_pool.alloc();
    data2[..4].copy_from_slice(&[5, 6, 7, 8]);
    let pkt2 = Packet { id: 1, data: data2, len: 4, is_systematic: true, coefficients: None };

    encoder.add_source_packet(pkt1.clone_for_encoder(&mem_pool));
    encoder.add_source_packet(pkt2.clone_for_encoder(&mem_pool));

    // Generate repair packet
    let repair = encoder.generate_repair_packet(0, &mem_pool).expect("repair");

    // Decoder receives one systematic and the repair packet
    let mut decoder = Decoder::new(2, Arc::clone(&mem_pool));
    assert!(!decoder.add_packet(pkt1).unwrap());
    assert!(decoder.add_packet(repair).unwrap());

    let mut recovered = decoder.get_decoded_packets();
    recovered.sort_by_key(|p| p.id);
    assert_eq!(recovered.len(), 2);
    assert_eq!(&recovered[0].data[..recovered[0].len], &[1,2,3,4]);
    assert_eq!(&recovered[1].data[..recovered[1].len], &[5,6,7,8]);
}
