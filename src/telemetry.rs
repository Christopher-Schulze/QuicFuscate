use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, IntGauge, TextEncoder, register_int_counter, register_int_gauge};

lazy_static! {
    pub static ref ENCODED_PACKETS: IntCounter =
        register_int_counter!("encoded_packets_total", "Total encoded packets").unwrap();
    pub static ref DECODED_PACKETS: IntCounter =
        register_int_counter!("decoded_packets_total", "Total decoded packets").unwrap();
    pub static ref LOSS_RATE: IntGauge =
        register_int_gauge!("loss_rate_percent", "Current loss rate * 100").unwrap();
    pub static ref FEC_MODE: IntGauge =
        register_int_gauge!("fec_mode", "Current FEC mode").unwrap();
}

pub fn serve(addr: &str) {
    use std::net::TcpListener;
    use std::io::Write;
    let listener = TcpListener::bind(addr).expect("bind metrics");
    std::thread::spawn(move || {
        let encoder = TextEncoder::new();
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let metrics = prometheus::gather();
                let mut buf = Vec::new();
                encoder.encode(&metrics, &mut buf).unwrap();
                let _ = s.write_all(&buf);
            }
        }
    });
}
