#![no_main]

use std::net::{Ipv4Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;

use quicfuscate::transport::packet;
use quicfuscate::transport::{Config, RecvInfo};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut cfg = match Config::new_with_version(1) {
        Ok(cfg) => cfg,
        Err(_) => return,
    };
    cfg.enable_dgram(8, 8);
    let scid = [data[0]; 8];
    let local = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 4433));
    let peer = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 4434));
    let mut conn = match packet::connect(None, &scid, local, peer, &mut cfg) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let info = RecvInfo { from: peer, to: local, ecn: None };
    let mut buf = data.to_vec();
    let _ = conn.recv(&mut buf, &info);
});
