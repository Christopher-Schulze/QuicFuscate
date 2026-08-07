use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode, FecPacket};
use quicfuscate::optimize::global_pool;
use std::collections::HashSet;
use std::time::Instant;

fn main() {
    // Params via env/args
    let args: Vec<String> = std::env::args().collect();
    let mut size: usize =
        std::env::var("FEC_SIM_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(1200);
    let mut k: u64 = std::env::var("FEC_SIM_K").ok().and_then(|v| v.parse().ok()).unwrap_or(64);
    let mut loss: f64 =
        std::env::var("FEC_SIM_LOSS").ok().and_then(|v| v.parse().ok()).unwrap_or(0.1);
    let seed: u64 =
        std::env::var("FEC_SIM_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(424242);
    let mut i = 1;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--size" => {
                size = args[i + 1].parse().unwrap_or(size);
                i += 2;
            }
            "--k" => {
                k = args[i + 1].parse().unwrap_or(k);
                i += 2;
            }
            "--loss" => {
                loss = args[i + 1].parse().unwrap_or(loss);
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Deterministic randomness for reproducible loss-matrix runs.
    fastrand::seed(seed);

    let pool = global_pool();
    let cfg = FecConfig { initial_mode: FecMode::Streaming, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    let start = Instant::now();
    let mut tx = Vec::new();
    // Build K systematic packets
    let source_id_start = 1000u64;
    let source_id_end = source_id_start + k;
    for i in 0..k {
        let mut buf = pool.alloc();
        let n = size.min(buf.len());
        for j in 0..n {
            buf[j] = (i as u8).wrapping_add((j * 17) as u8);
        }
        let pkt =
            FecPacket::try_new(source_id_start + i, Some(buf), n, true, None, 0, pool.clone())
                .expect("source packet fits the pool block");
        for p in fec.on_send(pkt) {
            tx.push(p);
        }
    }

    // Simulate loss: keep only (1-loss) fraction
    let mut rx = Vec::new();
    let mut kept_systematic_ids: HashSet<u64> = HashSet::with_capacity(k as usize);
    let mut keep = 0usize;
    let mut drop = 0usize;
    for p in tx {
        let r = fastrand::f64();
        if r >= loss {
            if p.is_systematic {
                kept_systematic_ids.insert(p.id);
            }
            rx.push(p);
            keep += 1;
        } else {
            drop += 1;
        }
    }

    let mut recovered_total = 0usize;
    let mut delivered_ids: HashSet<u64> = HashSet::with_capacity(k as usize);
    for p in rx {
        let out = fec.on_receive(p).expect("decode");
        for q in out {
            if q.payload_slice().is_some() {
                recovered_total += 1;
                if q.id >= source_id_start && q.id < source_id_end {
                    delivered_ids.insert(q.id);
                }
            }
        }
    }
    let dur = start.elapsed();
    let delivered_unique = delivered_ids.len();
    let mut source_coverage_ids = kept_systematic_ids.clone();
    source_coverage_ids.extend(delivered_ids.iter().copied());
    let source_coverage_unique = source_coverage_ids.len();
    let kept_systematic_unique = kept_systematic_ids.len();

    println!(
        "METRIC fec_sim size={} k={} loss={:.3} seed={} kept={} dropped={} kept_systematic_unique={} delivered_unique={} source_coverage_unique={} recovered={} duration_ms={}",
        size,
        k,
        loss,
        seed,
        keep,
        drop,
        kept_systematic_unique,
        delivered_unique,
        source_coverage_unique,
        recovered_total,
        dur.as_millis()
    );
}
