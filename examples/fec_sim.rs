use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode, FecPacket};
use quicfuscate::optimize::global_pool;
use std::collections::HashSet;
use std::time::Instant;

#[path = "bench_cli/mod.rs"]
mod bench_cli;

use bench_cli::{fail, parse_in_range, parse_ratio, parse_size};

/// Largest symbol count this model will simulate.
///
/// `k` sizes a `HashSet` and is added to the source-id base, so an unbounded value
/// could allocate without limit or wrap the identifiers the model is built on.
const MAX_SIM_SYMBOLS: u64 = 1 << 20;

/// Read one optional environment override, refusing a malformed value.
///
/// The previous `.ok().and_then(|v| v.parse().ok())` chain fell back to the default,
/// so an exported typo ran a different workload than the operator configured and the
/// output never said so.
fn env_override<T, F>(name: &str, parse: F) -> Option<T>
where
    F: Fn(&str) -> Result<T, String>,
{
    let raw = std::env::var(name).ok()?;
    Some(parse(&raw).unwrap_or_else(|error| fail(format!("{name}: {error}"))))
}

fn main() {
    // Params via env/args
    let args: Vec<String> = std::env::args().collect();
    let mut size: usize =
        env_override("FEC_SIM_SIZE", |raw| parse_size("FEC_SIM_SIZE", raw)).unwrap_or(1200);
    let mut k: u64 =
        env_override("FEC_SIM_K", |raw| parse_in_range("FEC_SIM_K", raw, 1, MAX_SIM_SYMBOLS))
            .unwrap_or(64);
    let mut loss: f64 =
        env_override("FEC_SIM_LOSS", |raw| parse_ratio("FEC_SIM_LOSS", raw)).unwrap_or(0.1);
    let seed: u64 = env_override("FEC_SIM_SEED", |raw| {
        raw.trim().parse::<u64>().map_err(|error| format!("{raw:?} is not a seed: {error}"))
    })
    .unwrap_or(424242);
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--size" => {
                let Some(value) = args.get(i + 1) else { fail("--size requires a value") };
                size = parse_size("--size", value).unwrap_or_else(|error| fail(error));
                i += 2;
            }
            "--k" => {
                let Some(value) = args.get(i + 1) else { fail("--k requires a value") };
                k = parse_in_range("--k", value, 1, MAX_SIM_SYMBOLS)
                    .unwrap_or_else(|error| fail(error));
                i += 2;
            }
            "--loss" => {
                let Some(value) = args.get(i + 1) else { fail("--loss requires a value") };
                // A non-finite or out-of-range loss models nothing; it used to be
                // accepted and silently produce a meaningless run.
                loss = parse_ratio("--loss", value).unwrap_or_else(|error| fail(error));
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: fec_sim [--size <bytes>] [--k <1..=1048576>] [--loss <0.0..=1.0>]"
                );
                return;
            }
            other => fail(format!("unknown option {other:?}; try --help")),
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
    let source_id_end = source_id_start
        .checked_add(k)
        .unwrap_or_else(|| fail("the requested symbol count overflows the source id range"));
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
