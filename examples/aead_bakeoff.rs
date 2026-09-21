//! Same-API AEAD bakeoff harness (TODO-1038).
//!
//! Owners share `AeadSeal`/`AeadOpen` except rustls cells, which use a real
//! `rustls::quic::PacketKey`. P1 always applies ring AES header protection.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use quicfuscate::crypto::aead::{
    AeadOpen, AeadOpenItem, AeadSeal, AeadSealItem, PacketHeaderProtector,
};
use quicfuscate::crypto::{
    select_libaegis128_packet, AesGcm128, LibAegis128Variant, RingAesGcm128, RingAesHp,
    RingChaCha20Poly1305,
};
use quicfuscate::error::ConnectionError;
use rustls::quic::PacketKey;
use rustls::Side;

const TAG_LEN: usize = 16;
const SIZES: [usize; 7] = [64, 256, 512, 1024, 1200, 1400, 8192];
const DEFAULT_ITERS: usize = 800;
const DEFAULT_WARMUP: usize = 80;
const HP_KEY: [u8; 16] = [0x09; 16];
const AEAD_KEY16: [u8; 16] = [0x11; 16];
const AEAD_KEY32: [u8; 32] = [0x22; 32];
const IV12: [u8; 12] = [0x33; 12];
const CID: &[u8] = b"bakeoff-cid-0001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Owner {
    RRing,
    RLc,
    RChaCha,
    SAegis,
    SAegisX2,
    SAegisX4,
    FAes,
    IRing,
}

impl Owner {
    fn id(self) -> &'static str {
        match self {
            Self::RRing => "R-RING",
            Self::RLc => "R-LC",
            Self::RChaCha => "R-CHACHA",
            Self::SAegis => "S-AEGIS",
            Self::SAegisX2 => "S-AEGIS-X2",
            Self::SAegisX4 => "S-AEGIS-X4",
            Self::FAes => "F-AES",
            Self::IRing => "I-RING",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value.to_ascii_uppercase().as_str() {
            "R-RING" | "RRING" => Self::RRing,
            "R-LC" | "RLC" => Self::RLc,
            "R-CHACHA" | "RCHACHA" => Self::RChaCha,
            "S-AEGIS" | "SAEGIS" | "S-AEGIS-L" | "SAEGISL" => Self::SAegis,
            "S-AEGIS-X2" | "SAEGISX2" => Self::SAegisX2,
            "S-AEGIS-X4" | "SAEGISX4" => Self::SAegisX4,
            "F-AES" | "FAES" => Self::FAes,
            "I-RING" | "IRING" => Self::IRing,
            _ => return None,
        })
    }
}

fn all_owners() -> Vec<Owner> {
    vec![
        Owner::RRing,
        Owner::RLc,
        Owner::RChaCha,
        Owner::SAegis,
        Owner::SAegisX2,
        Owner::SAegisX4,
        Owner::FAes,
        Owner::IRing,
    ]
}

fn libaegis_pair(variant: LibAegis128Variant) -> Result<LivePair, String> {
    let (seal, open) = select_libaegis128_packet(variant, &AEAD_KEY16, &IV12);
    Ok(LivePair::Boxed(Box::new(seal), Box::new(open)))
}

struct RustlsPacket {
    key: Box<dyn PacketKey>,
}

impl AeadSeal for RustlsPacket {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let tag_len = self.key.tag_len();
        let sealed = len.checked_add(tag_len).ok_or(ConnectionError::BufferTooShort)?;
        if buf.len() < sealed {
            return Err(ConnectionError::BufferTooShort);
        }
        let tag = self
            .key
            .encrypt_in_place(counter, ad, &mut buf[..len])
            .map_err(|error| ConnectionError::TlsError(error.to_string()))?;
        buf[len..sealed].copy_from_slice(tag.as_ref());
        Ok(sealed)
    }
}

impl AeadOpen for RustlsPacket {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        let plain = self
            .key
            .decrypt_in_place(counter, ad, buf)
            .map_err(|error| ConnectionError::TlsError(error.to_string()))?;
        Ok(plain.len())
    }
}

fn rustls_packet(suite: rustls::SupportedCipherSuite) -> Result<RustlsPacket, String> {
    let tls13 = suite.tls13().ok_or("suite is not TLS 1.3")?;
    let quic = tls13.quic.ok_or("suite has no QUIC algorithm")?;
    let keys =
        rustls::quic::Keys::initial(rustls::quic::Version::V1, tls13, quic, CID, Side::Client);
    Ok(RustlsPacket { key: keys.local.packet })
}

enum LivePair {
    Rustls(RustlsPacket),
    RingAes(RingAesGcm128),
    FirstPartyAes(AesGcm128),
    Boxed(Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>),
}

impl LivePair {
    fn seal(&self) -> &dyn AeadSeal {
        match self {
            Self::Rustls(owner) => owner,
            Self::RingAes(owner) => owner,
            Self::FirstPartyAes(owner) => owner,
            Self::Boxed(seal, _) => seal.as_ref(),
        }
    }

    fn open(&self) -> &dyn AeadOpen {
        match self {
            Self::Rustls(owner) => owner,
            Self::RingAes(owner) => owner,
            Self::FirstPartyAes(owner) => owner,
            Self::Boxed(_, open) => open.as_ref(),
        }
    }
}

fn owner_status(owner: Owner) -> Result<LivePair, String> {
    match owner {
        Owner::RRing => rustls_packet(rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256)
            .map(LivePair::Rustls),
        Owner::RLc => {
            #[cfg(feature = "rustls-aws-lc")]
            {
                rustls_packet(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256)
                    .map(LivePair::Rustls)
            }
            #[cfg(not(feature = "rustls-aws-lc"))]
            {
                Err("UNAVAILABLE: rustls-aws-lc feature is off".to_string())
            }
        }
        Owner::RChaCha => {
            rustls_packet(rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)
                .map(LivePair::Rustls)
        }
        Owner::SAegis => libaegis_pair(LibAegis128Variant::L),
        Owner::SAegisX2 => libaegis_pair(LibAegis128Variant::X2),
        Owner::SAegisX4 => libaegis_pair(LibAegis128Variant::X4),
        Owner::FAes => Ok(LivePair::FirstPartyAes(AesGcm128::from_arrays(&AEAD_KEY16, &IV12))),
        Owner::IRing => RingAesGcm128::from_arrays(&AEAD_KEY16, &IV12)
            .map(LivePair::RingAes)
            .map_err(|error| error.to_string()),
    }
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn measure_ns(iters: usize, warmup: usize, mut body: impl FnMut(u64)) -> (u128, u128, u128) {
    for i in 0..warmup {
        body(i as u64 + 1);
    }
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let start = Instant::now();
        body(i as u64 + 1 + warmup as u64);
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    (percentile(&samples, 0.50), percentile(&samples, 0.95), percentile(&samples, 0.99))
}

fn short_header(pn: u64) -> ([u8; 5], [u8; 4]) {
    let first = 0x43u8;
    let pn_bytes = (pn as u32).to_be_bytes();
    let mut aad = [0u8; 5];
    aad[0] = first;
    aad[1..].copy_from_slice(&pn_bytes);
    (aad, pn_bytes)
}

fn apply_hp(hp: &RingAesHp, aad: &mut [u8; 5], sample: &[u8]) {
    let mask = hp.new_mask(sample).expect("HP sample");
    aad[0] ^= mask[0] & 0x1f;
    for i in 0..4 {
        aad[1 + i] ^= mask[1 + i];
    }
}

struct Cell {
    owner: &'static str,
    path: &'static str,
    size: usize,
    batch: usize,
    median_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    status: String,
}

fn emit(cell: &Cell) {
    let bytes = cell.size as u128 * cell.batch as u128;
    let bps = if cell.median_ns == 0 {
        0.0
    } else {
        (bytes as f64) / (cell.median_ns as f64 / 1_000_000_000.0)
    };
    println!(
        "owner={} path={} size={} batch={} median_ns={} p95_ns={} p99_ns={} bytes_s={:.0} ns_packet={} allocs=0 copied=16 status={}",
        cell.owner,
        cell.path,
        cell.size,
        cell.batch,
        cell.median_ns,
        cell.p95_ns,
        cell.p99_ns,
        bps,
        cell.median_ns / cell.batch.max(1) as u128,
        cell.status
    );
}

fn prove_roundtrip(pair: &LivePair, size: usize) -> Result<(), String> {
    let mut buf = vec![0u8; size + TAG_LEN];
    for (i, byte) in buf.iter_mut().take(size).enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let original = buf[..size].to_vec();
    let sealed = pair
        .seal()
        .seal_with_u64_counter(7, b"aad", &mut buf, size, None)
        .map_err(|error| error.to_string())?;
    let opened = pair
        .open()
        .open_with_u64_counter(7, b"aad", &mut buf[..sealed])
        .map_err(|error| error.to_string())?;
    if opened != size || buf[..opened] != original {
        return Err("roundtrip mismatch".to_string());
    }
    Ok(())
}

fn run_p0(pair: &LivePair, size: usize, iters: usize, warmup: usize) -> Cell {
    let mut buf = vec![0u8; size + TAG_LEN];
    let payload = vec![0x5Au8; size];
    let (median, p95, p99) = measure_ns(iters, warmup, |counter| {
        buf[..size].copy_from_slice(&payload);
        let sealed = pair
            .seal()
            .seal_with_u64_counter(counter, b"p0-aad", &mut buf, size, None)
            .expect("p0 seal");
        std::hint::black_box(sealed);
        let opened = pair
            .open()
            .open_with_u64_counter(counter, b"p0-aad", &mut buf[..sealed])
            .expect("p0 open");
        std::hint::black_box(opened);
    });
    Cell {
        owner: "",
        path: "P0",
        size,
        batch: 1,
        median_ns: median,
        p95_ns: p95,
        p99_ns: p99,
        status: "ok".to_string(),
    }
}

fn run_p1(pair: &LivePair, hp: &RingAesHp, size: usize, iters: usize, warmup: usize) -> Cell {
    let mut buf = vec![0u8; size + TAG_LEN];
    let payload = vec![0xA5u8; size];
    let (median, p95, p99) = measure_ns(iters, warmup, |counter| {
        let (aad, _) = short_header(counter);
        buf[..size].copy_from_slice(&payload);
        let sealed = pair
            .seal()
            .seal_with_u64_counter(counter, &aad, &mut buf, size, None)
            .expect("p1 seal");
        let mut protected = aad;
        apply_hp(hp, &mut protected, &buf[..16]);
        std::hint::black_box(protected);
        std::hint::black_box(sealed);
        let opened =
            pair.open().open_with_u64_counter(counter, &aad, &mut buf[..sealed]).expect("p1 open");
        std::hint::black_box(opened);
    });
    Cell {
        owner: "",
        path: "P1",
        size,
        batch: 1,
        median_ns: median,
        p95_ns: p95,
        p99_ns: p99,
        status: "ok".to_string(),
    }
}

fn run_p2(
    pair: &LivePair,
    hp: &RingAesHp,
    size: usize,
    batch: usize,
    iters: usize,
    warmup: usize,
) -> Cell {
    let payload = vec![0x3Cu8; size];
    let mut bufs = vec![vec![0u8; size + TAG_LEN]; batch];
    let ads: Vec<[u8; 5]> = (0..batch).map(|i| short_header(i as u64 + 1).0).collect();
    let (median, p95, p99) = measure_ns(iters, warmup, |base| {
        for buf in bufs.iter_mut() {
            buf[..size].copy_from_slice(&payload);
        }
        let mut seal_items: Vec<AeadSealItem<'_>> = bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadSealItem {
                counter: base + i as u64,
                ad: &ads[i],
                buf,
                plaintext_len: size,
            })
            .collect();
        pair.seal().seal_batch(&mut seal_items).expect("p2 seal_batch");
        drop(seal_items);
        for (i, buf) in bufs.iter_mut().enumerate() {
            let mut protected = ads[i];
            apply_hp(hp, &mut protected, &buf[..16]);
            std::hint::black_box(protected);
        }
        let mut open_items: Vec<AeadOpenItem<'_>> = bufs
            .iter_mut()
            .enumerate()
            .map(|(i, buf)| AeadOpenItem { counter: base + i as u64, ad: &ads[i], buf })
            .collect();
        pair.open().open_batch(&mut open_items).expect("p2 open_batch");
        std::hint::black_box(open_items.len());
    });
    Cell {
        owner: "",
        path: if batch == 8 { "P2-8" } else { "P2-16" },
        size,
        batch,
        median_ns: median,
        p95_ns: p95,
        p99_ns: p99,
        status: "ok".to_string(),
    }
}

fn host_meta() -> String {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string());
    format!(
        "host={} arch={} os={} rustc={} commit={}",
        hostname(),
        env::consts::ARCH,
        env::consts::OS,
        rustc_version(),
        commit.trim()
    )
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string()
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string()
}

fn chi_square(hist: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let expected = total as f64 / 256.0;
    hist.iter()
        .map(|count| {
            let diff = *count as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

fn nearest_mean_accuracy(left: &[u8], right: &[u8]) -> f64 {
    let split = left.len() / 2;
    if split < 64 || right.len() <= split {
        return 0.5;
    }
    let mean = |samples: &[u8]| -> f64 {
        samples.iter().map(|byte| u64::from(*byte)).sum::<u64>() as f64 / samples.len() as f64
    };
    let mean_left = mean(&left[..split]);
    let mean_right = mean(&right[..split]);
    let mut correct = 0usize;
    let test = left[split..]
        .iter()
        .map(|sample| (*sample, true))
        .chain(right[split..].iter().map(|sample| (*sample, false)));
    let mut total = 0usize;
    for (sample, is_left) in test {
        let from_left = (f64::from(sample) - mean_left).abs();
        let from_right = (f64::from(sample) - mean_right).abs();
        if (from_left <= from_right) == is_left {
            correct += 1;
        }
        total += 1;
    }
    if total == 0 {
        0.5
    } else {
        correct as f64 / total as f64
    }
}

fn distinguish(owners: &[Owner], packets: usize, size: usize) {
    println!("# distinguisher packets={packets} size={size}");
    let mut first_bytes: Vec<(Owner, Vec<u8>)> = Vec::new();
    let mut max_chi = 0.0f64;
    for owner in owners {
        match owner_status(*owner) {
            Ok(pair) => {
                let mut hist = [0u64; 256];
                let mut runs = 0u64;
                let mut last = 0u8;
                let mut run_len = 0u64;
                let mut payload = vec![0xA5u8; size];
                let mut buf = vec![0u8; size + TAG_LEN];
                let mut samples = Vec::with_capacity(packets);
                for i in 0..packets {
                    payload[0] = i as u8;
                    buf[..size].copy_from_slice(&payload);
                    let sealed = pair
                        .seal()
                        .seal_with_u64_counter(i as u64 + 1, b"dist", &mut buf, size, None)
                        .expect("distinguish seal");
                    samples.push(buf[0]);
                    for &byte in &buf[..sealed] {
                        hist[byte as usize] += 1;
                        if byte == last {
                            run_len += 1;
                        } else {
                            if run_len >= 3 {
                                runs += 1;
                            }
                            last = byte;
                            run_len = 1;
                        }
                    }
                }
                let chi = chi_square(&hist, (packets * (size + TAG_LEN)) as u64);
                max_chi = max_chi.max(chi);
                println!(
                    "owner={} chi_square={:.2} long_runs={} status=random-looking",
                    owner.id(),
                    chi,
                    runs
                );
                first_bytes.push((*owner, samples));
            }
            Err(reason) => println!("owner={} status={}", owner.id(), reason),
        }
    }
    let Some((_, baseline)) = first_bytes.iter().find(|(owner, _)| *owner == Owner::RRing) else {
        println!("cheap_keyless_distinguisher=UNAVAILABLE baseline=R-RING");
        return;
    };
    let mut max_accuracy: f64 = 0.0;
    for (owner, samples) in &first_bytes {
        if *owner == Owner::RRing {
            continue;
        }
        let accuracy = nearest_mean_accuracy(baseline, samples);
        max_accuracy = max_accuracy.max(accuracy);
        println!("pair=R-RING,{} first_byte_accuracy={:.3}", owner.id(), accuracy);
    }
    // df=255 uniformity. 400 is many standard deviations above E[chi]=255.
    let cheap = max_accuracy > 0.60 || max_chi > 400.0;
    println!(
        "cheap_keyless_distinguisher={cheap} threshold=60pct max_accuracy={max_accuracy:.3} max_chi={max_chi:.2}"
    );
}

fn parse_owners(raw: Option<String>) -> Vec<Owner> {
    match raw {
        Some(value) => value
            .split(',')
            .map(|part| Owner::parse(part.trim()).unwrap_or_else(|| panic!("unknown owner {part}")))
            .collect(),
        None => all_owners(),
    }
}

fn main() {
    let mut owners = all_owners();
    let mut sizes = SIZES.to_vec();
    let mut iters = DEFAULT_ITERS;
    let mut warmup = DEFAULT_WARMUP;
    let mut out_dir: Option<PathBuf> = None;
    let mut mode = "matrix";
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--owners" => {
                i += 1;
                owners = parse_owners(args.get(i).cloned());
            }
            "--sizes" => {
                i += 1;
                sizes = args[i].split(',').map(|part| part.parse().expect("size")).collect();
            }
            "--iters" => {
                i += 1;
                iters = args[i].parse().expect("iters");
            }
            "--warmup" => {
                i += 1;
                warmup = args[i].parse().expect("warmup");
            }
            "--out" => {
                i += 1;
                out_dir = Some(PathBuf::from(&args[i]));
            }
            "--distinguish" => mode = "distinguish",
            "--profile" => mode = "profile",
            "--vectors" => mode = "vectors",
            other => panic!("unknown argument {other}"),
        }
        i += 1;
    }

    println!("# {}", host_meta());
    println!(
        "# command=cargo run --release --example aead_bakeoff --features benches,aead-bakeoff"
    );
    if mode == "distinguish" {
        distinguish(&owners, 10_000, 1400);
        return;
    }
    if mode == "vectors" {
        prove_standard_vectors();
        return;
    }

    let hp = RingAesHp::from_key(&HP_KEY).expect("ring HP");
    let mut lines = Vec::new();
    for owner in owners {
        match owner_status(owner) {
            Err(reason) => {
                for size in &sizes {
                    for path in ["P0", "P1", "P2-8", "P2-16"] {
                        let cell = Cell {
                            owner: owner.id(),
                            path,
                            size: *size,
                            batch: 1,
                            median_ns: 0,
                            p95_ns: 0,
                            p99_ns: 0,
                            status: reason.clone(),
                        };
                        emit(&cell);
                        lines
                            .push(format!("{:?}", (cell.owner, cell.path, cell.size, cell.status)));
                    }
                }
            }
            Ok(pair) => {
                if let Err(error) = prove_roundtrip(&pair, 64) {
                    println!("owner={} status=FAIL {error}", owner.id());
                    continue;
                }
                for size in &sizes {
                    let mut cell = run_p0(&pair, *size, iters, warmup);
                    cell.owner = owner.id();
                    emit(&cell);
                    let mut cell = run_p1(&pair, &hp, *size, iters, warmup);
                    cell.owner = owner.id();
                    emit(&cell);
                    if mode == "profile" {
                        continue;
                    }
                    let mut cell = run_p2(&pair, &hp, *size, 8, iters, warmup);
                    cell.owner = owner.id();
                    emit(&cell);
                    let mut cell = run_p2(&pair, &hp, *size, 16, iters, warmup);
                    cell.owner = owner.id();
                    emit(&cell);
                }
            }
        }
    }

    if let Some(dir) = out_dir {
        fs::create_dir_all(&dir).expect("create out dir");
        fs::write(dir.join("host.txt"), host_meta()).expect("write host");
    }
}

fn prove_standard_vectors() {
    #[cfg(feature = "aead-bakeoff")]
    {
        // CFRG AEGIS-128L vector 1 (draft-irtf-cfrg-aegis-aead 8e289c40).
        let key = hex_16("10010000000000000000000000000000");
        let nonce = hex_16("10000200000000000000000000000000");
        let mut buf = hex_bytes("00000000000000000000000000000000");
        let expected_ct = hex_bytes("c1c0e58bd913006feba00f4b3cc3594e");
        let expected_tag = hex_16("abe0ece80c24868a226a35d16bdae37a");
        let tag =
            aegis::aegis128l::Aegis128L::<16>::new(&key, &nonce).encrypt_in_place(&mut buf, b"");
        assert_eq!(buf, expected_ct, "S-AEGIS ciphertext must match CFRG vector 1");
        assert_eq!(tag.as_ref(), expected_tag, "S-AEGIS tag must match CFRG vector 1");
        println!("s_aegis_cfrg_vector1=ok");
    }
    #[cfg(not(feature = "aead-bakeoff"))]
    {
        println!("s_aegis_cfrg_vector1=UNAVAILABLE: aead-bakeoff feature is off");
    }
    let _ = RingChaCha20Poly1305::from_arrays(&AEAD_KEY32, &IV12).expect("ring chacha typed");
    let _ = RingAesGcm128::from_arrays(&AEAD_KEY16, &IV12).expect("ring aes typed");
}

fn hex_16(value: &str) -> [u8; 16] {
    let bytes = hex_bytes(value);
    bytes.try_into().expect("16-byte hex")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex")
}
