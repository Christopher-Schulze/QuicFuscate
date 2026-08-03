// QuicFuscate Microbench CLI
// Policy: AES-128-GCM only for handshake; ChaCha used for keystream tests only (no payload AEAD).
// Usage:
//   microbench help
//   microbench aes-block <total_bytes_per_iter> <iters>
//   microbench ghash <total_bytes_per_iter> <iters>
//   microbench ghash-short <iters>
//   microbench aes-gcm <total_bytes_per_iter> <iters>
//   microbench chacha-x4 <total_bytes_per_iter> <iters>
//   microbench bitpack <bit_width:1-8> <values_per_iter> <iters>
//   microbench bitunpack <bit_width:1-8> <values_per_iter> <iters>
//   microbench qpack-enc <bytes_per_iter> <iters>
//   microbench qpack-dec <bytes_per_iter> <iters>
//   microbench popcnt <bytes_per_iter> <iters>
//
// Notes:
// - total_bytes_per_iter controls the data volume processed per measurement iteration.
// - The program prints CSV-like summaries for easy parsing.

use std::env;
use std::time::Instant;

use quicfuscate::optimize::FeatureDetector;

fn parse_usize(s: &str) -> usize {
    if let Some(stripped) = s.strip_suffix("KiB") {
        return stripped.parse::<usize>().unwrap() * 1024;
    }
    if let Some(stripped) = s.strip_suffix("MiB") {
        return stripped.parse::<usize>().unwrap() * 1024 * 1024;
    }
    if let Some(stripped) = s.strip_suffix("B") {
        return stripped.parse::<usize>().unwrap();
    }
    s.parse::<usize>().unwrap()
}

fn format_mbps(bytes: usize, ns: u128) -> f64 {
    if ns == 0 {
        return 0.0;
    }
    let seconds = (ns as f64) / 1_000_000_000.0;
    (bytes as f64) / seconds / 1_000_000.0
}

fn bench_aes_block(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::aes::aes128_encrypt_block;
    let key = [0u8; 16];
    let mut block = [0u8; 16];
    let blocks = total_bytes.div_ceil(16);
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        // vary input minimally to avoid constant folding
        block[0] = (i & 0xFF) as u8;
        for _ in 0..blocks {
            let out = aes128_encrypt_block(&key, &block);
            sink ^= out[0];
        }
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = blocks * 16 * iters;
    println!(
        "bench,aes-block,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_ghash(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::aes::aes128_encrypt_block;
    use quicfuscate::crypto::gcm::ghash;
    let key = [0u8; 16];
    let zero = [0u8; 16];
    let h = aes128_encrypt_block(&key, &zero);
    let aad: [u8; 0] = [];
    let mut ct = vec![0u8; total_bytes];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        if !ct.is_empty() {
            ct[0] = (i & 0xFF) as u8;
        }
        let tag = ghash(h, &aad, &ct);
        sink ^= tag[0];
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,ghash,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_ghash_short(iters: usize) {
    use quicfuscate::crypto::aes::aes128_encrypt_block;
    use quicfuscate::crypto::gcm::ghash;

    const AAD_BYTES: usize = 32;
    const CIPHERTEXT_BYTES: usize = 128;
    let key = [0u8; 16];
    let zero = [0u8; 16];
    let h = aes128_encrypt_block(&key, &zero);
    let aad = [0u8; AAD_BYTES];
    let mut ct = [0u8; CIPHERTEXT_BYTES];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        ct[0] = (i & 0xFF) as u8;
        let tag = ghash(h, &aad, &ct);
        sink ^= tag[0];
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = (AAD_BYTES + CIPHERTEXT_BYTES) * iters;
    let ns_per_packet = if iters == 0 { 0.0 } else { elapsed as f64 / iters as f64 };
    println!(
        "bench,ghash-short,packets,{},bytes,{},iters,{},ns_total,{},ns_per_packet,{:.3},mbps,{:.3},sink,{}",
        iters,
        processed,
        iters,
        elapsed,
        ns_per_packet,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_aes_gcm(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::gcm::aes_gcm_seal;
    let key = [0u8; 16];
    let mut iv = [0u8; 12];
    let aad: [u8; 0] = [];
    let mut pt = vec![0u8; total_bytes];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        iv[0] = (i & 0xFF) as u8;
        if !pt.is_empty() {
            pt[0] = (i & 0x7F) as u8;
        }
        let (ct, tag) = aes_gcm_seal(&key, &iv, &aad, &pt);
        // light sink to avoid optimization
        sink ^= tag[0] ^ ct.first().copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,aes-gcm,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_chacha_x4(total_bytes: usize, iters: usize) {
    use quicfuscate::optimize::crypto::chacha20_blocks_x4;
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut sink: u8 = 0;
    let blocks64 = total_bytes.div_ceil(64);
    let groups = blocks64.div_ceil(4); // 4 blocks per call
    let start = Instant::now();
    for i in 0..iters {
        let mut counter = i as u32;
        for _ in 0..groups {
            let blocks = chacha20_blocks_x4(&key, &nonce, counter);
            counter = counter.wrapping_add(4);
            for block in blocks.iter() {
                sink ^= block[0];
            }
        }
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = groups * 4 * 64 * iters; // upper bound (may exceed requested bytes)
    println!(
        "bench,chacha-x4,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_morus_encrypt(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::MorusAead;
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let nonce = [0u8; 16];
    let ad: [u8; 0] = [];
    let morus = MorusAead::new(&key, &iv).expect("validated benchmark key and IV lengths");
    let mut buffer = vec![0u8; total_bytes];
    let mut sink: u8 = 0;

    let start = Instant::now();
    for i in 0..iters {
        if !buffer.is_empty() {
            buffer[0] = buffer[0].wrapping_add((i as u8).wrapping_add(1));
        }
        let tag = morus.encrypt_in_place(&mut buffer, &ad, &nonce);
        sink ^= tag[0] ^ buffer.first().copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,morus-enc,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_morus_decrypt(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::MorusAead;
    let key = [0xA5u8; 16];
    let iv = [0x5Au8; 12];
    let nonce = [0u8; 16];
    let ad: [u8; 0] = [];
    let morus = MorusAead::new(&key, &iv).expect("validated benchmark key and IV lengths");

    let mut plaintext = vec![0u8; total_bytes];
    for (idx, byte) in plaintext.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(17).wrapping_add(1);
    }

    let mut ciphertext = plaintext.clone();
    let tag = morus.encrypt_in_place(&mut ciphertext, &ad, &nonce);
    let mut work = ciphertext.clone();
    let mut sink = tag[0];

    let start = Instant::now();
    for _ in 0..iters {
        work.copy_from_slice(&ciphertext);
        morus
            .decrypt_in_place(&mut work, &tag, &ad, &nonce)
            .expect("decrypt_in_place should succeed");
        sink ^= work.first().copied().unwrap_or(0);
    }

    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,morus-dec,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_poly1305_mac(total_bytes: usize, iters: usize) {
    use quicfuscate::crypto::poly1305;

    let mut key = [0u8; 32];
    let mut msg = vec![0u8; total_bytes];
    let mut sink: u8 = 0;

    let start = Instant::now();
    for i in 0..iters {
        key[0] = i as u8;
        if !msg.is_empty() {
            msg[0] = msg[0].wrapping_add(1);
        }
        let tag = poly1305::tag(&msg, &key);
        sink ^= tag[0];
    }

    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,poly1305-mac,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

#[cfg(feature = "benches")]
fn bench_sha256(total_bytes: usize, iters: usize, backend: Option<&str>) {
    use quicfuscate::simd::{bench, Sha256BenchBackend};

    let requested = match backend {
        Some("avx2") => Sha256BenchBackend::Avx2,
        Some("vnni") => Sha256BenchBackend::Vnni,
        Some("scalar") => Sha256BenchBackend::Scalar,
        _ => Sha256BenchBackend::Auto,
    };

    let mut data = vec![0u8; total_bytes.max(1)];
    let mut sink: u8 = 0;
    let mut last_used = Sha256BenchBackend::Auto;
    let start = Instant::now();
    for i in 0..iters {
        if let Some(first) = data.first_mut() {
            *first = first.wrapping_add((i as u8).wrapping_add(1));
        }
        let (used, digest) = bench::sha256_digest(&data, requested);
        last_used = used;
        sink ^= digest[0];
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,sha256,bytes,{},iters,{},ns_total,{},mbps,{:.3},backend_req,{},backend_used,{},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        requested.as_str(),
        last_used.as_str(),
        sink
    );
}

#[cfg(not(feature = "benches"))]
fn bench_sha256(_total_bytes: usize, _iters: usize, _backend: Option<&str>) {
    eprintln!("sha256 microbench requires --features benches");
    std::process::exit(2);
}

fn bench_hmac_sha256(total_bytes: usize, iters: usize) {
    use quicfuscate::simd::crypto::hmac_sha256;

    let mut key = vec![0xA5u8; 64];
    let mut data = vec![0u8; total_bytes];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        if let Some(first) = data.first_mut() {
            *first = first.wrapping_add((i as u8) ^ 0x5A);
        }
        if let Some(k) = key.first_mut() {
            *k = k.wrapping_add(1);
        }
        let tag = hmac_sha256(&key, &data);
        sink ^= tag[0];
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = total_bytes * iters;
    println!(
        "bench,hmac-sha256,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn print_profile_info() {
    let detector = FeatureDetector::instance();
    let profile = format!("{:?}", detector.profile());
    let features = format!("{:?}", detector.features_full());
    println!(
        "profile_info,profile={},features={}",
        profile.replace(',', ";"),
        features.replace(',', ";")
    );
}

fn print_help() {
    eprintln!(
        "Microbench CLI\n\nCommands:\n  profile\n  aes-block <bytes_per_iter> <iters>\n  ghash <bytes_per_iter> <iters>\n  ghash-short <iters>\n  aes-gcm <bytes_per_iter> <iters>\n  chacha-x4 <bytes_per_iter> <iters>\n  morus-enc <bytes_per_iter> <iters>\n  morus-dec <bytes_per_iter> <iters>\n  poly1305-mac <bytes_per_iter> <iters>\n  sha256 <bytes_per_iter> <iters> [backend:auto|avx2|vnni|scalar] (requires --features benches)\n  hmac-sha256 <bytes_per_iter> <iters>\n  varint <values_per_iter> <iters>\n  hdr-validate <headers_per_iter> <iters>\n  bitpack <bit_width:1-8> <values_per_iter> <iters>\n  bitunpack <bit_width:1-8> <values_per_iter> <iters>\n  qpack-enc <bytes_per_iter> <iters>\n  qpack-dec <bytes_per_iter> <iters>\n  popcnt <bytes_per_iter> <iters>\nSizes accept suffixes: B, KiB, MiB"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "help" || args[1] == "--help" {
        print_help();
        return;
    }
    let cmd = &args[1];
    if cmd == "profile" {
        print_profile_info();
        return;
    }

    if cmd == "ghash-short" {
        if args.len() != 3 {
            print_help();
            std::process::exit(2);
        }
        bench_ghash_short(parse_usize(&args[2]));
        return;
    }

    if args.len() < 4 {
        print_help();
        std::process::exit(2);
    }

    let bytes = parse_usize(&args[2]);
    let iters = parse_usize(&args[3]);

    match cmd.as_str() {
        "aes-block" => bench_aes_block(bytes, iters),
        "ghash" => bench_ghash(bytes, iters),
        "aes-gcm" => bench_aes_gcm(bytes, iters),
        "chacha-x4" => bench_chacha_x4(bytes, iters),
        "morus-enc" => bench_morus_encrypt(bytes, iters),
        "morus-dec" => bench_morus_decrypt(bytes, iters),
        "poly1305-mac" => bench_poly1305_mac(bytes, iters),
        "sha256" => bench_sha256(bytes, iters, args.get(4).map(String::as_str)),
        "hmac-sha256" => bench_hmac_sha256(bytes, iters),
        "varint" => bench_varint(bytes, iters),
        "hdr-validate" => bench_header_validate(bytes, iters),
        "bitpack" => bench_bitpack(bytes as u8, iters),
        "bitunpack" => bench_bitunpack(bytes as u8, iters),
        "qpack-enc" => bench_qpack_encode(bytes, iters),
        "qpack-dec" => bench_qpack_decode(bytes, iters),
        "popcnt" => bench_popcnt(bytes, iters),
        _ => print_help(),
    }
}

fn bench_varint(values_per_iter: usize, iters: usize) {
    use quicfuscate::simd::transport as t;
    let mut sink: u64 = 0;
    // Cover boundaries: 1,2,4,8-byte encodings
    let corpus: [u64; 8] = [0, 1, 63, 64, 16_383, 16_384, (1u64 << 30) - 1, (1u64 << 62) - 1];
    let mut buf = [0u8; 16];
    let start = Instant::now();
    let mut total_bytes = 0usize;
    for i in 0..iters {
        for j in 0..values_per_iter {
            let v = corpus[i.wrapping_add(j) & 7].wrapping_add((i as u64) & 3);
            let used = t::encode_varint(v, &mut buf);
            if used == 0 {
                continue;
            }
            if let Some((dec, _)) = t::decode_varint(&buf[..used]) {
                sink ^= dec;
                total_bytes += used;
            }
        }
    }
    let elapsed = start.elapsed().as_nanos();
    println!(
        "bench,varint,ops,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        values_per_iter * iters,
        iters,
        elapsed,
        format_mbps(total_bytes, elapsed),
        (sink & 0xFF) as u8
    );
}

fn bench_header_validate(headers_per_iter: usize, iters: usize) {
    // Use the SIMD-routed QUIC header validator (x86/ARM dispatch inside)
    use quicfuscate::simd::fec::validate_header;
    // Two common shapes: short header (fixed=1, reserved=0), long header (0xC0)
    let short = [0x40u8, 0, 0, 0, 0];
    let long = [0xC0u8, 0, 0, 0, 0];
    let bad_short_reserved = [0x58u8, 0, 0, 0, 0]; // reserved bits set
    let mut sink: u64 = 0;
    let start = Instant::now();
    let mut ok = 0usize;
    for i in 0..iters {
        for j in 0..headers_per_iter {
            // Cycle through patterns
            let sel = (i + j) % 3;
            let h = match sel {
                0 => &short[..],
                1 => &long[..],
                _ => &bad_short_reserved[..],
            };
            let v = validate_header(h);
            sink ^= v as u64;
            ok += v as usize;
        }
    }
    let elapsed = start.elapsed().as_nanos();
    let processed_bytes = headers_per_iter * iters * short.len();
    println!(
        "bench,hdr-validate,headers,{},iters,{},ns_total,{},mbps,{:.3},ok,{},sink,{}",
        headers_per_iter * iters,
        iters,
        elapsed,
        format_mbps(processed_bytes, elapsed),
        ok,
        (sink & 0xFF) as u8
    );
}

fn bench_bitpack(bit_width: u8, iters: usize) {
    use quicfuscate::simd::bitstream;
    let values = 4096usize; // fixed corpus per iteration
    let mask = if bit_width == 8 { 0xFF } else { (1u16 << bit_width) as u8 - 1 };
    let mut src = vec![0u8; values];
    for (i, v) in src.iter_mut().enumerate() {
        *v = (i as u8).wrapping_mul(37) & mask;
    }
    let out_bytes = (values as u64 * bit_width as u64).div_ceil(8) as usize;
    let mut dst = vec![0u8; out_bytes];
    let start = Instant::now();
    let mut sink: u8 = 0;
    for i in 0..iters {
        if !src.is_empty() {
            src[0] = src[0].wrapping_add(i as u8);
        }
        let used = bitstream::pack_bits(&src, bit_width, &mut dst);
        sink ^= dst.get(used.wrapping_sub(1)).copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = values * iters;
    println!(
        "bench,bitpack,width,{},values,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        bit_width,
        values * iters,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_bitunpack(bit_width: u8, iters: usize) {
    use quicfuscate::simd::bitstream;
    let values = 4096usize;
    let mask = if bit_width == 8 { 0xFF } else { (1u16 << bit_width) as u8 - 1 };
    let mut src_vals = vec![0u8; values];
    for (i, v) in src_vals.iter_mut().enumerate() {
        *v = (i as u8).wrapping_mul(29) & mask;
    }
    let out_bytes = (values as u64 * bit_width as u64).div_ceil(8) as usize;
    let mut packed = vec![0u8; out_bytes];
    let used = bitstream::pack_bits(&src_vals, bit_width, &mut packed);
    let mut dst_vals = vec![0u8; values];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for _ in 0..iters {
        dst_vals.fill(0);
        let n = bitstream::unpack_bits(&packed[..used], bit_width, &mut dst_vals);
        sink ^= dst_vals.get(n.saturating_sub(1)).copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = values * iters;
    println!(
        "bench,bitunpack,width,{},values,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        bit_width,
        values * iters,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_qpack_encode(bytes_per_iter: usize, iters: usize) {
    use quicfuscate::simd::h3;
    let mut input = vec![0u8; bytes_per_iter];
    let mut output = vec![0u8; bytes_per_iter * 2];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        if !input.is_empty() {
            input[0] = input[0].wrapping_add(i as u8);
        }
        let used = h3::qpack_encode(&input, &mut output);
        sink ^= output.get(used.saturating_sub(1)).copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = bytes_per_iter * iters;
    println!(
        "bench,qpack-enc,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_qpack_decode(bytes_per_iter: usize, iters: usize) {
    use quicfuscate::simd::h3;
    let mut input = vec![0u8; bytes_per_iter];
    // Pre-fill with encoded-ish bytes to avoid early failures
    for (i, v) in input.iter_mut().enumerate().take(bytes_per_iter) {
        *v = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    let mut output = vec![0u8; bytes_per_iter * 2];
    let mut sink: u8 = 0;
    let start = Instant::now();
    for i in 0..iters {
        input[0] = input[0].wrapping_add((i as u8) | 1);
        let used = h3::qpack_decode(&input, &mut output);
        sink ^= output.get(used.saturating_sub(1)).copied().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = bytes_per_iter * iters;
    println!(
        "bench,qpack-dec,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        sink
    );
}

fn bench_popcnt(bytes_per_iter: usize, iters: usize) {
    use quicfuscate::simd::core;
    let mut data = vec![0u8; bytes_per_iter];
    for (i, v) in data.iter_mut().enumerate().take(bytes_per_iter) {
        *v = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    let mut sink: usize = 0;
    let start = Instant::now();
    for i in 0..iters {
        if !data.is_empty() {
            data[0] = data[0].wrapping_add(i as u8);
        }
        sink ^= core::popcnt(&data);
    }
    let elapsed = start.elapsed().as_nanos();
    let processed = bytes_per_iter * iters;
    println!(
        "bench,popcnt,bytes,{},iters,{},ns_total,{},mbps,{:.3},sink,{}",
        processed,
        iters,
        elapsed,
        format_mbps(processed, elapsed),
        (sink & 0xFF) as u8
    );
}
