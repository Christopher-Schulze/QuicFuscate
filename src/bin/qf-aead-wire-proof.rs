//! Packet-capture proof for the authenticated private AEAD upgrade (TODO-1029).
//!
//! Reads a tcpdump pcap of the QUIC underlay, an NSS keylog (`SSLKEYLOGFILE`)
//! and the private install dump (`QUICFUSCATE_PRIVATE_KEY_DUMP`), then
//! classifies every captured QUIC packet:
//!
//! - Initial / Handshake packets must open with the standard rustls AES-GCM
//!   keys (Initial secrets derive from the DCID per RFC 9001, handshake and
//!   1-RTT secrets come from the keylog).
//! - 1-RTT packets below the negotiated boundary must open with the rustls
//!   1-RTT key.
//! - 1-RTT packets at or above the boundary must FAIL the rustls open and must
//!   open with the negotiated private owner — same packet shape, private AEAD.
//!
//! Exit status is non-zero when any captured packet contradicts the contract.

use qf_crypto::aead::{AeadOpen, PacketHeaderProtector};
use qf_crypto::{quic_kdf, PrivateAeadFamily, RingAesGcm128, RingAesHp};
use std::collections::HashMap;
use std::env;
use std::path::Path;

const TAG_LEN: usize = 16;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;

// Mirror of qftls::private_protocol — private epoch schedule derivation
// (kept private there; duplicated here so the proof can derive epochs >= 2).
const PRIVATE_EXPORTER_SALT: &[u8] = b"quicfuscate private packet protection v1";
const PRIVATE_EXPORTER_LABEL: &[u8] = b"qf private packet aead v1";
const FALLBACK_CID_LEN: usize = 20;

fn main() {
    let args = Args::parse();
    let pcap = match read_pcap(&args.pcap) {
        Ok(p) => p,
        Err(e) => fatal(&format!("pcap read: {e}")),
    };
    let secrets = parse_keylog(&args.keylog);
    let private = parse_private_dump(&args.privdump);

    let mut state = State {
        secrets: &secrets,
        private: &private,
        server_port: args.port,
        expect: HashMap::new(),
        client_scid_len: FALLBACK_CID_LEN,
        server_scid_len: FALLBACK_CID_LEN,
        initial_dcid: None,
        app_version: None,
    };
    let mut report = Report { private_inconsistent: !private.consistent, ..Default::default() };
    for datagram in &pcap.datagrams {
        analyze_datagram(datagram, &mut state, &mut report);
    }
    report.finish(args.expect_standard);
    std::process::exit(if report.ok { 0 } else { 1 });
}

struct Args {
    pcap: String,
    keylog: String,
    privdump: String,
    port: u16,
    expect_standard: bool,
}

impl Args {
    fn parse() -> Self {
        let mut pcap = None;
        let mut keylog = None;
        let mut privdump = None;
        let mut port = 4433u16;
        let mut expect_standard = false;
        let mut it = env::args().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--pcap" => pcap = it.next(),
                "--keylog" => keylog = it.next(),
                "--privdump" => privdump = it.next(),
                "--expect" => {
                    expect_standard = it.next().map(|v| v == "standard").unwrap_or(false);
                }
                "--port" => {
                    port = it.next().and_then(|v| v.parse().ok()).unwrap_or(4433);
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage: qf-aead-wire-proof --pcap <file> --keylog <file> \
                         [--privdump <file>] [--port N] [--expect private|standard]"
                    );
                    std::process::exit(2);
                }
                other => fatal(&format!("unknown argument {other}")),
            }
        }
        Self {
            pcap: pcap.unwrap_or_else(|| fatal("missing --pcap")),
            keylog: keylog.unwrap_or_else(|| fatal("missing --keylog")),
            privdump: privdump.unwrap_or_default(),
            port,
            expect_standard,
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2)
}

// ---------------------------------------------------------------------------
// pcap parsing (classic libpcap, Ethernet / Linux SLL / SLL2)
// ---------------------------------------------------------------------------

struct Pcap {
    datagrams: Vec<Datagram>,
}

struct Datagram {
    src_port: u16,
    payload: Vec<u8>,
}

fn read_pcap(path: &str) -> Result<Pcap, String> {
    let data = std::fs::read(Path::new(path)).map_err(|e| format!("{e}"))?;
    if data.len() < 24 {
        return Err("file too short for pcap header".into());
    }
    let magic_bytes = [data[0], data[1], data[2], data[3]];
    // The on-disk byte order of the magic identifies the file's byte order:
    // a1b2c3d4 stored as-is is a big-endian capture; d4c3b2a1 is little-endian.
    let be_file = match magic_bytes {
        [0xa1, 0xb2, 0xc3, 0xd4] => true,
        [0xd4, 0xc3, 0xb2, 0xa1] => false,
        [0xa1, 0xb2, 0x3c, 0x4d] => true,
        [0x4d, 0x3c, 0xb2, 0xa1] => false,
        _ => {
            return Err(format!(
                "unsupported pcap magic {:02x}{:02x}{:02x}{:02x}",
                data[0], data[1], data[2], data[3]
            ))
        }
    };
    let u32at = |o: usize| -> u32 {
        let b = [data[o], data[o + 1], data[o + 2], data[o + 3]];
        if be_file {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };
    let linktype = u32at(20) as u16;
    let mut off = 24usize;
    let mut datagrams = Vec::new();
    while off + 16 <= data.len() {
        let incl = u32at(off + 8) as usize;
        off += 16;
        if off + incl > data.len() {
            break;
        }
        let frame = &data[off..off + incl];
        off += incl;
        if let Some(dg) = parse_frame(linktype, frame) {
            datagrams.push(dg);
        }
    }
    Ok(Pcap { datagrams })
}

fn parse_frame(linktype: u16, frame: &[u8]) -> Option<Datagram> {
    let ip_off = match linktype {
        1 => {
            // Ethernet II, with optional VLAN tags.
            if frame.len() < 14 {
                return None;
            }
            let mut off = 12usize;
            let mut eth = u16::from_be_bytes([frame[off], frame[off + 1]]);
            while eth == 0x8100 || eth == 0x88a8 {
                off += 4;
                if off + 2 > frame.len() {
                    return None;
                }
                eth = u16::from_be_bytes([frame[off], frame[off + 1]]);
            }
            if eth != 0x0800 && eth != 0x86dd {
                return None;
            }
            off + 2
        }
        113 => {
            // Linux cooked capture v1: protocol field at offset 14.
            if frame.len() < 16 {
                return None;
            }
            let proto = u16::from_be_bytes([frame[14], frame[15]]);
            if proto != 0x0800 && proto != 0x86dd {
                return None;
            }
            16
        }
        276 => {
            // Linux cooked capture v2: protocol field at offset 0.
            if frame.len() < 20 {
                return None;
            }
            let proto = u16::from_be_bytes([frame[0], frame[1]]);
            if proto != 0x0800 && proto != 0x86dd {
                return None;
            }
            20
        }
        _ => return None,
    };
    let ip = frame.get(ip_off..)?;
    let (proto, l4_off) = if ip[0] >> 4 == 4 {
        let ihl = (ip[0] & 0x0f) as usize * 4;
        (ip[9], ihl)
    } else if ip[0] >> 4 == 6 {
        (ip[6], 40usize)
    } else {
        return None;
    };
    if proto != 17 {
        return None;
    }
    let udp = ip.get(l4_off..)?;
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload = udp.get(8..len.min(udp.len()))?;
    Some(Datagram { src_port, payload: payload.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ethernet_ipv4_udp_frame() {
        let payload = vec![0u8; 32];
        let udp_len = 8 + payload.len() as u16;
        let mut frame = vec![0xaau8; 6];
        frame.extend_from_slice(&[0xbb; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        let ip_len = 20 + udp_len;
        frame.extend_from_slice(&[
            0x45,
            0,
            (ip_len >> 8) as u8,
            ip_len as u8,
            0,
            1,
            0,
            0,
            64,
            17,
            0,
            0,
            10,
            10,
            0,
            2,
            10,
            10,
            0,
            1,
        ]);
        frame.extend_from_slice(&[0xd9, 0x03, 0x10, 0xe1]);
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&payload);
        let dg = parse_frame(1, &frame).expect("frame parses");
        assert_eq!(dg.src_port, 55555);
        assert_eq!(dg.payload.len(), 32);
    }
}

// ---------------------------------------------------------------------------
// keylog + private dump parsing
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

struct Secrets {
    map: HashMap<String, Vec<u8>>,
}

impl Secrets {
    fn get(&self, label: &str) -> Option<&[u8]> {
        self.map.get(label).map(Vec::as_slice)
    }
}

fn parse_keylog(path: &str) -> Secrets {
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if let (Some(label), Some(_random), Some(secret)) = (it.next(), it.next(), it.next()) {
                if let Some(bytes) = hex_decode(secret) {
                    map.entry(label.to_string()).or_insert(bytes);
                }
            }
        }
    }
    Secrets { map }
}

#[derive(Default)]
struct PrivateInstall {
    family: Option<PrivateAeadFamily>,
    c2s_key: Option<Vec<u8>>,
    c2s_iv: Option<Vec<u8>>,
    c2s_boundary: u64,
    s2c_key: Option<Vec<u8>>,
    s2c_iv: Option<Vec<u8>>,
    s2c_boundary: u64,
    // Exporter-root schedule material — lets the proof derive arbitrary
    // private epochs for key-phase updates, mirroring
    // qftls::PrivateEpochSchedule::derive.
    schedule_root: Option<Vec<u8>>,
    context_hash: Option<Vec<u8>>,
    consistent: bool,
}

fn parse_private_dump(path: &str) -> PrivateInstall {
    let mut inst = PrivateInstall { consistent: true, ..Default::default() };
    if path.is_empty() {
        return inst;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return inst;
    };
    // Cross-check material between peers: client.write must equal server.read
    // (same direction), client.read must equal server.write.
    let mut client_write: Option<(Vec<u8>, Vec<u8>, u64)> = None;
    let mut client_read: Option<(Vec<u8>, Vec<u8>, u64)> = None;
    let mut server_write: Option<(Vec<u8>, Vec<u8>, u64)> = None;
    let mut server_read: Option<(Vec<u8>, Vec<u8>, u64)> = None;
    for line in text.lines() {
        let mut role = "";
        let mut kv = HashMap::new();
        for tok in line.split_whitespace() {
            if let Some((k, v)) = tok.split_once('=') {
                if k == "role" {
                    role = v;
                } else {
                    kv.insert(k, v);
                }
            }
        }
        if let Some(f) = kv.get("family") {
            inst.family = match *f {
                "aegis" => Some(PrivateAeadFamily::Aegis128L),
                _ => inst.family,
            };
        }
        if let Some(root) = kv.get("schedule_root").and_then(|v| hex_decode(v)) {
            if let Some(existing) = &inst.schedule_root {
                if *existing != root {
                    inst.consistent = false;
                }
            } else {
                inst.schedule_root = Some(root);
            }
        }
        if let Some(ctx) = kv.get("context_hash").and_then(|v| hex_decode(v)) {
            if let Some(existing) = &inst.context_hash {
                if *existing != ctx {
                    inst.consistent = false;
                }
            } else {
                inst.context_hash = Some(ctx);
            }
        }
        let triple = |w: &str| -> Option<(Vec<u8>, Vec<u8>, u64)> {
            Some((
                hex_decode(kv.get(format!("{w}_key").as_str()).copied().unwrap_or(""))?,
                hex_decode(kv.get(format!("{w}_iv").as_str()).copied().unwrap_or(""))?,
                kv.get(format!("{w}_boundary").as_str()).and_then(|v| v.parse().ok()).unwrap_or(0),
            ))
        };
        match role {
            "client" => {
                client_write = triple("write").or(client_write);
                client_read = triple("read").or(client_read);
            }
            "server" => {
                server_write = triple("write").or(server_write);
                server_read = triple("read").or(server_read);
            }
            _ => {}
        }
    }
    // c2s = client write (authoritative) else server read; s2c = server write
    // else client read.
    let c2s = client_write.clone().or_else(|| server_read.clone());
    let s2c = server_write.clone().or_else(|| client_read.clone());
    if let Some((k, i, b)) = c2s {
        inst.c2s_key = Some(k);
        inst.c2s_iv = Some(i);
        inst.c2s_boundary = b;
    }
    if let Some((k, i, b)) = s2c {
        inst.s2c_key = Some(k);
        inst.s2c_iv = Some(i);
        inst.s2c_boundary = b;
    }
    // Consistency only provable when both peers dumped.
    inst.consistent = match (&client_write, &server_read, &server_write, &client_read) {
        (Some(cw), Some(sr), Some(sw), Some(cr)) => {
            cw.0 == sr.0 && cw.1 == sr.1 && sw.0 == cr.0 && sw.1 == cr.1
        }
        _ => true,
    };
    inst
}

// ---------------------------------------------------------------------------
// QUIC packet analysis
// ---------------------------------------------------------------------------

struct DirectionKeys {
    open: RingAesGcm128,
    hp: RingAesHp,
}

impl DirectionKeys {
    fn from_secret(secret: &[u8], version: u32) -> Option<Self> {
        let key = quic_kdf::derive_pkt_key_for_version(secret, 16, version).ok()?;
        let iv = quic_kdf::derive_pkt_iv_for_version(secret, 12, version).ok()?;
        let hp_bytes = quic_kdf::derive_hdr_key_for_version(secret, 16, version).ok()?;
        let open = RingAesGcm128::new(&key, &iv).ok()?;
        let mut hp_arr = [0u8; 16];
        hp_arr.copy_from_slice(&hp_bytes);
        let hp = RingAesHp::from_key(&hp_arr).ok()?;
        Some(Self { open, hp })
    }
}

struct State<'a> {
    secrets: &'a Secrets,
    private: &'a PrivateInstall,
    server_port: u16,
    // Expected next packet number per (space, c2s): 0=initial 1=handshake 2=app.
    expect: HashMap<(u8, bool), u64>,
    client_scid_len: usize,
    server_scid_len: usize,
    // The original DCID from the client's first Initial — Initial secrets
    // derive from this CID for BOTH directions, not from per-packet DCIDs.
    initial_dcid: Option<Vec<u8>>,
    // Negotiated QUIC version learned from the first long-header packet —
    // v2 derives packet keys under different HKDF labels than v1.
    app_version: Option<u32>,
}

#[derive(Default)]
struct Report {
    ok: bool,
    initial_opened: u32,
    handshake_opened: u32,
    long_failed: u32,
    rtt_standard: u32,
    rtt_private: u32,
    rtt_failed: u32,
    rtt_private_below_boundary: u32,
    rtt_standard_above_boundary: u32,
    shape_violations: u32,
    private_inconsistent: bool,
}

impl Report {
    fn finish(&mut self, expect_standard: bool) {
        self.ok = true;
        println!(
            "\n=== AEAD WIRE PROOF SUMMARY (expect={}) ===",
            if expect_standard { "standard" } else { "private" }
        );
        let mut failed = false;
        let mut check = |name: &str, pass: bool, detail: String| {
            println!("  [{}] {name}: {detail}", if pass { "PASS" } else { "FAIL" });
            if !pass {
                failed = true;
            }
        };
        check(
            "initial/handshake open as rustls AES-GCM",
            self.initial_opened + self.handshake_opened > 0 && self.long_failed == 0,
            format!(
                "initial={} handshake={} failures={}",
                self.initial_opened, self.handshake_opened, self.long_failed
            ),
        );
        if expect_standard {
            // Control run against a standard-pinned peer: every 1-RTT packet
            // must stay inside the rustls owner.
            check(
                "all 1-RTT stays rustls-only",
                self.rtt_standard > 0 && self.rtt_private == 0,
                format!("standard_1rtt={} private_1rtt={}", self.rtt_standard, self.rtt_private),
            );
        } else {
            check(
                "pre-boundary 1-RTT opens with rustls keys",
                self.rtt_standard > 0,
                format!("standard_1rtt={}", self.rtt_standard),
            );
            check(
                "post-boundary 1-RTT fails rustls, opens private",
                self.rtt_private > 0 && self.rtt_private_below_boundary == 0,
                format!(
                    "private_1rtt={} below_boundary={}",
                    self.rtt_private, self.rtt_private_below_boundary
                ),
            );
        }
        check(
            "no packet fails every available key",
            self.rtt_failed == 0 && self.shape_violations == 0,
            format!("unopened={} shape_violations={}", self.rtt_failed, self.shape_violations),
        );
        check(
            "no standard packets above the boundary",
            self.rtt_standard_above_boundary == 0,
            format!("standard_above_boundary={}", self.rtt_standard_above_boundary),
        );
        check(
            "private material consistent across peers",
            !self.private_inconsistent,
            format!("cross_peer_mismatch={}", self.private_inconsistent),
        );
        self.ok = !failed;
    }
}

fn analyze_datagram(datagram: &Datagram, state: &mut State, report: &mut Report) {
    let buf = datagram.payload.as_slice();
    let c2s = datagram.src_port != state.server_port;
    let mut off = 0usize;
    while off < buf.len() {
        let first = buf[off];
        if first & 0x80 != 0 {
            // Long header.
            if off + 7 > buf.len() {
                return;
            }
            let version =
                u32::from_be_bytes([buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4]]);
            if version == 0 {
                return; // Version Negotiation: unprotected, ends datagram.
            }
            let dcid_len = buf[off + 5] as usize;
            let Some(dcid) = buf.get(off + 6..off + 6 + dcid_len) else { return };
            let scid_off = off + 6 + dcid_len;
            let Some(&scid_len) = buf.get(scid_off) else { return };
            let mut pos = scid_off + 1 + scid_len as usize;
            if pos > buf.len() {
                return;
            }
            let ty = (first >> 4) & 0x03;
            let (is_initial, is_handshake, is_retry) = match (version, ty) {
                (QUIC_V1, 0) => (true, false, false),
                (QUIC_V1, 2) => (false, true, false),
                (QUIC_V1, 3) => (false, false, true),
                (QUIC_V2, 1) => (true, false, false),
                (QUIC_V2, 3) => (false, true, false),
                (QUIC_V2, 0) => (false, false, true),
                _ => (false, false, false),
            };
            if is_retry {
                return;
            }
            // Learn the SCID length: the sender's source CID becomes the
            // peer's destination CID on short-header packets.
            if c2s {
                state.client_scid_len = scid_len as usize;
            } else {
                state.server_scid_len = scid_len as usize;
            }
            if state.app_version.is_none() {
                state.app_version = Some(version);
            }
            if is_initial && c2s && state.initial_dcid.is_none() {
                state.initial_dcid = Some(dcid.to_vec());
            }
            if is_initial {
                let Some((tok_len, n)) = read_varint(&buf[pos..]) else { return };
                pos += n + tok_len as usize;
            }
            // This stack deliberately omits the RFC 9000 Length field on
            // long-header packets (see transport::packet::format_header):
            // the packet number follows the header fields directly and the
            // packet always consumes the rest of the datagram. Long-header
            // packets therefore cannot be coalesced.
            let pn_offset = pos;
            let end = buf.len();
            if is_initial || is_handshake {
                analyze_long(
                    &buf[off..end],
                    pn_offset - off,
                    dcid,
                    version,
                    if is_initial { 0 } else { 1 },
                    c2s,
                    state,
                    report,
                );
            }
            // 0-RTT long-header packets are skipped; the key schedule for
            // early data is out of scope for this proof.
            off = end;
        } else {
            // Short header consumes the rest of the datagram.
            analyze_short(&buf[off..], c2s, state, report);
            return;
        }
    }
}

fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let &b0 = b.first()?;
    let n = 1usize << (b0 >> 6);
    if b.len() < n {
        return None;
    }
    let mut v = (b0 & 0x3f) as u64;
    for &x in &b[1..n] {
        v = (v << 8) | x as u64;
    }
    Some((v, n))
}

fn unprotect_header(
    hp: &RingAesHp,
    packet: &[u8],
    pn_offset: usize,
    long_header: bool,
) -> Option<(u8, [u8; 4], usize)> {
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let mask = hp.new_mask(sample).ok()?;
    let mut b0 = packet[0];
    b0 ^= if long_header { mask[0] & 0x0f } else { mask[0] & 0x1f };
    let pn_len = (b0 & 0x03) as usize + 1;
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = *packet.get(pn_offset + i)? ^ mask[1 + i];
    }
    Some((b0, pn_bytes, pn_len))
}

fn aad_for(packet: &[u8], pn_offset: usize, pn_len: usize, b0: u8, pn_bytes: &[u8; 4]) -> Vec<u8> {
    let mut aad = packet[..pn_offset + pn_len].to_vec();
    aad[0] = b0;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes[..pn_len]);
    aad
}

fn reconstruct_pn(expected: u64, truncated: u64, bits: u32) -> u64 {
    let window = 1u64 << bits;
    let half = window >> 1;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half <= expected && candidate + window <= u64::MAX {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn truncated_to_u64(pn_bytes: &[u8; 4], pn_len: usize) -> u64 {
    pn_bytes.iter().take(pn_len).fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn analyze_long(
    packet: &[u8],
    pn_offset: usize,
    dcid: &[u8],
    version: u32,
    space: u8,
    c2s: bool,
    state: &mut State,
    report: &mut Report,
) {
    let _ = dcid;
    let label = if space == 0 { "initial" } else { "handshake" };
    let keys = if space == 0 {
        let Some(initial_dcid) = &state.initial_dcid else {
            report.long_failed += 1;
            println!("  {label} dir={}: no original DCID learned yet", dir(c2s));
            return;
        };
        let initial_secret = quic_kdf::derive_initial_secret(initial_dcid, version);
        let side = if c2s {
            quic_kdf::derive_client_initial_secret(&initial_secret)
        } else {
            quic_kdf::derive_server_initial_secret(&initial_secret)
        };
        side.ok().and_then(|s| DirectionKeys::from_secret(&s, version))
    } else {
        let name =
            if c2s { "CLIENT_HANDSHAKE_TRAFFIC_SECRET" } else { "SERVER_HANDSHAKE_TRAFFIC_SECRET" };
        state.secrets.get(name).and_then(|s| DirectionKeys::from_secret(s, version))
    };
    let Some(keys) = keys else {
        report.long_failed += 1;
        println!("  {label} dir={}: no key material (keylog missing?)", dir(c2s));
        return;
    };
    let Some((b0, pn_bytes, pn_len)) = unprotect_header(&keys.hp, packet, pn_offset, true) else {
        report.long_failed += 1;
        println!("  {label} dir={}: header-protection sample unavailable", dir(c2s));
        return;
    };
    let truncated = truncated_to_u64(&pn_bytes, pn_len);
    let expect = state.expect.entry((space, c2s)).or_insert(0);
    let pn = reconstruct_pn(*expect, truncated, (pn_len * 8) as u32);
    let mut body = packet[pn_offset + pn_len..].to_vec();
    let aad = aad_for(packet, pn_offset, pn_len, b0, &pn_bytes);
    match keys.open.open_with_u64_counter(pn, &aad, &mut body) {
        Ok(_) => {
            *expect = pn + 1;
            if space == 0 {
                report.initial_opened += 1;
            } else {
                report.handshake_opened += 1;
            }
            println!("  {label} dir={} pn={pn} opened rustls-aes128gcm (hp=rustls)", dir(c2s));
        }
        Err(_) => {
            report.long_failed += 1;
            println!("  {label} dir={} pn={truncated} FAILED rustls keys", dir(c2s));
        }
    }
}

fn analyze_short(packet: &[u8], c2s: bool, state: &mut State, report: &mut Report) {
    // The DCID on a short packet is the peer's SCID, learned from the peer's
    // long-header packets.
    let dcid_len = if c2s { state.server_scid_len } else { state.client_scid_len };
    let pn_offset = 1 + dcid_len;
    let dir_name = dir(c2s);
    let std_secret_name = if c2s { "CLIENT_TRAFFIC_SECRET_0" } else { "SERVER_TRAFFIC_SECRET_0" };
    let version = state.app_version.unwrap_or(QUIC_V1);
    let Some(std_keys) =
        state.secrets.get(std_secret_name).and_then(|s| DirectionKeys::from_secret(s, version))
    else {
        report.rtt_failed += 1;
        println!("  1rtt {dir_name}: no standard traffic secret in keylog");
        return;
    };
    // Header protection stays rustls-standard for both standard and private
    // payloads — that is part of the contract under test.
    let Some((b0, pn_bytes, pn_len)) = unprotect_header(&std_keys.hp, packet, pn_offset, false)
    else {
        report.shape_violations += 1;
        println!("  1rtt {dir_name}: cannot unprotect header");
        return;
    };
    if !(1..=4).contains(&pn_len) {
        report.shape_violations += 1;
    }
    let body = &packet[pn_offset + pn_len..];
    if body.len() < TAG_LEN {
        report.shape_violations += 1;
        println!("  1rtt {dir_name}: body shorter than tag");
        return;
    }
    let truncated = truncated_to_u64(&pn_bytes, pn_len);
    let expect = state.expect.entry((2, c2s)).or_insert(0);
    let pn = reconstruct_pn(*expect, truncated, (pn_len * 8) as u32);
    let aad = aad_for(packet, pn_offset, pn_len, b0, &pn_bytes);

    // Standard rustls owner first.
    {
        let mut buf = body.to_vec();
        if std_keys.open.open_with_u64_counter(pn, &aad, &mut buf).is_ok() {
            *expect = pn + 1;
            let (boundary, have_private) = if c2s {
                (state.private.c2s_boundary, state.private.c2s_key.is_some())
            } else {
                (state.private.s2c_boundary, state.private.s2c_key.is_some())
            };
            if have_private && boundary != 0 && pn >= boundary {
                report.rtt_standard_above_boundary += 1;
                println!(
                    "  1rtt {dir_name} pn={pn} opened STANDARD above boundary {boundary} (unexpected)"
                );
            } else {
                report.rtt_standard += 1;
                println!("  1rtt {dir_name} pn={pn} opened rustls-aes128gcm (hp=rustls)");
            }
            return;
        }
    }

    // Standard failed — the private contract requires exactly this, then the
    // negotiated owner must open it.
    let family = state.private.family.unwrap_or(PrivateAeadFamily::Aegis128L);
    let (key, iv, boundary) = if c2s {
        (&state.private.c2s_key, &state.private.c2s_iv, state.private.c2s_boundary)
    } else {
        (&state.private.s2c_key, &state.private.s2c_iv, state.private.s2c_boundary)
    };
    let mut opened_epoch: Option<u32> = None;
    if let (Some(k), Some(i)) = (key, iv) {
        if let Ok((_, priv_open)) = qf_crypto::select_private_packet_data_aead(family, k, i) {
            let mut buf = body.to_vec();
            if priv_open.open_with_u64_counter(pn, &aad, &mut buf).is_ok() {
                opened_epoch = Some(1);
            }
        }
    }
    // Key-phase updates rotate the private epoch: the dumped material is the
    // install epoch, so derive later epochs from the exporter-root schedule.
    if opened_epoch.is_none() {
        if let (Some(root), Some(ctx)) = (&state.private.schedule_root, &state.private.context_hash)
        {
            let dir_label: &[u8] = if c2s { b"client-write" } else { b"server-write" };
            for epoch in 2u32..=8 {
                let mut info = Vec::with_capacity(128);
                info.extend_from_slice(PRIVATE_EXPORTER_LABEL);
                info.push(family.protocol_id());
                info.extend_from_slice(dir_label);
                info.extend_from_slice(&epoch.to_be_bytes());
                info.extend_from_slice(ctx);
                let prk = qf_crypto::hkdf::hkdf_extract(PRIVATE_EXPORTER_SALT, root);
                let Ok(material) = qf_crypto::hkdf::hkdf_expand(
                    &prk,
                    &info,
                    PrivateAeadFamily::KEY_LEN + PrivateAeadFamily::IV_LEN,
                ) else {
                    continue;
                };
                let Ok((_, open)) = qf_crypto::select_private_packet_data_aead(
                    family,
                    &material[..PrivateAeadFamily::KEY_LEN],
                    &material[PrivateAeadFamily::KEY_LEN..],
                ) else {
                    continue;
                };
                let mut buf = body.to_vec();
                if open.open_with_u64_counter(pn, &aad, &mut buf).is_ok() {
                    opened_epoch = Some(epoch);
                    break;
                }
            }
        }
    }
    if let Some(epoch) = opened_epoch {
        *expect = pn + 1;
        report.rtt_private += 1;
        if boundary != 0 && pn < boundary {
            report.rtt_private_below_boundary += 1;
            println!(
                "  1rtt {dir_name} pn={pn} opened PRIVATE below boundary {boundary} (unexpected)"
            );
        } else if epoch > 1 {
            println!(
                "  1rtt {dir_name} pn={pn} FAILED rustls, opened private-{} epoch {epoch} (boundary {boundary})",
                family.as_str()
            );
        } else {
            println!(
                "  1rtt {dir_name} pn={pn} FAILED rustls, opened private-{} (boundary {boundary})",
                family.as_str()
            );
        }
        return;
    }
    // Last resort: a QUIC key update rotates the standard traffic secret —
    // including the header-protection key, so the packet number must be
    // re-decoded under the updated hp key.
    if let Some(secret) = state.secrets.get(std_secret_name) {
        let mut next = secret.to_vec();
        for hop in 1..=4u8 {
            let Ok(n) = quic_kdf::derive_next_secret_for_version(&next, version) else {
                break;
            };
            next = n;
            let Some(upd) = DirectionKeys::from_secret(&next, version) else { continue };
            let Some((b0u, pnb, pnl)) = unprotect_header(&upd.hp, packet, pn_offset, false) else {
                continue;
            };
            let trunc = truncated_to_u64(&pnb, pnl);
            let pnu = reconstruct_pn(*expect, trunc, (pnl * 8) as u32);
            let aadu = aad_for(packet, pn_offset, pnl, b0u, &pnb);
            let mut buf = body.to_vec();
            if upd.open.open_with_u64_counter(pnu, &aadu, &mut buf).is_ok() {
                *expect = pnu + 1;
                report.rtt_standard_above_boundary += 1;
                println!(
                    "  1rtt {dir_name} pn={pnu} opened STANDARD key-update hop {hop} (boundary-crossing?)"
                );
                return;
            }
        }
    }
    report.rtt_failed += 1;
    let key_phase = (b0 & 0x04) != 0;
    println!(
        "  1rtt {dir_name} pn={pn} failed every available key (b0={b0:02x} kp={key_phase} pn_len={pn_len} pkt_len={})",
        packet.len()
    );
}

fn dir(c2s: bool) -> &'static str {
    if c2s {
        "c2s"
    } else {
        "s2c"
    }
}
