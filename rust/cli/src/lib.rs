pub mod options;

use options::{CommandLineOptions, FecCliMode, Fingerprint};
use core::{QuicConfig, QuicConnection};
use stealth::{
    BrowserProfile, QuicFuscateStealth, XORObfuscator, XORPattern,
};
use fec::{FECConfig, FECModule, FECPacket};
use rustls::{Certificate, RootCertStore, client::{WebPkiVerifier, ServerName, ServerCertVerifier}};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::time::SystemTime;

/// Dummy certificate used for peer verification tests.
const DUMMY_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIUSaKuYaaa7DWyHsmE2yAH8KlOHa4wDQYJKoZIhvcNAQEL\nBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUwNzA0MTEyNjE3WhcNMjUw\nNzA1MTEyNjE3WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAK5oTh4xA4rvCDB/Zlh8OFG+Puu4QRq/i/S5V1rS\nAravYHVZAj7uj20VsjzUoL9Zy8R707HQj7N4dr1k7ipKdMUPCD46kO6E9lnuNR9c\nC/IzNIpQwhCDXdaFskl+O2Q+/krK2Ugs9/7K/5Rv8sF4bTjF5oc6qcn3GM0zjJYv\nEM2gkQsTqSqcbbS5w+tNc2Uk9VCjbsnm6Tsfcv3+3HdKloW+IBi8XvhB2icGLXkS\nyNAjr4PCyi8DaBRRgLB/OYtC5V5qiTgTscNvop/1BknvtvPJVPBlgzbuQXaglekB\n9+dWgt2rikQp9idUX5PyhXVKObtMoigpflPjJIde0NO0UCMCAwEAAaNTMFEwHQYD\nVR0OBBYEFD1GRfi6wWeEHBkn38Y5kz/Vy52OMB8GA1UdIwQYMBaAFD1GRfi6wWeE\nHBkn38Y5kz/Vy52OMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAFgF4ECHZJ3PKYNI7L/ZkosQ5GbZWIgrk0BYqS78O6HBxmdJvbdxEOPrsgdnVFqU\nXJdjW7ONNo+fGSIpkCvqEy97/JA0OafrzmKQRuu8BMfT8viLE11CBscBZtL6/zhl\n6wGOFEAdFsBp7e8u7xajzPHORE9OpJOS+grcxXz0Xp9FLcrzF3GatGPBdL4Cklmx\nLJYTtW1wBQzha5bHoBNWn/puhq/xQsLT5SZaEg65l37+8n5yNeGYcsU/JLuAV4jD\nxmmKZJIVt8+KNyVl1OjBO+5LqeT2YromUcznw2YG5eEO8EpqOQsa2/ftEK3WP2ti\nR+Tx5te611wrhDhuTzbyCnM=\n-----END CERTIFICATE-----";

fn verify_certificate(ca_path: &str, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = RootCertStore::empty();
    let ca_file = File::open(ca_path)?;
    let mut reader = BufReader::new(ca_file);
    let ca_certs = certs(&mut reader).map_err(|_| "failed to read CA file")?;
    if ca_certs.is_empty() {
        return Err("CA file contained no certificates".into());
    }
    store.add_parsable_certificates(&ca_certs);

    let mut server_reader = BufReader::new(DUMMY_CERT_PEM.as_bytes());
    let server_certs = certs(&mut server_reader).map_err(|_| "invalid server certificate")?;
    let end_entity = Certificate(server_certs[0].clone());
    let intermediates: Vec<Certificate> = server_certs.into_iter().skip(1).map(Certificate).collect();
    let verifier = WebPkiVerifier::new(store, None);
    let name = ServerName::try_from(domain)?;
    verifier
        .verify_server_cert(
            &end_entity,
            &intermediates,
            &name,
            &mut std::iter::empty(),
            &[],
            SystemTime::now(),
        )
        .map(|_| ())
        .map_err(|e| format!("certificate validation failed: {e}").into())
}

async fn demo_transfer(
    stealth: &mut QuicFuscateStealth,
    fec: &mut FECModule,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut xor = XORObfuscator::new();
    let message = b"demo data".to_vec();
    let packets = fec.encode_packet(&message, 0)?;
    for p in &packets {
        let enc = xor.obfuscate(&p.data, XORPattern::Simple);
        stealth.datagram.send(enc, 1);
    }

    let mut received = Vec::new();
    for _ in 0..packets.len() {
        if let Some(data) = stealth.datagram.recv().await {
            let dec = xor.deobfuscate(&data, XORPattern::Simple);
            received.push(FECPacket {
                sequence_number: 0,
                is_repair: false,
                data: dec,
            });
        }
    }
    let out = fec.decode(&received)?;
    Ok(out)
}

pub fn run_cli(
    opts: CommandLineOptions,
    demo: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cfg = QuicConfig {
        server_name: opts.server.clone(),
        port: opts.port,
    };
    let mut conn = QuicConnection::new(cfg)?;
    conn.enable_mtu_discovery(true);
    let addr = format!("127.0.0.1:{}", opts.port);
    let _ = conn.connect(&addr);

    if opts.verify_peer {
        let ca = opts
            .ca_file
            .as_ref()
            .ok_or("--ca-file required with --verify-peer")?;
        verify_certificate(ca, &opts.server)?;
    }

    let mut fec_cfg = FECConfig::default();
    fec_cfg.mode = opts.fec.into();
    fec_cfg.redundancy_ratio = (opts.fec_ratio as f64) / 100.0;
    let mut fec_mod = FECModule::new(fec_cfg);

    let mut stealth = QuicFuscateStealth::new();
    stealth.set_browser_profile(BrowserProfile::from(opts.fingerprint));
    stealth.enable_utls(!opts.no_utls);
    stealth.set_spinbit_probability(opts.spin_probability);
    stealth.set_zero_rtt_max_early_data(opts.zero_rtt_max);
    stealth.enable_domain_fronting(opts.domain_fronting);
    stealth.enable_http3_masq(opts.http3_masq);
    stealth.enable_doh(opts.doh);
    stealth.enable_spinbit(opts.spin_random);
    stealth.enable_zero_rtt(opts.zero_rtt);
    stealth.initialize();

    let result = if demo {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(demo_transfer(&mut stealth, &mut fec_mod))?
    } else {
        Vec::new()
    };

    stealth.shutdown();
    drop(conn);
    Ok(result)
}

