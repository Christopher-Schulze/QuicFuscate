pub mod options;

use options::{CommandLineOptions, FecCliMode, Fingerprint};
use core::{QuicConfig, QuicConnection};
use stealth::{
    BrowserProfile, QuicFuscateStealth, XORObfuscator, XORPattern,
};
use fec::{FECConfig, FECModule, FECPacket};

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

