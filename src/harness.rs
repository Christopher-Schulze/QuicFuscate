//! Compatibility surface for the standalone developer harness.

use clap::Parser;
use std::net::SocketAddr;

pub use qf_harness::{
    Cli, Command, PacketProtectionReport, QpackEncoder, UdpSender, UdpSenderFactory,
};

struct RootUdpSender(crate::transport::udpfast::UdpFastPath);

impl UdpSender for RootUdpSender {
    fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
        self.0.send_batch(packets)
    }
}

fn qpack_encode(input: &[u8], output: &mut [u8]) -> usize {
    crate::simd::h3::qpack_encode(input, output)
}

fn udp_sender_factory(bind: SocketAddr) -> std::io::Result<Box<dyn UdpSender>> {
    let sender = crate::transport::udpfast::UdpFastPath::new(bind)?;
    Ok(Box::new(RootUdpSender(sender)))
}

/// Format the effective packet-protection owners of one live connection for the developer harness.
pub fn packet_protection_report(snapshot: crate::qftls::PacketProtectionSnapshot) -> String {
    qf_harness::format_packet_protection_report(PacketProtectionReport {
        initial_packet_owner: snapshot.initial.packet_aead_owner.as_str(),
        initial_header_owner: snapshot.initial.header_protection_owner.as_str(),
        handshake_packet_owner: snapshot.handshake.packet_aead_owner.as_str(),
        handshake_header_owner: snapshot.handshake.header_protection_owner.as_str(),
        zero_rtt_packet_owner: snapshot.zero_rtt.packet_aead_owner.as_str(),
        zero_rtt_header_owner: snapshot.zero_rtt.header_protection_owner.as_str(),
        one_rtt_packet_owner: snapshot.one_rtt.packet_aead_owner.as_str(),
        one_rtt_header_owner: snapshot.one_rtt.header_protection_owner.as_str(),
        negotiated_standard_suite: snapshot
            .negotiated_tls_cipher_suite
            .map_or("none", crate::qftls::StandardCipherSuite::as_str),
    })
}

pub fn run_cli(cli: Cli) {
    qf_harness::run_cli(cli, qpack_encode, udp_sender_factory);
}

pub fn run_from_args<I>(args: I)
where
    I: IntoIterator<Item = String>,
{
    run_cli(Cli::parse_from(args));
}

pub fn run_from_env() {
    run_cli(Cli::parse());
}
