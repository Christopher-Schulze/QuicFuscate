//! Compatibility surface for the standalone developer harness.

use clap::Parser;
use std::net::SocketAddr;

pub use qf_harness::{Cli, Command, QpackEncoder, UdpSender, UdpSenderFactory};

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
