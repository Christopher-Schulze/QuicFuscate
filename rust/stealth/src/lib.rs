pub mod qpack;
pub mod zero_rtt;
pub mod datagram;
pub mod stream;
pub mod spinbit;
pub mod xor;
pub mod browser;
pub mod http3_masq;

pub struct QuicFuscateStealth;

impl QuicFuscateStealth {
    pub fn new() -> Self {
        Self
    }

    pub fn initialize(&self) -> bool {
        true
    }

    pub fn shutdown(&self) {}
}
