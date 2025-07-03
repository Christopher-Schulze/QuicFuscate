pub mod browser;
pub mod datagram;
pub mod doh;
pub mod domain_fronting;
pub mod fake_tls;
pub mod http3_masq;
pub mod qpack;
pub mod spinbit;
pub mod stream;
pub mod xor;
pub mod zero_rtt;

pub use browser::{BrowserFingerprint, BrowserProfile, BrowserType, OperatingSystem};
use datagram::DatagramEngine;
use qpack::QpackEngine;
use spinbit::SpinBitRandomizer;
use stream::StreamEngine;
pub use xor::{XORConfig, XORObfuscator, XORPattern};
use zero_rtt::ZeroRttEngine;

pub struct QuicFuscateStealth {
    pub qpack: QpackEngine,
    pub zero_rtt: ZeroRttEngine,
    pub datagram: DatagramEngine,
    pub stream: StreamEngine,
    pub spin: SpinBitRandomizer,
}

impl QuicFuscateStealth {
    pub fn new() -> Self {
        Self {
            qpack: QpackEngine::new(),
            zero_rtt: ZeroRttEngine::new(),
            datagram: DatagramEngine::new(),
            stream: StreamEngine::new(),
            spin: SpinBitRandomizer::new(),
        }
    }

    pub fn initialize(&self) -> bool {
        true
    }

    pub fn shutdown(&self) {}

    pub fn randomize_spinbit(&self, bit: bool) -> bool {
        self.spin.randomize(bit)
    }
}
