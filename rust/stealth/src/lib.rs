pub mod qpack;
pub mod zero_rtt;
pub mod datagram;
pub mod stream;
pub mod spinbit;
pub mod xor;
pub mod browser;
pub mod doh;
pub mod domain_fronting;
pub mod fake_tls;
pub mod http3_masq;

pub use xor::{XORObfuscator, XORPattern};
pub use browser::{BrowserFingerprint, BrowserType, OperatingSystem, BrowserProfile};
use qpack::QpackEngine;
use zero_rtt::ZeroRttEngine;
use datagram::DatagramEngine;
use stream::StreamEngine;
use spinbit::SpinBitRandomizer;

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
