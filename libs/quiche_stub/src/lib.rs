pub struct Connection;

pub struct Config;

pub mod h3 {
    pub struct Header;
    pub const APPLICATION_PROTOCOL: &[u8] = b"h3";
    impl Header {
        pub fn new(_n: &[u8], _v: &[u8]) -> Self { Header }
    }
}

pub enum CongestionControlAlgorithm { BBRv2 }
impl Config {
    pub fn set_cc_algorithm(&mut self, _a: CongestionControlAlgorithm) {}
    pub fn enable_mtu_probing(&mut self) {}
}

pub struct ConnectionId;
impl ConnectionId {
    pub fn from_ref(_b: &[u8]) -> Self { ConnectionId }
}

pub const MAX_CONN_ID_LEN: usize = 20;

pub mod PathEvent { pub struct New(pub std::net::SocketAddr); pub struct Validated(pub std::net::SocketAddr); pub struct Closed(pub std::net::SocketAddr, pub u32); pub struct Reused(pub std::net::SocketAddr); pub struct Available(pub std::net::SocketAddr); }

pub enum Cipher { TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256, ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 }

impl Connection {
    pub fn stats(&self) {}
    pub fn path_event_next(&mut self) -> Option<PathEvent::New> { None }
    pub fn on_validation(&mut self, _pe: PathEvent::New) {}
}

pub fn connect(_s: Option<&str>, _cid: &ConnectionId, _l: std::net::SocketAddr, _r: std::net::SocketAddr, _c: &mut Config) -> Result<Connection, ()> { Ok(Connection) }

pub fn accept(_cid: &ConnectionId, _odcid: Option<&ConnectionId>, _l: std::net::SocketAddr, _r: std::net::SocketAddr, _c: &mut Config) -> Result<Connection, ()> { Ok(Connection) }
