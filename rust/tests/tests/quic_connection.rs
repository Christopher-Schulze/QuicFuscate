use core::{IoContext, QuicConfig, QuicConnection};

#[test]
fn constructible() {
    let ctx = IoContext;
    let cfg = QuicConfig;
    let _conn = QuicConnection::new(&ctx, cfg);
}
