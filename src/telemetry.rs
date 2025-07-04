use lazy_static::lazy_static;
use prometheus::{IntCounter, Encoder, TextEncoder, register_int_counter};
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};

lazy_static! {
    pub static ref OBFUSCATED_PACKETS: IntCounter =
        register_int_counter!("obfuscated_packets_total", "Number of obfuscated packets").unwrap();
    pub static ref DNS_QUERIES: IntCounter =
        register_int_counter!("dns_queries_total", "Number of DNS queries via DoH").unwrap();
}

async fn metrics_handler(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    Ok(Response::builder()
        .status(200)
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap())
}

pub fn start_exporter(addr: SocketAddr) {
    tokio::spawn(async move {
        let make_svc = make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(metrics_handler))
        });
        if let Err(e) = Server::bind(&addr).serve(make_svc).await {
            eprintln!("Prometheus exporter failed: {}", e);
        }
    });
}

