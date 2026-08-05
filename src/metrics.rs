use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_CONCURRENT_METRICS_CONNECTIONS: usize = 32;

async fn handle_connection(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
    {
        Ok(Ok(0)) => return,
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            log::debug!("Telemetry request read failed: {}", e);
            return;
        }
        Err(_) => return,
    };
    let req = &buf[..n];
    if is_telemetry_request(req) {
        let body = crate::telemetry::export_telemetry_text();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        if let Err(e) = stream.write_all(resp.as_bytes()).await {
            log::debug!("Telemetry response write failed: {}", e);
        }
    } else {
        let body = "Not Found";
        let resp = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        if let Err(e) = stream.write_all(resp.as_bytes()).await {
            log::debug!("Telemetry 404 write failed: {}", e);
        }
    }
    if let Err(e) = stream.shutdown().await {
        log::debug!("Telemetry socket shutdown failed: {}", e);
    }
}

/// Check if a raw HTTP request targets the /telemetry endpoint.
fn is_telemetry_request(req: &[u8]) -> bool {
    req.starts_with(b"GET /telemetry")
}

/// Spawn a minimal HTTP server that exposes a telemetry snapshot on /telemetry.
/// Address is taken from QUICFUSCATE_METRICS_ADDR (default 127.0.0.1:9898).
pub fn spawn_telemetry_server() {
    let environment = crate::env_utils::EnvSnapshot::capture();
    let addr =
        environment.first(["QUICFUSCATE_METRICS_ADDR"]).unwrap_or_else(|| "127.0.0.1:9898".into());
    tokio::spawn(async move {
        let semaphore =
            std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_METRICS_CONNECTIONS));
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                log::info!("Telemetry server listening on {} at /telemetry", addr);
                loop {
                    match listener.accept().await {
                        Ok((stream, _peer)) => {
                            let permit = match semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    drop(stream);
                                    continue;
                                }
                            };
                            tokio::spawn(async move {
                                handle_connection(stream).await;
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            log::warn!("Metrics accept error: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to bind metrics server on {}: {}", addr, e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_request_match() {
        assert!(is_telemetry_request(b"GET /telemetry HTTP/1.1\r\n"));
        assert!(is_telemetry_request(b"GET /telemetry"));
        assert!(is_telemetry_request(b"GET /telemetry "));
        assert!(is_telemetry_request(b"GET /telemetry?format=json HTTP/1.1\r\n"));
    }

    #[test]
    fn non_telemetry_request_rejected() {
        assert!(!is_telemetry_request(b"GET / HTTP/1.1\r\n"));
        assert!(!is_telemetry_request(b"GET /metrics HTTP/1.1\r\n"));
        assert!(!is_telemetry_request(b"POST /telemetry HTTP/1.1\r\n"));
        assert!(!is_telemetry_request(b""));
        assert!(!is_telemetry_request(b"GET /telemetr"));
    }

    #[test]
    fn default_metrics_addr() {
        let addr = std::env::var("QUICFUSCATE_METRICS_ADDR_NOEXIST")
            .unwrap_or_else(|_| "127.0.0.1:9898".into());
        assert_eq!(addr, "127.0.0.1:9898");
    }

    #[test]
    fn custom_metrics_addr() {
        let _env_lock = crate::env_utils::test_support::acquire_env_lock();
        let key = "QUICFUSCATE_METRICS_ADDR_TEST_CUSTOM";
        std::env::set_var(key, "0.0.0.0:1234");
        let addr = std::env::var(key).unwrap_or_else(|_| "127.0.0.1:9898".into());
        assert_eq!(addr, "0.0.0.0:1234");
        std::env::remove_var(key);
    }
}
