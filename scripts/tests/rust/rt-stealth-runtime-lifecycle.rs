#![cfg(feature = "rust-tests")]

use quicfuscate::reality::RealityConfig;
use quicfuscate::stealth::StealthRuntimeOwner;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_cover_capture_worker_is_single_and_closes_socket_on_shutdown() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind local capture peer");
    let port = listener.local_addr().expect("read capture peer address").port();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (closed_tx, closed_rx) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept cover capture socket");
        let _ = accepted_tx.send(());
        let mut buffer = [0_u8; 4096];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    let _ = closed_tx.send(());
                    return;
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    let owner = Arc::new(
        StealthRuntimeOwner::new(RealityConfig {
            enabled: true,
            cover_host: "127.0.0.1".to_string(),
            cover_port: port,
            cache_ttl: 1,
            ..RealityConfig::default()
        })
        .expect("valid local Reality config"),
    );
    owner.start(None, Vec::new(), 0).expect("start one Reality worker");
    assert_eq!(owner.worker_count(), 1, "one owner must start one refresh worker");
    assert!(owner.start(None, Vec::new(), 0).is_err(), "a generation cannot start twice");

    tokio::time::timeout(Duration::from_secs(2), accepted_rx)
        .await
        .expect("capture worker must open the real local socket")
        .expect("capture peer must report acceptance");

    let report =
        tokio::time::timeout(Duration::from_secs(2), owner.shutdown(Duration::from_secs(1)))
            .await
            .expect("owner shutdown must be bounded")
            .expect("owner workers must join cleanly");
    assert_eq!(report.workers_joined, 1);
    assert_eq!(report.workers_force_stopped, 0);
    assert_eq!(owner.worker_count(), 0);

    tokio::time::timeout(Duration::from_secs(2), closed_rx)
        .await
        .expect("shutdown must close the real capture socket")
        .expect("capture peer must report socket closure");
    peer.await.expect("capture peer task must exit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_restart_uses_a_new_generation_without_old_workers() {
    let first =
        Arc::new(StealthRuntimeOwner::new(RealityConfig::default()).expect("default config"));
    first.start(None, Vec::new(), 0).expect("start first generation");
    let first_generation = first.generation();
    first.shutdown(Duration::from_secs(1)).await.expect("stop first generation");
    assert_eq!(first.worker_count(), 0);

    let second =
        Arc::new(StealthRuntimeOwner::new(RealityConfig::default()).expect("default config"));
    assert!(second.generation() > first_generation);
    second.start(None, Vec::new(), 0).expect("start second generation");
    assert_eq!(second.worker_count(), 0);
    second.shutdown(Duration::from_secs(1)).await.expect("stop second generation");
    assert_eq!(second.worker_count(), 0);
}
