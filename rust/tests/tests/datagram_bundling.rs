use stealth::datagram::DatagramEngine;
use tokio::runtime::Runtime;

#[test]
fn bundling_flushes_after_queue_limit() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut eng = DatagramEngine::new();
        eng.enable_bundling(true);
        for i in 0..11 {
            eng.send(vec![i as u8], 1);
        }
        // sending more than the internal limit should trigger a flush
        assert!(eng.recv().await.is_some());
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn recv_returns_none_when_empty() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut eng = DatagramEngine::new();
        assert_eq!(eng.recv().await, None);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
