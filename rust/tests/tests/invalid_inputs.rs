use fec::{FECModule, FECConfig};
use stealth::stream::{StreamEngine, StreamError};
use tokio::runtime::Runtime;

#[test]
fn fec_decode_empty_slice() {
    let module = FECModule::new(FECConfig::default());
    let result = module.decode(&[]).expect("decode should succeed");
    assert!(result.is_empty());
}

#[test]
fn stream_recv_no_data() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let mut engine = StreamEngine::new();
        match engine.recv().await {
            Err(StreamError::NoData) => (),
            other => panic!("unexpected result: {:?}", other),
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
