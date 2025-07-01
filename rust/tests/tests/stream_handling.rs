use core::{QuicStreamOptimizer, StreamOptimizationConfig};

#[test]
fn priority_and_window() {
    let mut opt = QuicStreamOptimizer::new();
    let cfg = StreamOptimizationConfig;
    assert!(opt.initialize(cfg));
    assert!(opt.set_stream_priority(1, 10));
    assert!(opt.update_flow_control_window(1, 5000));
    assert!(opt.can_send_data(1, 1000));
    assert!(opt.get_optimal_chunk_size(1) > 0);
}
