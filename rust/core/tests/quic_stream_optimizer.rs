use core::{QuicStreamOptimizer, StreamOptimizationConfig};

#[test]
fn flow_control_allows_and_blocks() {
    let mut opt = QuicStreamOptimizer::new();
    opt.initialize(StreamOptimizationConfig);
    opt.set_stream_priority(1, 5);
    opt.update_flow_control_window(1, 1000);
    assert!(opt.can_send_data(1, 800));
    assert!(!opt.can_send_data(1, 1200));
    opt.update_flow_control_window(1, 2000);
    assert!(opt.can_send_data(1, 1200));
}

#[test]
fn priority_affects_chunk_size() {
    let mut opt = QuicStreamOptimizer::new();
    opt.initialize(StreamOptimizationConfig);
    opt.set_stream_priority(1, 1);
    opt.set_stream_priority(2, 10);
    opt.update_flow_control_window(1, 5000);
    opt.update_flow_control_window(2, 5000);
    let low = opt.get_optimal_chunk_size(1);
    let high = opt.get_optimal_chunk_size(2);
    assert!(high > low);
    assert!(low > 0);
    assert!(high > 0);
}
