use super::*;

#[test]
fn test_decay_histogram_half_decay_floors_correctly() {
    let mut bins = vec![100, 201, 50, 1, 0, 999];
    decay_histogram(&mut bins, 0.5);
    assert_eq!(bins, vec![50, 100, 25, 0, 0, 499]);
}

#[test]
fn test_decay_histogram_decay_one_is_noop() {
    let original = vec![10, 20, 30, 40, 50];
    let mut bins = original.clone();
    decay_histogram(&mut bins, 1.0);
    assert_eq!(bins, original);
}

#[test]
fn test_decay_histogram_decay_zero_clears_all() {
    let mut bins = vec![100, 200, 300, u64::MAX];
    decay_histogram(&mut bins, 0.0);
    assert_eq!(bins, vec![0, 0, 0, 0]);
}

#[test]
fn test_decay_histogram_negative_decay_clamps_to_zero() {
    let mut bins = vec![42, 99];
    decay_histogram(&mut bins, -5.0);
    assert_eq!(bins, vec![0, 0]);
}

#[test]
fn test_decay_histogram_above_one_clamps_to_noop() {
    let original = vec![7, 13, 255];
    let mut bins = original.clone();
    decay_histogram(&mut bins, 2.5);
    assert_eq!(bins, original);
}

#[test]
fn test_decay_histogram_empty_slice() {
    let mut bins: Vec<u64> = Vec::new();
    decay_histogram(&mut bins, 0.5);
    assert!(bins.is_empty());
}

#[test]
fn test_decay_histogram_single_element() {
    let mut bins = vec![7];
    decay_histogram(&mut bins, 0.9);
    assert_eq!(bins, vec![6]);
}

#[test]
fn test_decay_histogram_large_vector_consistency() {
    for len in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33] {
        let mut bins: Vec<u64> = (1..=len as u64).collect();
        let mut expected = bins.clone();
        let decay = 0.75;
        for bin in &mut expected {
            *bin = ((*bin as f64) * decay).floor() as u64;
        }
        decay_histogram(&mut bins, decay);
        assert_eq!(bins, expected, "mismatch at len={len}");
    }
}

#[test]
fn test_decay_histogram_matches_scalar_across_u64_range() {
    let original = vec![
        0,
        1,
        u32::MAX as u64,
        1u64 << 32,
        (1u64 << 53) - 1,
        1u64 << 53,
        (1u64 << 53) + 1,
        (1u64 << 63) - 1,
        1u64 << 63,
        u64::MAX - 1,
        u64::MAX,
    ];

    for decay in [0.5, 0.75, f64::from_bits(1.0f64.to_bits() - 1)] {
        let expected: Vec<u64> =
            original.iter().map(|&bin| ((bin as f64) * decay).floor() as u64).collect();
        let mut actual = original.clone();
        decay_histogram(&mut actual, decay);
        assert_eq!(actual, expected, "mismatch for decay={decay}");
    }
}

#[test]
fn test_jsd_identical_distributions_is_zero() {
    let bins = vec![25, 25, 25, 25];
    let target = vec![0.25, 0.25, 0.25, 0.25];
    let jsd = jensen_shannon_divergence(&bins, 100, &target);
    assert!(jsd.abs() < 1e-6, "JSD of identical distributions should be ~0, got {jsd}");
}

#[test]
fn test_jsd_completely_different_distributions() {
    let bins = vec![1000, 0, 0, 0];
    let target = vec![0.25, 0.25, 0.25, 0.25];
    let jsd = jensen_shannon_divergence(&bins, 1000, &target);
    assert!(jsd > 0.0, "JSD of different distributions must be > 0");
    assert!(jsd <= 0.7, "JSD must be <= ln(2), got {jsd}");
}

#[test]
fn test_jsd_empty_bins_returns_zero() {
    let bins: Vec<u64> = Vec::new();
    let target: Vec<f64> = Vec::new();
    assert_eq!(jensen_shannon_divergence(&bins, 0, &target), 0.0);
}

#[test]
fn test_jsd_zero_total_returns_zero() {
    let bins = vec![0, 0, 0];
    let target = vec![0.33, 0.33, 0.34];
    assert_eq!(jensen_shannon_divergence(&bins, 0, &target), 0.0);
}

#[test]
fn test_jsd_mismatched_lengths_uses_minimum() {
    let bins = vec![50, 50];
    let target = vec![0.5, 0.5, 0.0, 0.0];
    let jsd = jensen_shannon_divergence(&bins, 100, &target);
    assert!(jsd.abs() < 1e-6, "JSD of matching 2-bin dists should be ~0, got {jsd}");
}

#[test]
fn test_scalar_jsd_symmetry_property() {
    let bins_a = vec![60, 30, 10];
    let target_a = vec![0.1, 0.3, 0.6];
    let jsd_forward = scalar_jensen_shannon(&bins_a, 100, &target_a);
    let bins_b = vec![10, 30, 60];
    let target_b = vec![0.6, 0.3, 0.1];
    let jsd_reverse = scalar_jensen_shannon(&bins_b, 100, &target_b);
    assert!(
        (jsd_forward - jsd_reverse).abs() < 1e-10,
        "JSD must be symmetric: forward={jsd_forward}, reverse={jsd_reverse}"
    );
}

#[test]
fn test_moving_average_simple_window() {
    let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
    let result = moving_average(&data, 3);
    let expected = [1.0, 1.5, 2.0, 3.0, 4.0];
    assert_eq!(result.len(), expected.len());
    for (index, (&actual, &expected)) in result.iter().zip(expected.iter()).enumerate() {
        assert!(
            (actual - expected).abs() < 1e-5,
            "moving_average[{index}]: got {actual}, expected {expected}"
        );
    }
}

#[test]
fn test_moving_average_window_one_returns_identity() {
    let data = vec![5.0, 3.0, 8.0, 1.0];
    let result = moving_average(&data, 1);
    for (index, (&actual, &expected)) in result.iter().zip(data.iter()).enumerate() {
        assert!(
            (actual - expected).abs() < 1e-5,
            "window=1 should return identity at [{index}]: got {actual}, expected {expected}"
        );
    }
}

#[test]
fn test_moving_average_window_equals_length() {
    let data = vec![2.0, 4.0, 6.0];
    let result = moving_average(&data, 3);
    let expected = [2.0, 3.0, 4.0];
    for (index, (&actual, &expected)) in result.iter().zip(expected.iter()).enumerate() {
        assert!(
            (actual - expected).abs() < 1e-5,
            "moving_average window==len [{index}]: got {actual}, expected {expected}"
        );
    }
}

#[test]
fn test_moving_average_window_exceeds_length() {
    let result = moving_average(&[10.0, 20.0], 100);
    assert_eq!(result.len(), 2);
    assert!((result[0] - 10.0).abs() < 1e-5);
    assert!((result[1] - 15.0).abs() < 1e-5);
}

#[test]
fn test_moving_average_empty_data() {
    assert!(moving_average(&[], 5).is_empty());
}

#[test]
fn test_moving_average_window_zero_clamps_to_one() {
    let result = moving_average(&[1.0, 2.0, 3.0], 0);
    assert_eq!(result.len(), 3);
    assert!((result[0] - 1.0).abs() < 1e-6);
}

#[test]
fn test_compute_percentile_median() {
    let mut data = vec![5.0, 1.0, 3.0, 9.0, 7.0];
    let p50 = compute_percentile(&mut data, 50.0);
    assert!((p50 - 5.0).abs() < 1e-5, "50th percentile should be 5.0, got {p50}");
}

#[test]
fn test_compute_percentile_zero_returns_minimum() {
    let mut data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
    let p0 = compute_percentile(&mut data, 0.0);
    assert!((p0 - 10.0).abs() < 1e-5, "0th percentile should be min, got {p0}");
}

#[test]
fn test_compute_percentile_high() {
    let mut data: Vec<f32> = (1..=100).map(|value| value as f32).collect();
    let p99 = compute_percentile(&mut data, 99.0);
    assert!((p99 - 100.0).abs() < 1e-5, "99th percentile should be 100.0, got {p99}");
}

#[test]
fn test_compute_percentile_invalid_input_fails_closed_without_mutation() {
    for percentile in [-1.0, 100.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut data = vec![10.0, 20.0, 30.0];
        let original = data.clone();
        assert_eq!(compute_percentile(&mut data, percentile), 0.0);
        assert_eq!(data, original, "invalid percentile must not mutate input");
    }
}

#[test]
fn test_compute_percentile_hundred_returns_maximum() {
    let mut data = vec![5.0, 1.0, 3.0, 9.0, 7.0];
    assert_eq!(compute_percentile(&mut data, 100.0), 9.0);
}

#[test]
fn test_relu_batch_clamps_negatives_to_zero() {
    let mut data = vec![-3.0, -1.0, 0.0, 1.0, 5.0, -0.001];
    relu_batch(&mut data);
    assert_eq!(data, vec![0.0, 0.0, 0.0, 1.0, 5.0, 0.0]);
}

#[test]
fn test_relu_batch_all_positive_unchanged() {
    let mut data = vec![1.0, 2.5, 100.0, 0.001];
    let original = data.clone();
    relu_batch(&mut data);
    assert_eq!(data, original);
}

#[test]
fn test_relu_batch_empty() {
    let mut data = Vec::new();
    relu_batch(&mut data);
    assert!(data.is_empty());
}

#[test]
fn test_relu_batch_various_lengths() {
    for len in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
        let mut data: Vec<f32> = (0..len).map(|index| index as f32 - len as f32 / 2.0).collect();
        relu_batch(&mut data);
        for (index, &actual) in data.iter().enumerate() {
            let expected = (index as f32 - len as f32 / 2.0).max(0.0);
            assert!(
                (actual - expected).abs() < 1e-5,
                "relu len={len} [{index}]: got {actual}, expected {expected}"
            );
        }
    }
}

#[test]
fn test_softmax_batch_sums_to_one() {
    let mut data = vec![1.0, 2.0, 3.0, 4.0];
    softmax_batch(&mut data);
    let sum: f32 = data.iter().sum();
    assert!((sum - 1.0).abs() < 1e-4, "softmax output should sum to 1.0, got {sum}");
}

#[test]
fn test_softmax_batch_monotonic_ordering() {
    let mut data = vec![1.0, 2.0, 3.0];
    softmax_batch(&mut data);
    assert!(data[0] < data[1], "softmax should preserve ordering");
    assert!(data[1] < data[2], "softmax should preserve ordering");
}

#[test]
fn test_softmax_batch_all_equal_yields_uniform() {
    let mut data = vec![5.0, 5.0, 5.0, 5.0];
    softmax_batch(&mut data);
    for (index, &value) in data.iter().enumerate() {
        assert!(
            (value - 0.25).abs() < 1e-4,
            "softmax of equal inputs should be uniform: [{index}]={value}"
        );
    }
}

#[test]
fn test_softmax_batch_all_outputs_non_negative() {
    let mut data = vec![-10.0, -5.0, 0.0, 5.0, 10.0];
    softmax_batch(&mut data);
    for (index, &value) in data.iter().enumerate() {
        assert!(value >= 0.0, "softmax output must be >= 0: [{index}]={value}");
    }
}

#[test]
fn test_softmax_batch_single_element() {
    let mut data = vec![42.0];
    softmax_batch(&mut data);
    assert!((data[0] - 1.0).abs() < 1e-5, "softmax of one element should be 1.0");
}

#[test]
fn test_softmax_batch_empty() {
    let mut data = Vec::new();
    softmax_batch(&mut data);
    assert!(data.is_empty());
}

#[test]
fn test_softmax_scalar_matches_definition() {
    let mut data = vec![1.0f32, 2.0, 3.0];
    softmax_scalar(&mut data);
    let max = 3.0f32;
    let e0 = (1.0 - max).exp();
    let e1 = (2.0 - max).exp();
    let e2 = (3.0 - max).exp();
    let sum = e0 + e1 + e2;
    let expected = [e0 / sum, e1 / sum, e2 / sum];
    for (index, (&actual, &expected)) in data.iter().zip(expected.iter()).enumerate() {
        assert!(
            (actual - expected).abs() < 1e-5,
            "softmax_scalar[{index}]: got {actual}, expected {expected}"
        );
    }
}
