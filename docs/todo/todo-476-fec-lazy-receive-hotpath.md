# TODO-476: FEC Lazy Receive Hotpath and Bounded Clean-Block Tracking

## Status

DONE

## Motivation

`AdaptiveFec::on_receive()` called `InterleavedDecoder::get_result()` and `get_partial_result()` for every packet. In lazy mode this defeated the clean-link fast path because `LazyDecoder::get_result()` flushes pending repairs into the heavy decoder. The same lazy sequence tracker also retained clean source sequence numbers indefinitely, creating avoidable long-run memory and lookup cost on stable links.

## Implementation

- Added `LazyDecoder::recovery_needed()` and `InterleavedDecoder::recovery_needed()` so the receive path can avoid heavy recovery polling when no useful recovery work exists.
- Kept eager polling when `QUICFUSCATE_FEC_LAZY=0`, preserving explicit non-lazy behavior.
- Treated pending repairs as useful work when the current decoder block is incomplete, preserving tail-loss recovery where no later systematic packet can reveal a sequence gap.
- Pruned `seen_seqs` after clean complete blocks so the lazy tracker remains bounded during long no-loss sessions.
- Short-circuited `AdaptiveFec::on_receive()` to return systematic packets directly on clean lazy blocks, while still feeding the decoder for tracking.

## Verification

- Local:
  - `cargo test --lib -- internal::tests::test_lazy_decoder_buffers_repairs_until_loss internal::tests::test_lazy_decoder_flushes_on_gap internal::tests::test_lazy_decoder_prunes_clean_complete_blocks test_streaming_tetrys_style_recovery_single_loss test_streaming_tetrys_multi_loss_uniform_recovery test_streaming_tetrys_burst_loss_recovery test_fec_e2e_repair_packets_generated -- --nocapture`
  - `cargo bench --bench fec_pipeline --features benches fec_lazy_fast_path -- --sample-size 10 --warm-up-time 1 --measurement-time 2`
- Broderick:
  - `cargo test --lib -- internal::tests::test_lazy_decoder_prunes_clean_complete_blocks test_streaming_tetrys_style_recovery_single_loss test_streaming_tetrys_burst_loss_recovery -- --nocapture`
  - `cargo bench --bench fec_pipeline --features benches fec_lazy_fast_path -- --sample-size 10 --warm-up-time 1 --measurement-time 2`

## Results

- Broderick `fec_lazy_fast_path/zero_mode_passthrough`: improved from about `544 ns` to about `445 ns` (`~18%`).
- Broderick `fec_lazy_fast_path/normal_mode_no_loss`: no statistically significant change because the benchmark remains dominated by sender-side normal-mode work.
- Tail-loss and burst-loss recovery tests remain green.
