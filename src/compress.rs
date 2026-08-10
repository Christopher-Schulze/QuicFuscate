//! Compatibility projection for the standalone compression workspace leaf.

pub use qf_compress::{
    body_pool, classify_content_type, compress_with_dict, decompress_with_dict, get_dict,
    get_dict_by_id, global_policy, maybe_train, mime_matches, set_current_persona,
    set_global_policy, submit_sample, CompressionAnalysis, CompressionConfig, CompressionManager,
    CompressionPolicy, ContentClass,
};

pub(crate) fn global_policy_with_snapshot(
    environment: &qf_common::env_utils::EnvSnapshot,
) -> CompressionPolicy {
    qf_compress::global_policy_with_snapshot(environment)
}
