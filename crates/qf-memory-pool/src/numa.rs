#[cfg(target_os = "linux")]
use qf_common::env_utils::EnvSnapshot;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub(super) enum NumaPolicy {
    Local,
    Preferred(usize),
    Interleave,
}

#[cfg(target_os = "linux")]
pub(super) static NUMA_POLICY: OnceLock<NumaPolicy> = OnceLock::new();

#[cfg(target_os = "linux")]
fn resolve_numa_policy_with_snapshot(environment: &EnvSnapshot) -> NumaPolicy {
    if let Some(value) = environment.first(["QUICFUSCATE_NUMA_POLICY"]) {
        let value = value.to_ascii_lowercase();
        if value == "local" {
            return NumaPolicy::Local;
        }
        if value == "interleave" {
            return NumaPolicy::Interleave;
        }
        if let Some(rest) = value.strip_prefix("preferred:") {
            if let Ok(node) = rest.parse::<usize>() {
                return NumaPolicy::Preferred(node);
            }
        }
    }
    NumaPolicy::Local
}

#[cfg(target_os = "linux")]
pub(super) fn initialize_numa_policy(environment: &EnvSnapshot) {
    NUMA_POLICY.get_or_init(|| resolve_numa_policy_with_snapshot(environment));
}

#[cfg(target_os = "linux")]
pub(super) static RR_NODE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(target_os = "linux")]
pub(super) fn is_available() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(super) fn num_nodes() -> usize {
    1
}

#[cfg(target_os = "linux")]
pub(super) fn current_node() -> usize {
    0
}

#[cfg(target_os = "linux")]
pub(super) fn move_to_node(_ptr: *mut u8, _size: usize, _node: usize) {}

/// Pure classification of Windows NUMA API results.
///
/// Split out from the FFI module so the decision logic is provable on a non-Windows workspace.
/// The Windows adapter owns the calls; this owns what their outputs mean.
#[cfg(any(target_os = "windows", test))]
mod numa_classification {
    /// Node count implied by a successful `GetNumaHighestNodeNumber`.
    pub(super) fn node_count_from_highest(highest_node: u32) -> usize {
        (highest_node as usize).saturating_add(1)
    }

    /// Whether a successful `GetNumaHighestNodeNumber` means NUMA is usable.
    pub(super) fn available_from_query(query_succeeded: bool) -> bool {
        query_succeeded
    }

    /// Node index implied by a `GetNumaProcessorNodeEx` result.
    pub(super) fn node_from_processor_result(query_succeeded: bool, node: u16) -> usize {
        if query_succeeded && node != u16::MAX {
            node as usize
        } else {
            0
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::numa_classification;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessorNumberEx, GetNumaHighestNodeNumber, GetNumaProcessorNodeEx,
    };

    static NUMA_NODES: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn is_available() -> bool {
        let mut highest_node = 0u32;
        let query_succeeded = unsafe { GetNumaHighestNodeNumber(&mut highest_node) } != 0;
        if query_succeeded {
            NUMA_NODES.store(
                numa_classification::node_count_from_highest(highest_node),
                Ordering::Relaxed,
            );
        }
        numa_classification::available_from_query(query_succeeded)
    }

    pub(super) fn num_nodes() -> usize {
        let nodes = NUMA_NODES.load(Ordering::Relaxed);
        if nodes > 0 {
            nodes
        } else if is_available() {
            NUMA_NODES.load(Ordering::Relaxed)
        } else {
            1
        }
    }

    pub(super) fn current_node() -> usize {
        let mut processor: PROCESSOR_NUMBER = unsafe { std::mem::zeroed() };
        unsafe { GetCurrentProcessorNumberEx(&mut processor) };
        let mut node = 0u16;
        let query_succeeded = unsafe { GetNumaProcessorNodeEx(&processor, &mut node) } != 0;
        numa_classification::node_from_processor_result(query_succeeded, node)
    }
}

#[cfg(target_os = "windows")]
pub(super) fn num_nodes() -> usize {
    windows::num_nodes()
}

#[cfg(target_os = "windows")]
pub(super) fn current_node() -> usize {
    windows::current_node()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn num_nodes() -> usize {
    1
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn current_node() -> usize {
    0
}

/// Proof for the Windows NUMA result classification.
///
/// Runs on every target. The FFI calls themselves are Windows-only and remain unproven here, but
/// what their outputs mean is decided by these pure functions and is provable anywhere.
#[cfg(test)]
mod numa_classification_tests {
    use super::numa_classification::*;

    #[test]
    fn single_node_topology_counts_as_available() {
        assert!(available_from_query(true), "a successful query means the topology is usable");
        assert_eq!(node_count_from_highest(0), 1, "highest node 0 means exactly one node");
        assert!(!available_from_query(false), "a failed query means unavailable");
    }

    #[test]
    fn node_count_is_one_more_than_the_highest_and_never_overflows() {
        assert_eq!(node_count_from_highest(1), 2);
        assert_eq!(node_count_from_highest(63), 64);
        assert_eq!(node_count_from_highest(u32::MAX), u32::MAX as usize + 1);
        assert!(node_count_from_highest(u32::MAX) > 0);
    }

    #[test]
    fn processor_node_result_honours_failure_and_the_no_node_sentinel() {
        assert_eq!(node_from_processor_result(true, 0), 0);
        assert_eq!(node_from_processor_result(true, 3), 3);
        assert_eq!(node_from_processor_result(true, u16::MAX), 0);
        assert_eq!(node_from_processor_result(false, 7), 0);
        assert_eq!(node_from_processor_result(false, u16::MAX), 0);
    }
}
