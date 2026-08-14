use super::*;

#[test]
fn test_drop_error_display() {
    assert!(format!("{}", DropError::UserNotFound("foo".into())).contains("foo"));
    assert!(format!("{}", DropError::UnsafeTarget("root".into())).contains("root"));
    assert!(format!("{}", DropError::NotSupported).contains("not supported"));
}

#[test]
fn partial_transition_error_preserves_state_and_operation() {
    let error = partial_transition_error(
        PrivilegeTransitionState::GroupIdsChanged,
        "setuid",
        DropError::SystemCallFailed { operation: "setuid", errno: libc::EPERM },
    );

    assert!(matches!(
        &error,
        DropError::PartialTransition { state, operation, detail }
            if *state == PrivilegeTransitionState::GroupIdsChanged
                && *operation == "setuid"
                && detail.contains("errno")
    ));
    assert!(format!("{error}").contains("partial"));
}

#[test]
fn test_capability_report_construction() {
    let report = CapabilityReport::unavailable();
    assert!(!report.is_root);
    assert!(!report.can_drop);
}

#[cfg(unix)]
#[test]
fn numeric_identity_selectors_never_fallback_to_names() {
    assert_eq!(parse_numeric_selector("123", "user").unwrap(), Some(123));
    assert_eq!(parse_numeric_selector("alice", "user").unwrap(), None);
    assert!(parse_numeric_selector("", "user").is_err());
}

#[cfg(unix)]
#[test]
fn lookup_buffer_rejects_nonzero_status_before_extraction() {
    let result =
        lookup_buffer::<u32>("status-failure", |_output, _buffer, _len, _result| libc::EIO);

    assert!(matches!(
        result,
        Err(DropError::AccountLookupFailed { errno, .. }) if errno == libc::EIO
    ));
}

#[cfg(unix)]
#[test]
fn lookup_buffer_retries_and_grows_after_erange() {
    let mut calls = 0;
    let (value, buffer) = lookup_buffer::<u32>("erange-retry", |output, _buffer, len, result| {
        calls += 1;
        match calls {
            1 => {
                assert_eq!(len, 16 * 1024);
                libc::ERANGE
            }
            2 => {
                assert_eq!(len, 32 * 1024);
                // SAFETY: the fixture writes the initialized test
                // value through the exact output pointer supplied by
                // `lookup_buffer` and returns that same pointer.
                unsafe {
                    output.write(7);
                    *result = output;
                }
                0
            }
            _ => unreachable!("lookup callback called after successful retry"),
        }
    })
    .expect("ERANGE retry must succeed");

    assert_eq!(calls, 2);
    assert_eq!(value, 7);
    assert_eq!(buffer.len(), 32 * 1024);
}

#[cfg(unix)]
#[test]
fn lookup_buffer_rejects_null_result_before_extraction() {
    let result = lookup_buffer::<u32>("null-result", |_output, _buffer, _len, _result| 0);

    assert!(matches!(
        result,
        Err(DropError::AccountLookupFailed { errno, .. }) if errno == 0
    ));
}

#[cfg(unix)]
#[test]
fn lookup_buffer_rejects_result_pointer_not_owned_by_output() {
    let mut foreign = std::mem::MaybeUninit::<u32>::new(11);
    let foreign_pointer = foreign.as_mut_ptr();
    let result = lookup_buffer::<u32>("pointer-mismatch", |_output, _buffer, _len, result| {
        // SAFETY: this fixture intentionally returns a foreign pointer to
        // prove that the production identity check rejects it before any
        // uninitialized output is read.
        unsafe {
            *result = foreign_pointer;
        }
        0
    });

    assert!(matches!(
        result,
        Err(DropError::AccountLookupFailed { errno, .. }) if errno == libc::EINVAL
    ));
}

#[cfg(unix)]
#[test]
fn final_identity_boundary_rejects_forged_root_target() {
    let identity = ResolvedIdentity {
        user_selector: "0".to_string(),
        user_name: "root".to_string(),
        uid: 0,
        group_selector: "0".to_string(),
        group_name: "root".to_string(),
        gid: 0,
    };

    assert!(matches!(validate_resolved_identity(&identity), Err(DropError::UnsafeTarget(_))));
}

#[cfg(unix)]
#[test]
fn group_result_rejects_count_larger_than_requested_capacity() {
    assert!(matches!(
        checked_group_result_count(2, 3),
        Err(DropError::MalformedSystemCallResult { operation, detail })
            if operation == "getgroups"
                && detail == "returned count exceeds requested capacity"
    ));
    assert_eq!(checked_group_result_count(2, 2).unwrap(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_thread_status_requires_filesystem_uid_and_gid_fields() {
    let identity = ResolvedIdentity {
        user_selector: "1001".to_string(),
        user_name: "fixture-user".to_string(),
        uid: 1001,
        group_selector: "1002".to_string(),
        group_name: "fixture-group".to_string(),
        gid: 1002,
    };
    let path = std::path::Path::new("/proc/self/task/fixture");
    let status = "Uid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\nGroups:\t\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";

    verify_linux_thread_status(status, &identity, path)
        .expect("all four Linux UID/GID fields must be accepted");

    let filesystem_mismatch = status.replace("1001 1001 1001 1001", "1001 1001 1001 0");
    assert!(matches!(
        verify_linux_thread_status(&filesystem_mismatch, &identity, path),
        Err(DropError::VerificationFailed(detail)) if detail.contains("filesystem")
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn root_regain_result_contract_is_deterministic_without_syscalls() {
    let regained = verify_root_regain_result_with_errno("setresuid", 0, 0).unwrap_err();
    assert!(matches!(
        regained,
        DropError::VerificationFailed(detail) if detail.contains("unexpectedly regained root")
    ));

    let wrong_errno =
        verify_root_regain_result_with_errno("setresgid", -1, libc::EACCES).unwrap_err();
    assert!(matches!(
        wrong_errno,
        DropError::VerificationFailed(detail) if detail.contains("expected EPERM")
    ));

    verify_root_regain_result_with_errno("setresuid", -1, libc::EPERM)
        .expect("EPERM is the only accepted root-regain result");
}

#[cfg(unix)]
#[test]
fn real_unknown_user_and_group_are_reported_as_not_found() {
    let user_selector = "__quicfuscate_missing_user_5f4d8e2a__";
    let group_selector = "__quicfuscate_missing_group_5f4d8e2a__";

    assert!(matches!(resolve_user(user_selector), Err(DropError::UserNotFound(_))));
    assert!(matches!(resolve_group(group_selector), Err(DropError::GroupNotFound(_))));
}

#[cfg(unix)]
fn c_char_buffer(bytes: &[u8]) -> Vec<libc::c_char> {
    bytes.iter().map(|byte| *byte as libc::c_char).collect()
}

#[cfg(unix)]
#[test]
fn bounded_cstr_field_accepts_nul_terminated_pointer_inside_buffer() {
    let buffer = c_char_buffer(b"prefix\0alice\0");
    let pointer = buffer.as_ptr().wrapping_add("prefix\0".len());

    let value = copy_bounded_cstr_field("normal", "pw_name", pointer, &buffer)
        .expect("bounded account name must be copied");

    assert_eq!(value, "alice");
}

#[cfg(unix)]
#[test]
fn bounded_cstr_field_rejects_null_pointer() {
    let buffer = c_char_buffer(b"alice\0");
    let result = copy_bounded_cstr_field("null", "pw_name", std::ptr::null(), &buffer);

    assert!(matches!(
        result,
        Err(DropError::MalformedAccountRecord { field, reason, .. })
            if field == "pw_name" && reason == "pointer is null"
    ));
}

#[cfg(unix)]
#[test]
fn bounded_cstr_field_rejects_pointer_outside_buffer() {
    let buffer = c_char_buffer(b"alice\0");
    let pointer = buffer.as_ptr().wrapping_add(buffer.len());
    let result = copy_bounded_cstr_field("outside", "gr_name", pointer, &buffer);

    assert!(matches!(
        result,
        Err(DropError::MalformedAccountRecord { field, reason, .. })
            if field == "gr_name" && reason == "pointer is outside the lookup buffer"
    ));
}

#[cfg(unix)]
#[test]
fn bounded_cstr_field_rejects_missing_nul_terminator() {
    let buffer = c_char_buffer(b"alice");
    let result = copy_bounded_cstr_field("unterminated", "pw_name", buffer.as_ptr(), &buffer);

    assert!(matches!(
        result,
        Err(DropError::MalformedAccountRecord { field, reason, .. })
            if field == "pw_name"
                && reason == "field has no NUL terminator in the lookup buffer"
    ));
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "l4re",
    target_os = "linux",
    target_os = "openbsd",
))]
#[test]
fn saved_ids_are_reported_when_the_platform_supports_the_query() {
    let ids = current_ids().expect("supported platform identity query must succeed");
    assert!(ids.2.is_some());
    assert!(ids.5.is_some());
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "l4re",
        target_os = "linux",
        target_os = "openbsd",
    ))
))]
#[test]
fn saved_ids_are_not_inferred_on_platforms_without_a_query() {
    let ids = current_ids().expect("basic Unix identity query must succeed");
    assert_eq!(ids.2, None);
    assert_eq!(ids.5, None);
}

#[test]
fn startup_capability_validation_names_every_missing_capability() {
    let report = CapabilityReport::unavailable();
    let error = validate_startup_capabilities(
        &report,
        CapabilityRequirements {
            tun: true,
            privileged_bind: true,
            privilege_finalize: true,
            audit_owner: true,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("CAP_NET_ADMIN"));
    assert!(error.contains("CAP_NET_RAW"));
    assert!(error.contains("CAP_NET_BIND_SERVICE"));
    assert!(error.contains("CAP_SETGID"));
    assert!(error.contains("CAP_SETUID"));
    assert!(error.contains("CAP_CHOWN"));
}

#[test]
fn test_should_drop_privileges_consistent_with_check() {
    let report = check_capabilities();
    assert_eq!(should_drop_privileges(), report.is_root);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn process_privilege_verification_does_not_claim_linux_proof_elsewhere() {
    let identity = ResolvedIdentity {
        user_selector: "1001".to_string(),
        user_name: "fixture-user".to_string(),
        uid: 1001,
        group_selector: "1002".to_string(),
        group_name: "fixture-group".to_string(),
        gid: 1002,
    };

    assert!(matches!(verify_process_privilege_state(&identity), Err(DropError::NotSupported)));
}

#[cfg(not(unix))]
#[test]
fn test_drop_privileges_not_supported_on_non_unix() {
    let result = drop_privileges("nobody", "nogroup");
    assert!(matches!(result, Err(DropError::NotSupported)));
}

#[cfg(all(unix, not(target_os = "linux")))]
mod non_linux_supplementary_groups {
    use super::super::{
        check_supplementary_groups_cleared, clear_supplementary_groups, current_groups, DropError,
    };

    #[test]
    fn an_empty_group_set_passes_verification() {
        check_supplementary_groups_cleared(&[], 501).expect("no groups is a cleared set");
    }

    #[test]
    fn the_new_primary_gid_is_the_only_tolerated_entry() {
        // POSIX leaves it unspecified whether getgroups() reports the effective
        // GID, and this platform family does. Tolerating it is required; it must
        // not become a licence to tolerate anything else.
        check_supplementary_groups_cleared(&[501], 501)
            .expect("the new primary GID may be reported");
    }

    #[test]
    fn a_retained_membership_fails_verification_and_names_itself() {
        for (label, groups) in [
            ("a single retained group", vec![20u32]),
            ("a retained group beside the primary GID", vec![501, 20]),
            ("the previous root membership", vec![0]),
            ("several retained groups", vec![0, 20, 80]),
        ] {
            let error = check_supplementary_groups_cleared(&groups, 501)
                .expect_err("a retained membership must fail the drop");
            let message = match error {
                DropError::VerificationFailed(message) => message,
                other => panic!("{label} must fail verification, got {other:?}"),
            };
            assert!(
                message.contains("supplementary groups remain"),
                "{label} must name the defect, got {message}"
            );
            for group in groups.iter().filter(|group| **group != 501) {
                assert!(
                    message.contains(&group.to_string()),
                    "{label} must name the retained group {group}, got {message}"
                );
            }
            assert!(
                !message.contains("[501"),
                "{label} must not report the new primary GID as retained, got {message}"
            );
        }
    }

    #[test]
    fn clearing_groups_without_privilege_fails_instead_of_reporting_success() {
        // An unprivileged test process cannot call setgroups, which is exactly the
        // case that must never be swallowed: the drop path propagates it and can
        // therefore never report a reduction it did not perform. Under a
        // privileged runner the call succeeds and the group set is genuinely
        // cleared, so both outcomes are asserted against the observed state.
        let before = current_groups().expect("group set is readable");
        match clear_supplementary_groups() {
            Ok(()) => {
                let after = current_groups().expect("group set is readable after clearing");
                let gid = unsafe { libc::getegid() };
                check_supplementary_groups_cleared(&after, gid)
                    .expect("a successful clear must leave no retained membership");
            }
            Err(DropError::SystemCallFailed { operation, errno }) => {
                assert_eq!(operation, "setgroups");
                assert_ne!(errno, 0, "a failed clear must carry a real errno");
                assert_eq!(
                    current_groups().expect("group set is readable after a failed clear"),
                    before,
                    "a failed clear must not partially modify the group set"
                );
            }
            Err(other) => panic!("unexpected setgroups failure shape: {other:?}"),
        }
    }
}
