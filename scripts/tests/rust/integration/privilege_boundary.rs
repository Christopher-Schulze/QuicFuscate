use quicfuscate::privilege::{
    resolve_identity, try_check_capabilities, validate_startup_capabilities,
    CapabilityRequirements, DropError,
};

#[test]
fn unknown_and_root_identities_fail_closed() {
    let missing = format!("quicfuscate-account-that-must-not-exist-{}", std::process::id());
    assert!(matches!(
        resolve_identity(&missing, &missing),
        Err(DropError::UserNotFound(_)) | Err(DropError::AccountLookupFailed { .. })
    ));

    #[cfg(unix)]
    assert!(matches!(resolve_identity("0", "0"), Err(DropError::UnsafeTarget(_))));
}

#[test]
fn capability_cli_json_is_clean_and_reports_each_target_lookup() {
    let missing_user = format!("quicfuscate-user-that-must-not-exist-{}", std::process::id());
    let missing_group = format!("quicfuscate-group-that-must-not-exist-{}", std::process::id());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_quicfuscate"))
        .args([
            "capabilities",
            "--json",
            "--user",
            &missing_user,
            "--group",
            &missing_group,
            "--tun",
        ])
        .output()
        .expect("run capability diagnostics");
    assert!(output.status.success(), "capability diagnostics failed");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must contain only valid JSON");
    assert_eq!(report["target_user_exists"], false);
    assert_eq!(report["target_group_exists"], false);
    assert!(report["target_error"].as_str().is_some_and(|error| error.contains("not found")));
    assert!(output.stderr.is_empty(), "JSON diagnostics wrote stderr noise");
}

#[test]
fn capability_report_is_serializable_and_readiness_is_fail_closed() {
    let report = try_check_capabilities(None, CapabilityRequirements::default())
        .expect("current privilege state must be inspectable");
    let encoded = serde_json::to_value(&report).expect("capability report must serialize");
    assert!(encoded.get("real_uid").is_some());
    assert!(encoded.get("effective_capabilities").is_some());
    assert!(encoded.get("supplementary_groups").is_some());
    assert!(encoded.get("no_new_privileges").is_some());

    let requirements = CapabilityRequirements {
        tun: true,
        privileged_bind: true,
        privilege_finalize: true,
        audit_owner: true,
    };
    assert_eq!(
        validate_startup_capabilities(&report, requirements).is_ok(),
        report.ready_for_tun
            && report.ready_for_privileged_bind
            && report.has_setgid
            && report.has_setuid
            && report.has_chown
    );
}

#[cfg(target_os = "linux")]
#[test]
fn privileged_drop_is_isolated_in_a_subprocess() {
    // SAFETY: geteuid has no side effects.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("root-only subprocess proof deferred to the privileged Omega gate");
        return;
    }

    let identity = resolve_identity("nobody", "nogroup")
        .or_else(|_| resolve_identity("nobody", "nobody"))
        .expect("Linux test host must provide a nobody identity");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_qf-privilege-probe"))
        .arg(identity.uid().to_string())
        .arg(identity.gid().to_string())
        .output()
        .expect("launch isolated privilege-drop probe");
    assert!(
        output.status.success(),
        "privilege-drop probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let proof: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse privilege-drop proof");
    assert_eq!(proof["real_uid"], identity.uid());
    assert_eq!(proof["effective_uid"], identity.uid());
    assert_eq!(proof["saved_uid"], identity.uid());
    assert_eq!(proof["real_gid"], identity.gid());
    assert_eq!(proof["effective_gid"], identity.gid());
    assert_eq!(proof["saved_gid"], identity.gid());
    assert_eq!(proof["supplementary_groups"], serde_json::json!([]));
    assert_eq!(proof["effective_capabilities"], 0);
    assert_eq!(proof["permitted_capabilities"], 0);
    assert_eq!(proof["inheritable_capabilities"], 0);
    assert_eq!(proof["ambient_capabilities"], 0);
    assert_eq!(proof["no_new_privileges"], true);

    let tokio_output = std::process::Command::new(env!("CARGO_BIN_EXE_qf-privilege-probe"))
        .arg(identity.uid().to_string())
        .arg(identity.gid().to_string())
        .args(["--tokio-threads", "8"])
        .output()
        .expect("launch Tokio privilege-drop probe");
    assert!(
        tokio_output.status.success(),
        "Tokio privilege-drop probe failed: {}",
        String::from_utf8_lossy(&tokio_output.stderr)
    );
    let tokio_proof: serde_json::Value =
        serde_json::from_slice(&tokio_output.stdout).expect("parse Tokio privilege-drop proof");
    assert_eq!(tokio_proof["effective_uid"], identity.uid());
    assert_eq!(tokio_proof["effective_gid"], identity.gid());
    assert_eq!(tokio_proof["effective_capabilities"], 0);
    assert_eq!(tokio_proof["no_new_privileges"], true);

    // SAFETY: parent identity is inspected only; the child performed the drop.
    assert_eq!(unsafe { libc::geteuid() }, 0);
}
