use super::*;

/// The rule file must be unpredictable, exclusively created, and never a symlink.
///
/// The path was `/tmp/quicfuscate_killswitch_<pid>.conf` and was written with
/// `std::fs::write`, which follows symlinks. A local attacker who could predict the PID could
/// place a symlink there before this privileged process wrote it and redirect pf rule content
/// to another file.
#[cfg(target_os = "macos")]
#[test]
fn killswitch_rule_file_is_unpredictable_exclusive_and_symlink_safe() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let switch = MacOSKillSwitch::new();
    let path = std::path::PathBuf::from(&switch.config_path);

    // Unpredictable: the path must not be derived from the process id.
    assert!(
        !switch.config_path.contains(&std::process::id().to_string()),
        "the rule path must not be PID-derived: {}",
        switch.config_path
    );
    // Two instances must not collide.
    let other = MacOSKillSwitch::new();
    assert_ne!(switch.config_path, other.config_path, "instances must not share a rule path");

    // A normal write produces an owner-only regular file with exactly the requested content.
    switch.write_rules_exclusive("block out all\n").expect("first write");
    let metadata = std::fs::metadata(&path).expect("rule file metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "rule file must be owner-only");
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(std::fs::read_to_string(&path).expect("read rules"), "block out all\n");

    // A rewrite replaces the content rather than appending, and keeps the same guarantees.
    switch.write_rules_exclusive("pass out on lo0\n").expect("rewrite");
    assert_eq!(std::fs::read_to_string(&path).expect("read rules"), "pass out on lo0\n");
    assert_eq!(std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777, 0o600);

    // A symlink planted at the path must not be followed: the target must stay untouched.
    let _ = std::fs::remove_file(&path);
    let victim =
        std::env::temp_dir().join(format!("qf-killswitch-victim-{}", switch.config_path.len()));
    let _ = std::fs::remove_file(&victim);
    std::fs::write(&victim, "ORIGINAL").expect("seed victim");
    std::os::unix::fs::symlink(&victim, &path).expect("plant symlink");

    switch.write_rules_exclusive("block out all\n").expect("write over a planted symlink");
    assert_eq!(
        std::fs::read_to_string(&victim).expect("victim survives"),
        "ORIGINAL",
        "a planted symlink must not redirect privileged rule content"
    );
    assert!(
        !std::fs::symlink_metadata(&path).expect("rule path").file_type().is_symlink(),
        "the rule path must be a regular file after the write, not the planted symlink"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&victim);
    let _ = std::fs::remove_file(&other.config_path);
}

/// A pre-existing regular file at the path must be replaced, not appended to or reused.
#[cfg(target_os = "macos")]
#[test]
fn killswitch_replaces_a_preexisting_rule_file() {
    use std::os::unix::fs::PermissionsExt;

    let switch = MacOSKillSwitch::new();
    let path = std::path::PathBuf::from(&switch.config_path);

    // Something world-readable left behind by an earlier run or another user.
    std::fs::write(&path, "STALE RULES").expect("seed stale file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
        .expect("seed permissive mode");

    switch.write_rules_exclusive("block out all\n").expect("write over stale file");

    assert_eq!(std::fs::read_to_string(&path).expect("read"), "block out all\n");
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600,
        "a permissive stale mode must not be inherited"
    );

    let _ = std::fs::remove_file(&path);
}
