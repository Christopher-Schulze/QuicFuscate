use std::path::{Path, PathBuf};

struct TemporaryFileGuard {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, committed: false }
    }

    fn mark_committed(&mut self) {
        self.committed = true;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn open_temp_file(path: &Path, mode: Option<u32>) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let file = options.open(path)?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(file)
}

pub fn atomic_write_file(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    nonce_context: &str,
) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut nonce = [0u8; 8];
    crate::rng::fill_secure_or_abort(&mut nonce, nonce_context);
    let suffix = format!(".tmp-{}", hex_from_bytes(&nonce));
    let tmp_path = path.with_file_name(format!(
        "{}{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        suffix
    ));

    let mut temporary_file_guard = TemporaryFileGuard::new(tmp_path.clone());
    let mut file = open_temp_file(&tmp_path, mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;

    std::fs::rename(&tmp_path, path)?;
    temporary_file_guard.mark_committed();

    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            log::warn!("set_permissions failed for {}: {}", path.display(), e);
        }
    }

    Ok(())
}

fn hex_from_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir_for_test(suffix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("qf_fsutil_test_{}", suffix));
        // Clean up from previous runs
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_atomic_write_file_happy_path() {
        let dir = temp_dir_for_test("happy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("testfile.txt");
        let content = b"hello world";

        atomic_write_file(&path, content, None, "test::happy_path").unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, content);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_write_file_overwrites_existing() {
        let dir = temp_dir_for_test("overwrite");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overwrite.txt");

        atomic_write_file(&path, b"original", None, "test::overwrite_1").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original");

        atomic_write_file(&path, b"replaced", None, "test::overwrite_2").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replaced");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_write_file_creates_parent_dirs() {
        let dir = temp_dir_for_test("nested_parent");
        let path = dir.join("a").join("b").join("c").join("deep.txt");

        atomic_write_file(&path, b"deep content", None, "test::nested").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"deep content");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_write_file_empty_content() {
        let dir = temp_dir_for_test("empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.txt");

        atomic_write_file(&path, b"", None, "test::empty").unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert!(read_back.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_write_file_removes_temporary_after_commit_failure() {
        let dir = temp_dir_for_test("failed_commit_cleanup");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("destination");
        std::fs::create_dir(&path).unwrap();

        let result = atomic_write_file(&path, b"must not publish", None, "test::failed_commit");

        assert!(result.is_err());
        assert!(path.is_dir(), "failed replacement must retain the destination");
        let temporary_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(temporary_files.is_empty(), "failed commit left temporary files");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_file_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir_for_test("perms");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.txt");

        atomic_write_file(&path, b"secret", Some(0o600), "test::perms").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file mode should be 0600, got {:o}", mode);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_temp_file_permissions_are_restricted_before_rename() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir_for_test("temp_perms");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.tmp");

        let file = open_temp_file(&path, Some(0o600)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "temporary file must be 0600 before commit");
        drop(file);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hex_from_bytes_encoding() {
        assert_eq!(hex_from_bytes(&[]), "");
        assert_eq!(hex_from_bytes(&[0x00]), "00");
        assert_eq!(hex_from_bytes(&[0xff]), "ff");
        assert_eq!(hex_from_bytes(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_from_bytes(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
            "0123456789abcdef"
        );
    }
}
