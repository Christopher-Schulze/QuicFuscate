#[inline]
pub fn aesni_available() -> bool {
    if std::env::var("FORCE_SOFTWARE").is_ok() {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[inline]
pub fn vaes_available() -> bool {
    if std::env::var("FORCE_SOFTWARE").is_ok() {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("vaes") && std::is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[inline]
pub fn neon_available() -> bool {
    if std::env::var("FORCE_SOFTWARE").is_ok() {
        return false;
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("neon")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}
