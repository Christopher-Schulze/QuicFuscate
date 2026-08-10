//! Compatibility crypto profile alias that forwards to the SSOT in `simd::CryptoAeadPlan`.
//! This file exists for compatibility only and does not contain selection logic.

use super::CryptoAeadPlan;

/// Crypto profile selector based on CPU features.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Aegis128Profile {
    /// Single-lane AEGIS-128L with AES-NI
    L_AESNI,
    /// Single-lane AEGIS-128L with ARM AES instructions.
    #[cfg(target_arch = "aarch64")]
    L_NEON,
    /// MORUS-1280 fallback
    Morus1280,
}

impl From<CryptoAeadPlan> for Aegis128Profile {
    fn from(p: CryptoAeadPlan) -> Self {
        match p {
            #[cfg(target_arch = "aarch64")]
            CryptoAeadPlan::Aegis128L | CryptoAeadPlan::Aegis128X4 | CryptoAeadPlan::Aegis128X8 => {
                Self::L_NEON
            }
            #[cfg(not(target_arch = "aarch64"))]
            CryptoAeadPlan::Aegis128L | CryptoAeadPlan::Aegis128X4 | CryptoAeadPlan::Aegis128X8 => {
                Self::L_AESNI
            }
            CryptoAeadPlan::Morus => Self::Morus1280,
        }
    }
}

impl From<Aegis128Profile> for CryptoAeadPlan {
    fn from(p: Aegis128Profile) -> Self {
        match p {
            Aegis128Profile::L_AESNI => Self::Aegis128L,
            #[cfg(target_arch = "aarch64")]
            Aegis128Profile::L_NEON => Self::Aegis128X4,
            Aegis128Profile::Morus1280 => Self::Morus,
        }
    }
}

impl Aegis128Profile {
    pub fn select() -> Self {
        CryptoAeadPlan::select().into()
    }

    pub fn select_for_len(len: usize) -> Self {
        CryptoAeadPlan::select_for_len(len).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aegis_plan_roundtrip() {
        // On aarch64 AEGIS maps to L_NEON, on x86_64 to L_AESNI
        let plan = CryptoAeadPlan::Aegis128L;
        let profile: Aegis128Profile = plan.into();
        let back: CryptoAeadPlan = profile.into();
        // L_AESNI -> Aegis128L, L_NEON -> Aegis128X4 (architecture-dependent mapping)
        assert!(matches!(back, CryptoAeadPlan::Aegis128L | CryptoAeadPlan::Aegis128X4));
    }

    #[test]
    fn l_aesni_to_plan() {
        let plan: CryptoAeadPlan = Aegis128Profile::L_AESNI.into();
        assert_eq!(plan, CryptoAeadPlan::Aegis128L);
    }

    #[test]
    fn morus_roundtrip() {
        let profile = Aegis128Profile::Morus1280;
        let plan: CryptoAeadPlan = profile.into();
        assert_eq!(plan, CryptoAeadPlan::Morus);
        let back: Aegis128Profile = plan.into();
        assert_eq!(back, Aegis128Profile::Morus1280);
    }

    #[test]
    fn all_plans_convert_to_profile() {
        for plan in [
            CryptoAeadPlan::Aegis128L,
            CryptoAeadPlan::Aegis128X4,
            CryptoAeadPlan::Aegis128X8,
            CryptoAeadPlan::Morus,
        ] {
            let _profile: Aegis128Profile = plan.into();
        }
    }

    #[test]
    fn select_returns_valid_profile() {
        let profile = Aegis128Profile::select();
        let _plan: CryptoAeadPlan = profile.into();
    }

    #[test]
    fn select_for_len_returns_valid_profile() {
        for len in [0, 64, 1024, 16384, 1_000_000] {
            let profile = Aegis128Profile::select_for_len(len);
            let _plan: CryptoAeadPlan = profile.into();
        }
    }
}
