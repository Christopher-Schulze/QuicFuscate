use quicfuscate::crypto::{CipherSuiteSelector, CipherSuite};
use quicfuscate::optimize::CpuFeature;

#[test]
fn selector_prefers_vaes_then_aesni() {
    let sel = CipherSuiteSelector::new_with_features(&[CpuFeature::VAES]);
    assert_eq!(sel.selected_suite(), CipherSuite::Aegis128X);

    let sel = CipherSuiteSelector::new_with_features(&[CpuFeature::AESNI]);
    assert_eq!(sel.selected_suite(), CipherSuite::Aegis128L);

    let sel = CipherSuiteSelector::new_with_features(&[CpuFeature::NEON]);
    assert_eq!(sel.selected_suite(), CipherSuite::Aegis128L);

    let sel = CipherSuiteSelector::new_with_features(&[]);
    assert_eq!(sel.selected_suite(), CipherSuite::Morus1280_128);
}
