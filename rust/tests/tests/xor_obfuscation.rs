use stealth::{XORConfig, XORObfuscator, XORPattern};

#[test]
fn encode_decode_roundtrip() {
    let mut obf = XORObfuscator::new();
    let data = vec![1u8, 2, 3, 4, 5];
    let encoded = obf.obfuscate(&data, XORPattern::Simple);
    assert_eq!(encoded.len(), data.len());
    let decoded = obf.deobfuscate(&encoded, XORPattern::Simple);
    assert_eq!(decoded, data);
}

#[test]
fn obfuscation_flips_bits() {
    let mut obf = XORObfuscator::new();
    let data = [0xFFu8];
    let encoded = obf.obfuscate(&data, XORPattern::Simple);
    assert_eq!(encoded, vec![0x55]);
}

#[test]
fn layered_pattern_changes_output() {
    let mut obf = XORObfuscator::with_config(XORConfig {
        multi_layer: true,
        ..Default::default()
    });
    let data = vec![1, 2, 3];
    let layered = obf.obfuscate(&data, XORPattern::Layered);
    assert_ne!(layered, data);
    let decoded = obf.deobfuscate(&layered, XORPattern::Layered);
    assert_eq!(decoded, data);
}

#[test]
fn position_based_pattern_roundtrip() {
    let mut obf = XORObfuscator::new();
    let data = vec![10u8, 20, 30, 40];
    let enc = obf.obfuscate(&data, XORPattern::PositionBased);
    assert_eq!(enc.len(), data.len());
    let dec = obf.deobfuscate(&enc, XORPattern::PositionBased);
    assert_eq!(dec, data);
}
