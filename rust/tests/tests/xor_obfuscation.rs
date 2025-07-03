use stealth::{XORObfuscator, XORPattern};

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
