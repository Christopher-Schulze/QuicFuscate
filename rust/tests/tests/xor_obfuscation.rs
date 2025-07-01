use stealth::xor::{XorObfuscator, XorPattern};

#[test]
fn encode_decode_roundtrip() {
    let mut obf = XorObfuscator::new();
    let data = vec![1u8, 2, 3, 4, 5];
    let encoded = obf.obfuscate(&data, XorPattern::Simple);
    assert_eq!(encoded.len(), data.len());
    let decoded = obf.deobfuscate(&encoded, XorPattern::Simple);
    assert_eq!(decoded, data);
}
