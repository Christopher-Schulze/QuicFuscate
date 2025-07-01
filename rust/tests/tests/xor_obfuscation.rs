use stealth::{XORObfuscator, XORPattern};

#[test]
fn encode_decode_roundtrip() {
    let obf = XORObfuscator;
    let data = vec![1u8, 2, 3, 4, 5];
    let encoded = obf.obfuscate(&data, XORPattern::SIMPLE, 42);
    assert_eq!(encoded.len(), data.len());
    let decoded = obf.deobfuscate(&encoded, XORPattern::SIMPLE, 42);
    assert_eq!(decoded, data);
}
