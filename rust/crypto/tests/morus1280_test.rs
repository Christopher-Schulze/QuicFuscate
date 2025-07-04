use crypto::Morus1280;

const MSG: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const AD: &[u8] = b"Comment numero un";
const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = &[
    113, 42, 233, 132, 67, 60, 238, 160, 68, 138, 106, 79, 53, 175, 212, 107, 66, 244, 45, 105, 49,
    110, 66, 170, 84, 38, 77, 253, 137, 81, 41, 59, 110, 214, 118, 201, 168, 19, 231, 244, 39, 69,
    230, 33, 13, 233, 200, 44, 74, 198, 127, 222, 87, 105, 92, 45, 30, 31, 47, 48, 38, 130, 241,
    24, 198, 137, 89, 21, 222, 143, 166, 61, 225, 187, 121, 140, 122, 23, 140, 227, 41, 13, 254,
    53, 39, 195, 112, 164, 198, 91, 224, 28, 165, 91, 122, 187, 38, 181, 115, 173, 233, 7, 108,
    191, 155, 140, 6, 172, 199, 80, 71, 10, 69, 36,
];
const EXPECTED_TAG: [u8; 16] = [
    254, 11, 243, 234, 96, 11, 3, 85, 235, 83, 93, 221, 53, 50, 14, 27,
];

#[test]
fn encrypt_decrypt_vectors() -> Result<(), crypto::CryptoError> {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let cipher = Morus1280::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher.encrypt(MSG, KEY, &NONCE, AD, &mut ct, &mut tag)?;
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    cipher.decrypt(&ct, KEY, &NONCE, AD, &tag, &mut pt)?;
    assert_eq!(pt, MSG);
    Ok(())
}
