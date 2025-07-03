use fec::{EncoderCore, DecoderCore, FecAlgorithm, FECPacket};

fn roundtrip(algo: FecAlgorithm) -> Result<(), Box<dyn std::error::Error>> {
    let enc = EncoderCore::new(algo);
    let dec = DecoderCore::new(algo);
    let data = b"hello";
    let packets = enc.encode(data, 1)?;
    let decoded = dec.decode(&packets)?;
    assert_eq!(data.to_vec(), decoded);
    Ok(())
}

#[test]
fn stripe_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    roundtrip(FecAlgorithm::StripeXor)
}

#[test]
fn rlnc_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    roundtrip(FecAlgorithm::SparseRlnc)
}

#[test]
fn cm256_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    roundtrip(FecAlgorithm::Cm256)
}

#[test]
fn rs_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    roundtrip(FecAlgorithm::ReedSolomon)
}
