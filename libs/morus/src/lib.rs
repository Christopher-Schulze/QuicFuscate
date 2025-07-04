pub struct Morus;
impl Morus {
    pub fn new(_k: &[u8;16], _n: &[u8;16]) -> Self { Morus }
    pub fn encrypt(&mut self, data: &[u8], _ad: &[u8]) -> (Vec<u8>, [u8;16]) { (data.to_vec(), [0u8;16]) }
    pub fn decrypt(&mut self, data: &[u8], _tag: &[u8;16], _ad: &[u8]) -> Result<Vec<u8>, ()> { Ok(data.to_vec()) }
}
