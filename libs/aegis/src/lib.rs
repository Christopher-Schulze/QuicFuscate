pub mod aegis128l {
    pub struct Aegis128L;
    impl Aegis128L {
        pub fn new(_k: &[u8; 16], _n: &[u8; 16]) -> Self { Aegis128L }
        pub fn encrypt(&self, data: &[u8], _ad: &[u8]) -> (Vec<u8>, [u8;16]) { (data.to_vec(), [0u8;16]) }
        pub fn decrypt(&self, data: &[u8], _tag: &[u8;16], _ad: &[u8]) -> Result<Vec<u8>, ()> { Ok(data.to_vec()) }
    }
    pub fn tag_from_slice(s: &[u8]) -> &[u8;16] { s.try_into().unwrap() }
}

pub mod aegis128x {
    pub struct Aegis128X;
    impl Aegis128X {
        pub fn new(_k: &[u8;32], _n: &[u8;32]) -> Self { Aegis128X }
        pub fn encrypt(&self, data: &[u8], _ad: &[u8]) -> (Vec<u8>, [u8;16]) { (data.to_vec(), [0u8;16]) }
        pub fn decrypt(&self, data: &[u8], _tag: &[u8;16], _ad: &[u8]) -> Result<Vec<u8>, ()> { Ok(data.to_vec()) }
    }
    pub fn tag_from_slice(s: &[u8]) -> &[u8;16] { s.try_into().unwrap() }
}

pub mod Tag {
    pub fn from_slice(s: &[u8]) -> &[u8;16] { s.try_into().unwrap() }
}
