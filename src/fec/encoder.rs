use crate::optimize::{MemoryPool, OptimizationManager};
use aligned_box::AlignedBox;
use std::sync::Arc;
pub struct Packet {
    pub id: u64,
    pub data: Option<AlignedBox<[u8]>>,
    pub len: usize,
    pub is_systematic: bool,
    pub coefficients: Option<AlignedBox<[u8]>>,
    pub coeff_len: usize,
    mem_pool: Arc<MemoryPool>,
}

impl Packet {
    /// Deserializes a packet from a raw byte buffer.
    /// This is a lightweight framing implementation.
    /// Frame format: <is_systematic_byte (1)> <coeff_len (2)> <coeffs (coeff_len)> <payload>
    pub fn from_raw(
        id: u64,
        raw_data: &[u8],
        opt_manager: &OptimizationManager,
    ) -> Result<Self, String> {
        if raw_data.is_empty() {
            error!("from_raw: input buffer empty");
            return Err("Raw data is empty".to_string());
        }

        let is_systematic = raw_data[0] == 1;
        let mut offset = 1;

        let (coefficients, coeff_len, payload_offset) = if !is_systematic {
            if raw_data.len() < 3 {
                error!("from_raw: coefficient length missing");
                return Err("Buffer too short for coefficient length".to_string());
            }
            let coeff_len =
                u16::from_be_bytes(raw_data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            if raw_data.len() < offset + coeff_len {
                error!("from_raw: coefficient data truncated");
                return Err("Buffer too short for coefficients".to_string());
            }
            let mut coeff_block = opt_manager.alloc_block();
            coeff_block[..coeff_len].copy_from_slice(&raw_data[offset..offset + coeff_len]);
            (Some(coeff_block), coeff_len, offset + coeff_len)
        } else {
            (None, 0, offset)
        };

        let payload = &raw_data[payload_offset..];
        let mut data = opt_manager.alloc_block();
        if data.len() < payload.len() {
            error!("from_raw: pool buffer too small");
            return Err("Buffer from pool is too small".to_string());
        }
        data[..payload.len()].copy_from_slice(payload);

        Ok(Packet {
            id,
            data: Some(data),
            len: payload.len(),
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool: opt_manager.memory_pool(),
        })
    }

    /// Creates a packet from a pooled memory block. The `len` parameter
    /// specifies the amount of valid data in the block.
    pub fn from_block(
        id: u64,
        mut block: AlignedBox<[u8]>,
        len: usize,
        opt_manager: &OptimizationManager,
    ) -> Result<Self, String> {
        if len == 0 || len > block.len() {
            opt_manager.free_block(block);
            error!("from_block: invalid length {}", len);
            return Err("Invalid raw packet length".to_string());
        }

        let is_systematic = block[0] == 1;
        let mut offset = 1;

        let (coefficients, coeff_len, payload_offset) = if !is_systematic {
            if len < 3 {
                opt_manager.free_block(block);
                error!("from_block: coefficient length missing");
                return Err("Buffer too short for coefficient length".to_string());
            }
            let coeff_len = u16::from_be_bytes([block[offset], block[offset + 1]]) as usize;
            offset += 2;
            if len < offset + coeff_len {
                opt_manager.free_block(block);
                error!("from_block: coefficient data truncated");
                return Err("Buffer too short for coefficients".to_string());
            }
            let mut coeff_block = opt_manager.alloc_block();
            coeff_block[..coeff_len].copy_from_slice(&block[offset..offset + coeff_len]);
            (Some(coeff_block), coeff_len, offset + coeff_len)
        } else {
            (None, 0, offset)
        };

        let payload_len = len - payload_offset;
        if payload_offset > 0 {
            block.copy_within(payload_offset..len, 0);
        }

        Ok(Packet {
            id,
            data: Some(block),
            len: payload_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool: opt_manager.memory_pool(),
        })
    }

    /// Serializes the packet into a raw byte buffer for transmission.
    pub fn to_raw(&self, buffer: &mut [u8]) -> Result<usize, quiche::Error> {
        let mut required_len = self.len + 1;
        if let Some(_) = &self.coefficients {
            required_len += 2 + self.coeff_len;
        }
        if buffer.len() < required_len {
            return Err(quiche::Error::BufferTooShort);
        }

        let mut offset = 0;
        buffer[offset] = if self.is_systematic { 1 } else { 0 };
        offset += 1;

        if let Some(coeffs) = &self.coefficients {
            let coeff_len = self.coeff_len as u16;
            buffer[offset..offset + 2].copy_from_slice(&coeff_len.to_be_bytes());
            offset += 2;
            buffer[offset..offset + self.coeff_len]
                .copy_from_slice(&coeffs[..self.coeff_len]);
            offset += self.coeff_len;
        }

        if let Some(ref data) = self.data {
            buffer[offset..offset + self.len].copy_from_slice(&data[..self.len]);
        }
        offset += self.len;

        Ok(offset)
    }

    /// Clones the packet structure and its data for use in the encoder window.
    /// This is a deep copy of the data into a new buffer from the memory pool.
    pub fn clone_for_encoder(&self, mem_pool: &Arc<MemoryPool>) -> Self {
        let mut new_data = mem_pool.alloc();
        if let Some(ref data) = self.data {
            new_data[..self.len].copy_from_slice(&data[..self.len]);
        }
        Packet {
            id: self.id,
            data: Some(new_data),
            len: self.len,
            is_systematic: self.is_systematic,
            coefficients: self.coefficients.as_ref().map(|c| {
                let mut nb = mem_pool.alloc();
                nb[..self.coeff_len].copy_from_slice(&c[..self.coeff_len]);
                nb
            }),
            coeff_len: self.coeff_len,
            mem_pool: Arc::clone(mem_pool),
        }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            self.mem_pool.free(data);
        }
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}
