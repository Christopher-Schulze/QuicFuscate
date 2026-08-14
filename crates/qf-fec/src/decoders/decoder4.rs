use super::{anchor_is_valid, source_id_for_params, validate_decoder_dimensions};
use crate::codecs::FecPacket;
use qf_memory_pool::{MemoryPool, PooledBlock};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

// --- GF(2^4) Decoder for Low-Loss Scenarios (<5%) ---

struct Equation4 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: PooledBlock,
    len: usize,
}

#[doc(hidden)]
pub struct Decoder4 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (PooledBlock, usize)>,
    equations: VecDeque<Equation4>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder4 {
    #[doc(hidden)]
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self::new_with_depth(k, pool, 1)
    }

    fn rejected(pool: Arc<MemoryPool>) -> Self {
        Self {
            k: 0,
            mem_pool: pool,
            known: HashMap::new(),
            equations: VecDeque::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    #[doc(hidden)]
    pub fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        if validate_decoder_dimensions(k, depth, 15).is_err() {
            return Self::rejected(pool);
        }
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: VecDeque::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        source_id_for_params(self.k, self.depth, base_id, j).unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn take_packet(&mut self, p: FecPacket) {
        if self.k == 0 {
            return;
        }
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                if data.len() > self.mem_pool.block_size() || self.known.contains_key(&p.id) {
                    return;
                }
                let mut buf = PooledBlock::new(Arc::clone(&self.mem_pool));
                buf[..data.len()].copy_from_slice(data);
                self.known.insert(p.id, (buf, data.len()));
            }
            self.try_peel_all();
        } else if let Some(ref coeffs) = p.coefficients {
            // Mirror Decoder8 logic for compatibility
            let Some(d) = p.payload_slice() else {
                return;
            };
            let Some(coeffs) = coeffs.get(..p.coeff_len) else {
                return;
            };
            let n = p.data_len;
            if p.coeff_len != self.k
                || n > self.mem_pool.block_size()
                || d.len() < n
                || !anchor_is_valid(self.k, self.depth, p.id)
            {
                return;
            }
            let mut data_buf = PooledBlock::new(Arc::clone(&self.mem_pool));
            data_buf[..n].copy_from_slice(&d[..n]);

            let eq = Equation4 { base_id: p.id, coeffs: coeffs.to_vec(), data: data_buf, len: n };
            self.equations.push_back(eq);
            self.try_peel_all();
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let equations_in_pass = self.equations.len();
            for _ in 0..equations_in_pass {
                let Some(mut equation) = self.equations.pop_front() else {
                    break;
                };
                if self.try_solve_equation(&mut equation) {
                    progress = true;
                } else {
                    self.equations.push_back(equation);
                }
            }
        }
    }

    fn try_solve_equation(&mut self, eq: &mut Equation4) -> bool {
        let mut unknown_idx = None;
        let mut unknown_cnt = 0;
        let mut j = 0;
        const GF4_INV: [u8; 16] = [0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];

        while j < self.k {
            let c = eq.coeffs[j];
            if c == 0 {
                j += 1;
                continue;
            }
            let pid = self.source_id_for(eq.base_id, j);

            if let Some((kdata, len)) = self.known.get(&pid) {
                let sl = eq.len.min(*len);
                if sl > 0 {
                    qf_simd::galois::gf4_mul_xor(&kdata[..sl], c, &mut eq.data[..sl]);
                }
                eq.coeffs[j] = 0;
            } else {
                unknown_idx = Some(j);
                unknown_cnt += 1;
            }
            j += 1;
        }

        if unknown_cnt == 1 {
            let Some(idx) = unknown_idx else {
                return false;
            };
            let pid = self.source_id_for(eq.base_id, idx);
            if self.known.contains_key(&pid) {
                return false;
            }
            let c = eq.coeffs[idx];
            let inv = GF4_INV[(c & 0xF) as usize];

            let sl = eq.len;
            if sl > 0 {
                let mut rec = PooledBlock::new(Arc::clone(&self.mem_pool));
                rec[..sl].fill(0);
                let mut k = 0;
                while k < sl {
                    let chunk = (sl - k).min(128);
                    qf_simd::galois::gf4_mul(&eq.data[k..k + chunk], inv, &mut rec[k..k + chunk]);
                    k += chunk;
                }
                let mut rec_clone = PooledBlock::new(Arc::clone(&self.mem_pool));
                rec_clone[..sl].copy_from_slice(&rec[..sl]);
                let pkt = match FecPacket::from_pooled_blocks(
                    pid,
                    Some(rec_clone),
                    sl,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                ) {
                    Ok(pkt) => pkt,
                    Err(_) => return false,
                };
                self.emit_q.push_back(pkt);
                self.known.insert(pid, (rec, sl));
                return true;
            }
            return true;
        }

        false
    }

    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.emit_q.is_empty() {
            None
        } else {
            let mut res = VecDeque::new();
            std::mem::swap(&mut res, &mut self.emit_q);
            Some(res)
        }
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let mut res = VecDeque::new();
        std::mem::swap(&mut res, &mut self.emit_q);
        res
    }
}
