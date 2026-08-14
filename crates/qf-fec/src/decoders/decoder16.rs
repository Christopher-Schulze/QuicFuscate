use super::{
    anchor_is_valid, copy_to_pooled_block, id_is_in_window, record_decoder_solve,
    source_id_for_params, validate_decoder_dimensions, MAX_DECODER_SOURCE_COUNT,
};
use crate::codecs::FecPacket;
use crate::gf_tables;
use crate::{gf16_mul_scalar_slice_padded, gf16_mul_scalar_slice_u16, gf16_mul_slice};
use qf_memory_pool::{MemoryPool, PooledBlock};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

// GF(2^16) Decoder for higher error correction modes
struct Equation16 {
    base_id: u64,
    coeffs: Vec<u16>,
    data: PooledBlock,
    len: usize,
}

#[doc(hidden)]
pub struct Decoder16 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (PooledBlock, usize)>,
    equations: VecDeque<Equation16>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
    /// Anchor ID for the active source window. Repair packets establish it.
    active_anchor: Option<u64>,
}

impl Decoder16 {
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
            active_anchor: None,
        }
    }

    #[doc(hidden)]
    pub fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        if validate_decoder_dimensions(k, depth, MAX_DECODER_SOURCE_COUNT).is_err() {
            return Self::rejected(pool);
        }
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: VecDeque::new(),
            emit_q: VecDeque::new(),
            depth,
            active_anchor: None,
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
                if data.len() > self.mem_pool.block_size()
                    || self.known.contains_key(&p.id)
                    || self
                        .active_anchor
                        .is_some_and(|anchor| !id_is_in_window(self.k, self.depth, anchor, p.id))
                {
                    return;
                }
                let mut buf = PooledBlock::new(Arc::clone(&self.mem_pool));
                buf[..data.len()].copy_from_slice(data);
                self.known.insert(p.id, (buf, data.len()));
            }
            // Try peeling any pending equations
            self.try_peel_all();
        } else if let Some(ref coeffs_be) = p.coefficients {
            // Parse coefficients as big-endian u16
            let Some(coeffs_be) = coeffs_be.get(..p.coeff_len) else {
                return;
            };
            let Some(expected_coeff_len) = self.k.checked_mul(2) else {
                return;
            };
            if p.coeff_len != expected_coeff_len {
                return;
            }
            let mut coeffs16 = vec![0u16; self.k];
            let mut j = 0usize;
            while j < self.k {
                let Some(offset) = j.checked_mul(2) else {
                    return;
                };
                let Some(end) = offset.checked_add(2) else {
                    return;
                };
                if end > coeffs_be.len() {
                    return;
                }
                let b0 = coeffs_be[offset] as u16;
                let b1 = coeffs_be[offset + 1] as u16;
                coeffs16[j] = (b0 << 8) | b1;
                j += 1;
            }
            let len = p.data_len;
            let Some(d) = p.payload_slice() else {
                return;
            };
            if len > self.mem_pool.block_size() || d.len() < len {
                return;
            }
            let mut data_buf = PooledBlock::new(Arc::clone(&self.mem_pool));
            data_buf[..len].copy_from_slice(&d[..len]);
            if !self.active_anchor.is_some_and(|anchor| anchor == p.id) {
                if self.active_anchor.is_some() || !anchor_is_valid(self.k, self.depth, p.id) {
                    return;
                }
                self.active_anchor = Some(p.id);
                self.known.retain(|&id, _| id_is_in_window(self.k, self.depth, p.id, id));
            }
            let mut equation = Equation16 { base_id: p.id, coeffs: coeffs16, data: data_buf, len };
            if self.try_solve_equation(&mut equation) {
                self.try_peel_all();
                return;
            }
            self.equations.push_back(equation);
            let _ = self.try_eliminate();
        }
    }

    #[doc(hidden)]
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.is_complete() {
            let mut result = VecDeque::new();
            for (&id, (data, len)) in self.known.iter() {
                let data_block = copy_to_pooled_block(&self.mem_pool, &data[..*len])?;
                let packet = FecPacket::from_pooled_blocks(
                    id,
                    Some(data_block),
                    *len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                )
                .ok()?;
                result.push_back(packet);
            }
            Some(result)
        } else {
            None
        }
    }

    #[doc(hidden)]
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    fn is_complete(&self) -> bool {
        let Some(anchor) = self.active_anchor else {
            return false;
        };
        self.known.len() >= self.k
            && self.known.keys().all(|&id| id_is_in_window(self.k, self.depth, anchor, id))
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u16]) -> Vec<(usize, u64)> {
        coeffs
            .iter()
            .enumerate()
            .take(self.k)
            .filter_map(|(j, &c)| {
                let sid = self.source_id_for(base_id, j);
                if c != 0 && !self.known.contains_key(&sid) {
                    Some((j, sid))
                } else {
                    None
                }
            })
            .collect()
    }

    fn try_solve_equation(&mut self, eq: &mut Equation16) -> bool {
        // Subtract known sources from equation data using GF(2^16) operations
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = self.source_id_for(eq.base_id, j);
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let source_len = ::core::cmp::min(eq.len, *klen);
                if source_len > 0 {
                    gf16_mul_scalar_slice_padded(
                        *coeff,
                        &kdata[..source_len],
                        &mut eq.data[..eq.len],
                    );
                }
                *coeff = 0;
            }
        }
        // Identify single unknown
        let mut last: Option<(usize, u64, u16)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = self.source_id_for(eq.base_id, j);
                if !self.known.contains_key(&sid) {
                    if last.is_some() {
                        return false;
                    }
                    last = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last {
            if self.known.contains_key(&sid) {
                return false;
            }
            let inv = gf_tables::gf16_inv(cj);
            let mut rec = PooledBlock::new(Arc::clone(&self.mem_pool));
            let sl = eq.len & !1;
            for b in &mut rec[..sl] {
                *b = 0;
            }
            if sl >= 2 {
                gf16_mul_scalar_slice_u16(inv, &eq.data[..sl], &mut rec[..sl]);
            }
            let mut rec2 = PooledBlock::new(Arc::clone(&self.mem_pool));
            if sl > 0 {
                rec2[..sl].copy_from_slice(&rec[..sl]);
            }
            let packet = match FecPacket::from_pooled_blocks(
                sid,
                Some(rec2),
                sl,
                true,
                None,
                0,
                Arc::clone(&self.mem_pool),
            ) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            self.known.insert(sid, (rec, sl));
            self.emit_q.push_back(packet);
            true
        } else {
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let equations_in_pass = self.equations.len();
            for _ in 0..equations_in_pass {
                let Some(mut eq) = self.equations.pop_front() else {
                    break;
                };
                if self.try_solve_equation(&mut eq) {
                    progress = true;
                } else {
                    self.equations.push_back(eq);
                }
            }
            if !progress {
                let _ = self.try_eliminate();
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
        let started = std::time::Instant::now();
        let solved = self.try_eliminate_unmeasured();
        record_decoder_solve(started, solved);
        solved
    }

    fn try_eliminate_unmeasured(&mut self) -> bool {
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = ::core::cmp::min(min_len, eq.len & !1);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len < 2 {
            return false;
        }
        if min_len > self.mem_pool.block_size() {
            return false;
        }
        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let u = unknowns.len();
        let m = self.equations.len();
        if m < u {
            return false;
        }

        let words = min_len / 2;
        let mut solutions = vec![Vec::with_capacity(words); u];
        let mut solved_any = false;

        for w in 0..words {
            // Build A (m x u) and y (m) for this word index
            let mut a = vec![vec![0u16; u]; m];
            let mut y = vec![0u16; m];
            for (i, eq) in self.equations.iter().enumerate() {
                let Some(byte_offset) = w.checked_mul(2) else {
                    return false;
                };
                let Some(end) = byte_offset.checked_add(2) else {
                    return false;
                };
                if end <= eq.len {
                    let b0 = eq.data[byte_offset] as u16;
                    let b1 = eq.data[byte_offset + 1] as u16;
                    y[i] = (b0 << 8) | b1;
                    for (col, &sid) in unknowns.iter().enumerate() {
                        for j in 0..self.k {
                            if self.source_id_for(eq.base_id, j) == sid {
                                a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                                break;
                            }
                        }
                    }
                }
            }
            // Gaussian elimination in GF(2^16)
            let mut row = 0usize;
            let mut pivot_rows = vec![usize::MAX; u];
            for col in 0..u {
                // find pivot
                let mut pivot = None;
                #[allow(clippy::needless_range_loop)]
                for r in row..m {
                    if a[r][col] != 0 {
                        pivot = Some(r);
                        break;
                    }
                }
                if let Some(pr) = pivot {
                    if pr != row {
                        a.swap(pr, row);
                        y.swap(pr, row);
                    }
                } else {
                    continue;
                }
                pivot_rows[col] = row;
                let inv = gf_tables::gf16_inv(a[row][col]);
                // scale
                for cell in a[row].iter_mut().take(u) {
                    *cell = gf_tables::gf16_mul(*cell, inv);
                }
                y[row] = gf_tables::gf16_mul(y[row], inv);
                // eliminate other rows (vectorized)
                for r in 0..m {
                    if r != row && a[r][col] != 0 {
                        let f = a[r][col];
                        // XOR row r with f * row(row)
                        let pivot_row = a[row].clone();
                        gf16_mul_slice(f, &pivot_row[..u], &mut a[r][..u]);
                        // Update RHS
                        let prody = gf_tables::gf16_mul(f, y[row]);
                        y[r] ^= prody;
                    }
                }
                row += 1;
                if row == m {
                    break;
                }
            }
            if pivot_rows.contains(&usize::MAX) {
                return false;
            }
            // Reduced rows hold the solution for their corresponding pivot columns.
            for col in 0..u {
                solutions[col].push(y[pivot_rows[col]]);
                solved_any = true;
            }
        }

        if !solved_any {
            return false;
        }
        // Materialize recovered unknowns as bytes
        for (col, &sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(&sid) {
                continue;
            }
            // Two bytes per GF16 word. Check the product itself, not only the result against the
            // block size, so an oversized word count cannot wrap into a small accepted length.
            let Some(sl) = words.checked_mul(2) else {
                return false;
            };
            if sl > self.mem_pool.block_size() {
                return false;
            }
            let mut buf = PooledBlock::new(Arc::clone(&self.mem_pool));
            for (w, &val) in solutions[col].iter().enumerate() {
                let Some(byte_offset) = w.checked_mul(2) else {
                    return false;
                };
                let Some(end) = byte_offset.checked_add(2) else {
                    return false;
                };
                if end > buf.len() {
                    return false;
                }
                buf[byte_offset] = (val >> 8) as u8;
                buf[byte_offset + 1] = (val & 0xff) as u8;
            }
            let mut buf2 = PooledBlock::new(Arc::clone(&self.mem_pool));
            buf2[..sl].copy_from_slice(&buf[..sl]);
            let packet = match FecPacket::from_pooled_blocks(
                sid,
                Some(buf2),
                sl,
                true,
                None,
                0,
                Arc::clone(&self.mem_pool),
            ) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            self.known.insert(sid, (buf, sl));
            self.emit_q.push_back(packet);
        }
        self.equations.clear();
        true
    }
}
