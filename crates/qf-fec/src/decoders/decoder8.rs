use super::{
    anchor_is_valid, record_decoder_solve, source_id_for_params, validate_decoder_dimensions,
};
use crate::codecs::FecPacket;
use crate::gf_tables;
use crate::policy::FecRuntimePolicy;
use crate::wire;
use qf_memory_pool::{MemoryPool, PooledBlock};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

struct Equation8 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: PooledBlock,
    len: usize,
}

/// Independent deterministic projector vectors tried before the Wiedemann solve gives up.
///
/// Scalar Wiedemann can fail for a particular projector even on a full-rank system, so a single
/// attempt would push solvable systems onto the Gaussian fallback. Four rounds cover the cases in
/// the regression suite while keeping the worst case bounded at a small multiple of one solve.
const WIEDEMANN_PROJECTION_ROUNDS: usize = 4;

#[doc(hidden)]
pub struct WiedemannScratch {
    #[doc(hidden)]
    pub column_buffers: Vec<Vec<u8>>,
    #[doc(hidden)]
    pub spmv_acc: Vec<u8>,
}

impl WiedemannScratch {
    fn from_lookup(eq_coeff_lookup: &[Vec<Option<u8>>], n: usize) -> Self {
        let row_limit = eq_coeff_lookup.len().min(n);
        let column_buffers = if row_limit > 0 && n > 0 {
            (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = eq_coeff_lookup[row].get(col).copied().flatten().unwrap_or(0);
                    }
                    column
                })
                .collect()
        } else {
            Vec::new()
        };
        let spmv_acc = if row_limit > 0 { vec![0u8; row_limit] } else { Vec::new() };
        if !column_buffers.is_empty() {
            qf_telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS.inc_by(column_buffers.len() as u64);
        }
        if !spmv_acc.is_empty() {
            qf_telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.inc();
        }
        Self { column_buffers, spmv_acc }
    }

    #[cfg(any(test, feature = "rust-tests", feature = "benches"))]
    #[doc(hidden)]
    pub fn from_matrix(matrix: &[Vec<u8>], n: usize) -> Self {
        let row_limit = matrix.len().min(n);
        let column_buffers = if row_limit > 0 && n > 0 {
            (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = matrix[row].get(col).copied().unwrap_or(0);
                    }
                    column
                })
                .collect()
        } else {
            Vec::new()
        };
        let spmv_acc = if row_limit > 0 { vec![0u8; row_limit] } else { Vec::new() };
        if !column_buffers.is_empty() {
            qf_telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS.inc_by(column_buffers.len() as u64);
        }
        if !spmv_acc.is_empty() {
            qf_telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.inc();
        }
        Self { column_buffers, spmv_acc }
    }

    #[inline]
    #[doc(hidden)]
    pub fn clear_spmv_acc(&mut self) {
        self.spmv_acc.fill(0);
    }
}

#[inline]
#[doc(hidden)]
pub fn multiply_gf256_with_scratch(
    scratch: &mut WiedemannScratch,
    vector: &[u8],
    output: &mut [u8],
) {
    output.fill(0);
    if scratch.column_buffers.is_empty() || scratch.spmv_acc.is_empty() {
        return;
    }

    scratch.clear_spmv_acc();
    let limit = scratch.column_buffers.len().min(vector.len());
    for (col_idx, &coeff) in vector.iter().enumerate().take(limit) {
        if coeff != 0 {
            gf_tables::gf_mul_scalar_slice(
                coeff,
                &scratch.column_buffers[col_idx],
                &mut scratch.spmv_acc,
            );
        }
    }

    let copy = scratch.spmv_acc.len().min(output.len());
    output[..copy].copy_from_slice(&scratch.spmv_acc[..copy]);
}

#[doc(hidden)]
pub struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    pub decoder_policy: String,
    known: HashMap<u64, (PooledBlock, usize)>,
    equations: VecDeque<Equation8>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved, >1 = interleaved mode).
    /// Source IDs in a block's window are spaced `depth` apart.
    depth: usize,
}

impl Decoder8 {
    // Called from fec/tests.rs (cfg(test)) and fec/mod.rs self-use; allow suppresses dead_code in non-test builds.
    #[doc(hidden)]
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(k, pool, &policy)
    }

    #[doc(hidden)]
    pub fn new_with_policy(k: usize, pool: Arc<MemoryPool>, policy: &FecRuntimePolicy) -> Self {
        Self::new_with_depth(k, pool, policy, 1)
    }

    fn rejected(pool: Arc<MemoryPool>, policy: &FecRuntimePolicy) -> Self {
        Self {
            k: 0,
            mem_pool: pool,
            decoder_policy: policy.decoder_policy.clone(),
            known: HashMap::new(),
            equations: VecDeque::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    #[doc(hidden)]
    pub fn new_with_depth(
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        if validate_decoder_dimensions(k, depth, wire::MAX_GF8_BLOCK_SOURCE_COUNT).is_err() {
            return Self::rejected(pool, policy);
        }
        Self {
            k,
            mem_pool: pool,
            decoder_policy: policy.decoder_policy.clone(),
            known: HashMap::new(),
            equations: VecDeque::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    /// Resolve coefficient index `j` to the actual source packet ID.
    ///
    /// In interleaved mode (depth > 1), source IDs in a block's window are
    /// spaced `depth` apart: base_id - (k-1-j) * depth.
    /// In non-interleaved mode (depth = 1), this simplifies to base_id - k + 1 + j.
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
            // New known may peel pending equations
            self.try_peel_all();
        } else {
            // Incoming repair equation
            if let Some(ref coeffs) = p.coefficients {
                let len = p.data_len;
                let Some(d) = p.payload_slice() else {
                    return;
                };
                let Some(coeffs) = coeffs.get(..p.coeff_len) else {
                    return;
                };
                if p.coeff_len != self.k
                    || len > self.mem_pool.block_size()
                    || d.len() < len
                    || !anchor_is_valid(self.k, self.depth, p.id)
                {
                    return;
                }
                let mut data_buf = PooledBlock::new(Arc::clone(&self.mem_pool));
                data_buf[..len].copy_from_slice(&d[..len]);

                let mut equation =
                    Equation8 { base_id: p.id, coeffs: coeffs.to_vec(), data: data_buf, len };
                if self.try_solve_equation(&mut equation) {
                    self.try_peel_all();
                    return;
                }
                self.equations.push_back(equation);
                let _ = self.try_eliminate();
            }
        }
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u8]) -> Vec<(usize, u64)> {
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

    fn try_solve_equation(&mut self, eq: &mut Equation8) -> bool {
        // Subtract known sources from equation data; zero-out corresponding coeffs
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = self.source_id_for(eq.base_id, j);
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let sl = ::core::cmp::min(eq.len, *klen);
                gf_tables::gf_mul_scalar_slice(*coeff, &kdata[..sl], &mut eq.data[..sl]);
                *coeff = 0;
            }
        }
        // Count unknowns
        let mut last_idx: Option<(usize, u64, u8)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = self.source_id_for(eq.base_id, j);
                if !self.known.contains_key(&sid) {
                    if last_idx.is_some() {
                        // More than one unknown remains
                        return false;
                    }
                    last_idx = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last_idx {
            // Solve for single unknown sid: x = cj^{-1} * eq.data
            if self.known.contains_key(&sid) {
                return false;
            }
            let inv = gf_tables::gf_inv8(cj);
            let mut rec = PooledBlock::new(Arc::clone(&self.mem_pool));
            for b in &mut rec[..eq.len] {
                *b = 0;
            }
            gf_tables::gf_mul_scalar_slice(inv, &eq.data[..eq.len], &mut rec[..eq.len]);
            let mut rec2 = PooledBlock::new(Arc::clone(&self.mem_pool));
            rec2[..eq.len].copy_from_slice(&rec[..eq.len]);
            let packet = match FecPacket::from_pooled_blocks(
                sid,
                Some(rec2),
                eq.len,
                true,
                None,
                0,
                Arc::clone(&self.mem_pool),
            ) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            self.known.insert(sid, (rec, eq.len));
            self.emit_q.push_back(packet);
            // Equation resolved
            true
        } else {
            // Nothing unknown left (all canceled) -> no new info
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut pass = 0;
        'outer: loop {
            let mut progress = false;
            let equations_in_pass = self.equations.len();
            for _ in 0..equations_in_pass {
                let Some(mut e) = self.equations.pop_front() else {
                    break;
                };
                let solved = self.try_solve_equation(&mut e);
                if !solved {
                    self.equations.push_back(e);
                } else {
                    progress = true;
                }
            }
            if !progress {
                // Attempt Gaussian elimination on remaining system
                let _ = self.try_eliminate();
                break 'outer;
            }
            pass += 1;
            if pass > self.k.saturating_mul(4) {
                break 'outer;
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
        // Decoder policy via ENV: QUICFUSCATE_FEC_DECODER = gauss|wiedemann|auto (default)
        match self.decoder_policy.to_ascii_lowercase().as_str() {
            "wiedemann" => {
                if self.try_eliminate_wiedemann() {
                    return true;
                }
                // Fallback to Gaussian elimination below
            }
            "gauss" => { /* force Gaussian below */ }
            _ => {
                if self.equations.len() > 32 && self.try_eliminate_wiedemann() {
                    return true;
                }
            }
        }

        // Collect unknown ids from all equations
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = ::core::cmp::min(min_len, eq.len);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len == 0 {
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

        // Build coefficient matrix A (m x u)
        let mut a = vec![vec![0u8; u]; m];
        for (i, eq) in self.equations.iter().enumerate() {
            for (col, sid) in unknowns.iter().enumerate() {
                // Find which coefficient index j maps to this sid
                for j in 0..self.k {
                    if self.source_id_for(eq.base_id, j) == *sid {
                        a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                        break;
                    }
                }
            }
        }

        // Solve ALL byte columns with ONE augmented Gaussian elimination in
        // GF(2^8) (TODO-899). The previous loop re-ran elimination per byte
        // column, cloning the m x u matrix each time: O(B * u^2 * m). The row
        // operations are identical for every RHS, so batching all B columns
        // into one augmented matrix costs O(u^2 * m + B * u * m) - the
        // asymptotic optimum for dense elimination.
        let mut yb: Vec<Vec<u8>> = vec![vec![0u8; min_len]; m];
        for (i, eq) in self.equations.iter().enumerate() {
            let eq_len = eq.len;
            let eq_data = &eq.data;
            for b in 0..min_len {
                let mut rhs = if b < eq_len { eq_data[b] } else { 0 };
                for j in 0..self.k {
                    let cj = *eq.coeffs.get(j).unwrap_or(&0);
                    if cj == 0 {
                        continue;
                    }
                    let sid = self.source_id_for(eq.base_id, j);
                    if let Some((ref kd, klen)) = self.known.get(&sid) {
                        if b < *klen {
                            rhs ^= gf_tables::gf_mul_table(cj, kd[b]);
                        }
                    }
                }
                yb[i][b] = rhs;
            }
        }

        let mut ab = a.clone();
        let mut row = 0usize;
        let mut piv_row_for_col = vec![usize::MAX; u];

        for (col, piv_slot) in piv_row_for_col.iter_mut().enumerate().take(u) {
            // Find pivot
            let mut pivot_row = None;
            for (r_idx, rref) in ab.iter().enumerate().skip(row).take(m.saturating_sub(row)) {
                if rref[col] != 0 {
                    pivot_row = Some(r_idx);
                    break;
                }
            }

            if let Some(pr) = pivot_row {
                if pr != row {
                    ab.swap(pr, row);
                    yb.swap(pr, row);
                }
                *piv_slot = row;

                let pivot = ab[row][col];
                let pivot_inv = gf_tables::gf_inv8(pivot);

                // Scale pivot row
                for cell in ab[row].iter_mut().take(u) {
                    *cell = gf_tables::gf_mul_table(*cell, pivot_inv);
                }
                for cell in yb[row].iter_mut() {
                    *cell = gf_tables::gf_mul_table(*cell, pivot_inv);
                }

                // Eliminate column in other rows (SIMD-accelerated multiply-and-XOR)
                let pivot_row_snapshot = ab[row].clone();
                for (r_idx, rrow) in ab.iter_mut().enumerate() {
                    if r_idx != row {
                        let factor = rrow[col];
                        if factor != 0 {
                            // rrow[0..u] ^= factor * pivot_row_snapshot[0..u]
                            gf_tables::gf_mul_scalar_slice(
                                factor,
                                &pivot_row_snapshot[..u],
                                &mut rrow[..u],
                            );
                            // Same factor applies to every RHS column.
                            let pivot_rhs = yb[row].clone();
                            for (cell, pv) in yb[r_idx].iter_mut().zip(pivot_rhs.iter()) {
                                *cell ^= gf_tables::gf_mul_table(factor, *pv);
                            }
                        }
                    }
                }
                row += 1;
                if row == m {
                    break;
                }
            }
        }

        // Extract solutions where pivot exists
        let mut recon: Vec<Vec<u8>> = vec![vec![0u8; min_len]; u];
        let mut solved_any = false;
        for (col, &r) in piv_row_for_col.iter().enumerate().take(u) {
            if r == usize::MAX {
                return false;
            }
            recon[col].copy_from_slice(&yb[r]);
            solved_any = true;
        }

        if !solved_any {
            return false;
        }

        // Materialize recovered unknowns
        for (col, sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(sid) {
                continue;
            }
            let mut buf = PooledBlock::new(Arc::clone(&self.mem_pool));
            buf[..min_len].copy_from_slice(&recon[col][..min_len]);
            let mut buf2 = PooledBlock::new(Arc::clone(&self.mem_pool));
            buf2[..min_len].copy_from_slice(&recon[col][..min_len]);
            let packet = match FecPacket::from_pooled_blocks(
                *sid,
                Some(buf2),
                min_len,
                true,
                None,
                0,
                Arc::clone(&self.mem_pool),
            ) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            self.known.insert(*sid, (buf, min_len));
            self.emit_q.push_back(packet);
        }
        self.equations.clear();
        true
    }

    fn try_eliminate_wiedemann(&mut self) -> bool {
        use rayon::prelude::*;

        // Collect unknown source IDs.
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = ::core::cmp::min(min_len, eq.len);
            for j in 0..self.k {
                if eq.coeffs.get(j).copied().unwrap_or(0) != 0 {
                    let sid = self.source_id_for(eq.base_id, j);
                    if !self.known.contains_key(&sid) {
                        unknown_set.insert(sid);
                    }
                }
            }
        }

        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let n = unknowns.len();
        if n == 0 || self.equations.len() < n {
            return false;
        }

        // Precompute coefficient index for each (eq_idx, unknown_sid) pair
        // so the Rayon closure doesn't need &self.
        let eq_coeff_lookup: Vec<Vec<Option<u8>>> = self
            .equations
            .iter()
            .map(|eq| {
                unknowns
                    .iter()
                    .map(|&sid| {
                        for j in 0..self.k {
                            if self.source_id_for(eq.base_id, j) == sid {
                                return eq.coeffs.get(j).copied();
                            }
                        }
                        None
                    })
                    .collect()
            })
            .collect();

        // Block Wiedemann for parallel processing
        let _block_size = 32.min(n / 4 + 1);
        let mut solutions = vec![vec![0u8; min_len]; n];

        // Parallel byte-wise solve with Rayon (without mutable capture)
        let equation_count = self.equations.len();
        let rayon_workers = rayon::current_num_threads().max(1);
        let byte_chunk_len = min_len.div_ceil(rayon_workers).max(1);
        let byte_indices: Vec<usize> = (0..min_len).collect();
        let byte_solutions: Vec<Option<Vec<u8>>> = byte_indices
            .into_par_iter()
            .chunks(byte_chunk_len)
            .map_init(
                || WiedemannScratch::from_lookup(&eq_coeff_lookup, n),
                |scratch, byte_indices| {
                    byte_indices
                        .into_iter()
                        .map(|byte_idx| {
                            // Build matrix for this byte
                            let mut matrix = vec![vec![0u8; n]; equation_count];
                            let mut rhs = vec![0u8; equation_count];
                            qf_telemetry::WIEDEMANN_MATRIX_RHS_ALLOCS
                                .inc_by((equation_count + 1) as u64);

                            for (i, eq) in self.equations.iter().enumerate() {
                                if byte_idx < eq.len {
                                    rhs[i] = eq.data[byte_idx];
                                    for (j, _uid) in unknowns.iter().enumerate() {
                                        if let Some(coeff) = eq_coeff_lookup[i][j] {
                                            matrix[i][j] = coeff;
                                        }
                                    }
                                }
                            }

                            // Wiedemann solver with Berlekamp-Massey
                            let solution =
                                self.solve_wiedemann_system(&matrix, &rhs, n, scratch)?;
                            let valid = matrix.iter().zip(&rhs).all(|(row, expected)| {
                                row.iter().zip(&solution).fold(
                                    0u8,
                                    |acc, (&coefficient, &value)| {
                                        acc ^ gf_tables::gf_mul_table(coefficient, value)
                                    },
                                ) == *expected
                            });
                            valid.then_some(solution)
                        })
                        .collect::<Vec<_>>()
                },
            )
            .flatten()
            .collect();

        for (byte_idx, column) in byte_solutions.into_iter().enumerate() {
            let Some(solution) = column.filter(|values| values.len() == n) else {
                return false;
            };
            for (j, &value) in solution.iter().enumerate() {
                solutions[j][byte_idx] = value;
            }
        }

        if min_len > self.mem_pool.block_size() {
            return false;
        }

        // Store solved unknowns
        for (idx, &sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(&sid) {
                continue;
            }
            let mut buf = PooledBlock::new(Arc::clone(&self.mem_pool));
            buf[..min_len].copy_from_slice(&solutions[idx][..min_len]);
            let mut buf2 = PooledBlock::new(Arc::clone(&self.mem_pool));
            buf2[..min_len].copy_from_slice(&solutions[idx][..min_len]);
            let packet = match FecPacket::from_pooled_blocks(
                sid,
                Some(buf2),
                min_len,
                true,
                None,
                0,
                Arc::clone(&self.mem_pool),
            ) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            self.known.insert(sid, (buf, min_len));
            self.emit_q.push_back(packet);
        }
        self.equations.clear();
        true
    }

    #[doc(hidden)]
    pub fn solve_wiedemann_system(
        &self,
        matrix: &[Vec<u8>],
        rhs: &[u8],
        n: usize,
        scratch: &mut WiedemannScratch,
    ) -> Option<Vec<u8>> {
        // Wiedemann algorithm with Berlekamp-Massey
        let m = matrix.len();
        if n == 0 || m != n || rhs.len() != m || matrix.iter().any(|row| row.len() != n) {
            return None;
        }

        // Two n terms is the standard requirement for Berlekamp-Massey to recover a recurrence of
        // degree at most n.
        let seq_len = n.checked_mul(2)?;

        qf_telemetry::WIEDEMANN_USAGE.inc();
        qf_telemetry::WIEDEMANN_SCALAR_OPS.inc();
        qf_telemetry::WIEDEMANN_KRYLOV_ALLOCS.inc_by(3);

        let mut sequence = vec![0u8; seq_len];
        let mut krylov = vec![0u8; n];
        let mut next = vec![0u8; n];
        let mut projector = vec![0u8; m];
        let mut accumulator = vec![0u8; n];
        let mut spun = vec![0u8; n];
        qf_telemetry::WIEDEMANN_CANDIDATE_ALLOCS.inc_by(2);

        // Scalar Wiedemann projects the system onto a single sequence, so an unlucky projector can
        // expose a recurrence shorter than the true minimal polynomial of `b` under `A` and yield
        // a candidate that does not solve the system. A 3-cycle permutation over GF(256) is the
        // smallest example. Retrying with independent deterministic projectors recovers those
        // cases; determinism keeps decoding reproducible across peers.
        for round in 0..WIEDEMANN_PROJECTION_ROUNDS {
            for (index, element) in projector.iter_mut().enumerate() {
                let spread = (index as u32 + 1)
                    .wrapping_mul(2 * round as u32 + 1)
                    .wrapping_add(round as u32 * 37);
                // Never zero: an all-zero projector produces the zero sequence for every matrix.
                *element = ((spread % 255) as u8).wrapping_add(1);
            }

            // Krylov sequence s_i = u^T A^i b, built from the right-hand side. The polynomial we
            // need is the one annihilating `b` under `A`, and that is what makes the
            // back-substitution below a solution rather than a plausible-looking vector.
            krylov.copy_from_slice(rhs);
            for slot in sequence.iter_mut() {
                let mut projection = 0u8;
                for (index, &coefficient) in projector.iter().enumerate() {
                    projection ^= gf_tables::gf_mul_table(coefficient, krylov[index]);
                }
                *slot = projection;

                qf_telemetry::WIEDEMANN_ITERATION_ALLOCS.inc();
                multiply_gf256_with_scratch(scratch, &krylov, &mut next);
                krylov.copy_from_slice(&next);
            }

            // Berlekamp-Massey returns the connection polynomial `lambda` with `lambda[0] == 1`
            // and degree equal to the recurrence length, satisfying
            // `XOR_j lambda[j] * s_{i-j} == 0`.
            let lambda = qf_simd::fec::berlekamp_massey_gf256(&sequence, sequence.len());
            let Some(degree) = lambda.len().checked_sub(1).filter(|&degree| degree > 0) else {
                continue;
            };
            // A zero constant term means the reversed polynomial has no invertible leading term,
            // which is what a singular restriction of `A` to `b` looks like. Fail this round
            // rather than dividing by zero or shortening the degree, which would silently solve a
            // different system.
            let leading = lambda[degree];
            if leading == 0 {
                continue;
            }

            // With `f(A) b = 0` for the reversed polynomial `f` of degree `d`:
            //
            //   XOR_{j=0..d} lambda[j] A^(d-j) b = 0
            //   lambda[d] b = A * (XOR_{j=0..d-1} lambda[j] A^(d-1-j) b)
            //
            // so `x = lambda[d]^-1 * XOR_{j=0..d-1} lambda[j] A^(d-1-j) b` satisfies `A x = b`.
            // Subtraction is XOR in GF(2^8), so the rearrangement carries no sign. The sum is
            // accumulated by Horner's rule at one SpMV per degree step.
            accumulator.fill(0);
            for &coefficient in lambda.iter().take(degree) {
                multiply_gf256_with_scratch(scratch, &accumulator, &mut spun);
                for (slot, (&carried, &right)) in
                    accumulator.iter_mut().zip(spun.iter().zip(rhs.iter()))
                {
                    *slot = carried ^ gf_tables::gf_mul_table(coefficient, right);
                }
            }

            let inverse = gf_tables::gf_inv8(leading);
            if inverse == 0 {
                continue;
            }
            for value in accumulator.iter_mut() {
                *value = gf_tables::gf_mul_table(inverse, *value);
            }

            // Verify before returning. The caller validates every equation again before mutating
            // decoder state, but a solver that can return a non-solution is not a solver, and an
            // unverified candidate would make the fallback decision depend on luck.
            multiply_gf256_with_scratch(scratch, &accumulator, &mut spun);
            if spun == rhs {
                return Some(accumulator);
            }
        }

        None
    }
}

impl Decoder8 {
    /// Attempt recovery via Gaussian elimination and return recovered packets.
    #[doc(hidden)]
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        self.try_eliminate();
        if self.emit_q.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.emit_q))
        }
    }

    /// Drain all currently queued recovered packets without further elimination.
    #[doc(hidden)]
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    /// Returns true if enough source packets have been recovered to fill the block.
    #[cfg(any(test, feature = "rust-tests", feature = "benches"))]
    #[doc(hidden)]
    pub fn is_complete(&self) -> bool {
        self.known.len() >= self.k
    }
}
