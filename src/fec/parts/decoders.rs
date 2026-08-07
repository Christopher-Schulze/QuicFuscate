// --- GF(2^8) Streaming Decoder (peeling) ---

#[inline]
fn source_id_for_params(k: usize, depth: usize, base_id: u64, j: usize) -> Option<u64> {
    if k == 0 || j >= k || depth == 0 {
        return None;
    }
    if depth == 1 {
        let start = u64::try_from(k - 1).ok()?;
        base_id.checked_sub(start)?.checked_add(j as u64)
    } else {
        let span = (k - 1 - j).checked_mul(depth)?;
        base_id.checked_sub(u64::try_from(span).ok()?)
    }
}

#[inline]
fn anchor_is_valid(k: usize, depth: usize, anchor: u64) -> bool {
    k > 0
        && depth > 0
        && (k - 1)
            .checked_mul(depth)
            .and_then(|span| u64::try_from(span).ok())
            .is_some_and(|span| anchor >= span)
}

#[inline]
fn id_is_in_window(k: usize, depth: usize, anchor: u64, id: u64) -> bool {
    (0..k).any(|j| source_id_for_params(k, depth, anchor, j) == Some(id))
}

#[inline]
fn record_decoder_solve(started: std::time::Instant, solved: bool) {
    crate::telemetry::FEC_DECODER_SOLVE_ATTEMPTS.inc();
    crate::telemetry::FEC_DECODER_SOLVE_TIME_NS
        .inc_by(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    if solved {
        crate::telemetry::FEC_DECODER_SOLVE_SUCCESSES.inc();
    }
}

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

struct WiedemannScratch {
    column_buffers: Vec<Vec<u8>>,
    spmv_acc: Vec<u8>,
}

impl WiedemannScratch {
    fn from_lookup(eq_coeff_lookup: &[Vec<Option<u8>>], n: usize) -> Self {
        let row_limit = eq_coeff_lookup.len().min(n);
        let column_buffers = if row_limit > 0 && n > 0 {
            (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = eq_coeff_lookup[row]
                            .get(col)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                    }
                    column
                })
                .collect()
        } else {
            Vec::new()
        };
        let spmv_acc = if row_limit > 0 { vec![0u8; row_limit] } else { Vec::new() };
        if !column_buffers.is_empty() {
            crate::telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS
                .inc_by(column_buffers.len() as u64);
        }
        if !spmv_acc.is_empty() {
            crate::telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.inc();
        }
        Self { column_buffers, spmv_acc }
    }

    #[cfg(test)]
    fn from_matrix(matrix: &[Vec<u8>], n: usize) -> Self {
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
            crate::telemetry::WIEDEMANN_COLUMN_BUFFER_ALLOCS
                .inc_by(column_buffers.len() as u64);
        }
        if !spmv_acc.is_empty() {
            crate::telemetry::WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.inc();
        }
        Self { column_buffers, spmv_acc }
    }

    #[inline]
    fn clear_spmv_acc(&mut self) {
        self.spmv_acc.fill(0);
    }
}

#[inline]
fn multiply_gf256_with_scratch(
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

struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoder_policy: String,
    known: HashMap<u64, (PooledBlock, usize)>,
    equations: VecDeque<Equation8>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved, >1 = interleaved mode).
    /// Source IDs in a block's window are spaced `depth` apart.
    depth: usize,
}

impl Decoder8 {
    // Called from fec/tests.rs (cfg(test)) and fec/mod.rs self-use; allow suppresses dead_code in non-test builds.
    #[allow(dead_code)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(k, pool, &policy)
    }

    fn new_with_policy(k: usize, pool: Arc<MemoryPool>, policy: &FecRuntimePolicy) -> Self {
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

    fn new_with_depth(
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
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        source_id_for_params(self.k, self.depth, base_id, j).unwrap_or(0)
    }

    fn take_packet(&mut self, p: FecPacket) {
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

                let mut equation = Equation8 {
                    base_id: p.id,
                    coeffs: coeffs.to_vec(),
                    data: data_buf,
                    len,
                };
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
                let sl = core::cmp::min(eq.len, *klen);
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
            min_len = core::cmp::min(min_len, eq.len);
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

        // Solve per byte column using Gaussian elimination in GF(2^8)
        let mut recon: Vec<Vec<u8>> = vec![vec![0u8; min_len]; u];
        let mut solved_any = false;

        for b in 0..min_len {
            // Build RHS y with known contributions subtracted
            let mut y = vec![0u8; m];
            for (i, eq) in self.equations.iter().enumerate() {
                let mut rhs = if b < eq.len { eq.data[b] } else { 0 };
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
                y[i] = rhs;
            }

            // Copy A and y for elimination
            let mut ab = a.clone();
            let mut yb = y;
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
                    yb[row] = gf_tables::gf_mul_table(yb[row], pivot_inv);

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
                                yb[r_idx] ^= gf_tables::gf_mul_table(factor, yb[row]);
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
            for (col, &r) in piv_row_for_col.iter().enumerate().take(u) {
                if r == usize::MAX {
                    return false;
                }
                recon[col][b] = yb[r];
                solved_any = true;
            }
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
            min_len = core::cmp::min(min_len, eq.len);
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
                            crate::telemetry::WIEDEMANN_MATRIX_RHS_ALLOCS
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

    fn solve_wiedemann_system(
        &self,
        matrix: &[Vec<u8>],
        rhs: &[u8],
        n: usize,
        scratch: &mut WiedemannScratch,
    ) -> Option<Vec<u8>> {
        // Wiedemann algorithm with Berlekamp-Massey
        let m = matrix.len();
        if n == 0
            || m != n
            || rhs.len() != m
            || matrix.iter().any(|row| row.len() != n)
        {
            return None;
        }

        // Two n terms is the standard requirement for Berlekamp-Massey to recover a recurrence of
        // degree at most n.
        let seq_len = n.checked_mul(2)?;

        crate::telemetry::WIEDEMANN_USAGE.inc();
        crate::telemetry::WIEDEMANN_SCALAR_OPS.inc();
        crate::telemetry::WIEDEMANN_KRYLOV_ALLOCS.inc_by(3);

        let mut sequence = vec![0u8; seq_len];
        let mut krylov = vec![0u8; n];
        let mut next = vec![0u8; n];
        let mut projector = vec![0u8; m];
        let mut accumulator = vec![0u8; n];
        let mut spun = vec![0u8; n];
        crate::telemetry::WIEDEMANN_CANDIDATE_ALLOCS.inc_by(2);

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

                crate::telemetry::WIEDEMANN_ITERATION_ALLOCS.inc();
                multiply_gf256_with_scratch(scratch, &krylov, &mut next);
                krylov.copy_from_slice(&next);
            }

            // Berlekamp-Massey returns the connection polynomial `lambda` with `lambda[0] == 1`
            // and degree equal to the recurrence length, satisfying
            // `XOR_j lambda[j] * s_{i-j} == 0`.
            let lambda = crate::simd::fec::berlekamp_massey_gf256(&sequence, sequence.len());
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

// --- GF(2^4) Decoder for Low-Loss Scenarios (<5%) ---

struct Equation4 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: PooledBlock,
    len: usize,
}

struct Decoder4 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (PooledBlock, usize)>,
    equations: VecDeque<Equation4>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder4 {
    #[allow(dead_code)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
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

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
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
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        source_id_for_params(self.k, self.depth, base_id, j).unwrap_or(0)
    }

    fn take_packet(&mut self, p: FecPacket) {
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

            let eq = Equation4 {
                base_id: p.id,
                coeffs: coeffs.to_vec(),
                data: data_buf,
                len: n,
            };
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
                    crate::simd::galois::gf4_mul_xor(&kdata[..sl], c, &mut eq.data[..sl]);
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
                    crate::simd::galois::gf4_mul(
                        &eq.data[k..k + chunk],
                        inv,
                        &mut rec[k..k + chunk],
                    );
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

// GF(2^16) Decoder for higher error correction modes
struct Equation16 {
    base_id: u64,
    coeffs: Vec<u16>,
    data: PooledBlock,
    len: usize,
}

struct Decoder16 {
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
    #[cfg(test)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
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

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
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
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        source_id_for_params(self.k, self.depth, base_id, j).unwrap_or(0)
    }

    fn take_packet(&mut self, p: FecPacket) {
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
            let mut equation =
                Equation16 { base_id: p.id, coeffs: coeffs16, data: data_buf, len };
            if self.try_solve_equation(&mut equation) {
                self.try_peel_all();
                return;
            }
            self.equations.push_back(equation);
            let _ = self.try_eliminate();
        }
    }

    fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
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

    fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    fn is_complete(&self) -> bool {
        let Some(anchor) = self.active_anchor else {
            return false;
        };
        self.known.len() >= self.k
            && self
                .known
                .keys()
                .all(|&id| id_is_in_window(self.k, self.depth, anchor, id))
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
                let source_len = core::cmp::min(eq.len, *klen);
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
            min_len = core::cmp::min(min_len, eq.len & !1);
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
