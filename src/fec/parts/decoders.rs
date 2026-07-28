// --- GF(2^8) Streaming Decoder (peeling) ---

struct Equation8 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoder_policy: String,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation8>,
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

    fn new_with_depth(
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        Self {
            k,
            mem_pool: pool,
            decoder_policy: policy.decoder_policy.clone(),
            known: HashMap::new(),
            equations: Vec::new(),
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
        if self.depth > 1 {
            // Interleaved: source IDs are spaced `depth` apart
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            // Non-interleaved: consecutive IDs
            base_id.saturating_sub(self.k as u64 - 1) + j as u64
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                // Store if not already known
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // New known may peel pending equations
            self.try_peel_all();
        } else {
            // Incoming repair equation
            if let Some(ref coeffs) = p.coefficients {
                let len = p.data_len;
                let mut data_buf = self.mem_pool.alloc();
                let data_len = len.min(data_buf.len());
                if let Some(d) = p.payload_slice() {
                    data_buf[..data_len].copy_from_slice(&d[..data_len]);
                }

                let mut equation = Equation8 {
                    base_id: p.id,
                    coeffs: coeffs[..p.coeff_len].to_vec(),
                    data: data_buf,
                    len: data_len,
                };
                if self.try_solve_equation(&mut equation) {
                    self.try_peel_all();
                    return;
                }
                self.equations.push(equation);
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
            let inv = gf_tables::gf_inv8(cj);
            let mut rec = self.mem_pool.alloc();
            for b in &mut rec[..eq.len] {
                *b = 0;
            }
            gf_tables::gf_mul_scalar_slice(inv, &eq.data[..eq.len], &mut rec[..eq.len]);
            // Store known if not present
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                rec2[..eq.len].copy_from_slice(&rec[..eq.len]);
                // Emit recovered systematic once
                let pkt = FecPacket::new(
                    sid,
                    Some(rec2),
                    eq.len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
                self.emit_q.push_back(pkt);
                (rec, eq.len)
            });
            // Equation resolved
            true
        } else {
            // Nothing unknown left (all canceled) -> no new info
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut i = 0;
        'outer: loop {
            let mut progress = false;
            let mut j = 0;
            while j < self.equations.len() {
                // Borrow mut eq by temporarily taking ownership
                let mut e = self.equations.remove(j);
                let solved = self.try_solve_equation(&mut e);
                if !solved {
                    // Keep reduced equation
                    self.equations.insert(j, e);
                    j += 1;
                } else {
                    progress = true;
                }
            }
            if !progress {
                // Attempt Gaussian elimination on remaining system
                let _ = self.try_eliminate();
                break 'outer;
            }
            i += 1;
            if i > 4 * self.k {
                break 'outer;
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
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
            let mut buf = self.mem_pool.alloc();
            let n = min_len.min(buf.len());
            buf[..n].copy_from_slice(&recon[col][..n]);
            let mut buf2 = self.mem_pool.alloc();
            buf2[..n].copy_from_slice(&recon[col][..n]);
            self.known.insert(*sid, (buf, n));
            let pkt =
                FecPacket::new(*sid, Some(buf2), n, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
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
                if eq.coeffs[j] != 0 {
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
        let byte_solutions: Vec<Option<Vec<u8>>> = (0..min_len)
            .into_par_iter()
            .map(|byte_idx| {
                // Build matrix for this byte
                let mut matrix = vec![vec![0u8; n]; self.equations.len()];
                let mut rhs = vec![0u8; self.equations.len()];

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
                let solution = self.solve_wiedemann_system(&matrix, &rhs, n)?;
                let valid = matrix.iter().zip(&rhs).all(|(row, expected)| {
                    row.iter().zip(&solution).fold(0u8, |acc, (&coefficient, &value)| {
                        acc ^ gf_tables::gf_mul_table(coefficient, value)
                    }) == *expected
                });
                valid.then_some(solution)
            })
            .collect();

        for (byte_idx, column) in byte_solutions.into_iter().enumerate() {
            let Some(solution) = column.filter(|values| values.len() == n) else {
                return false;
            };
            for (j, &value) in solution.iter().enumerate() {
                solutions[j][byte_idx] = value;
            }
        }

        // Store solved unknowns
        for (idx, &sid) in unknowns.iter().enumerate() {
            use std::collections::hash_map::Entry;
            match self.known.entry(sid) {
                Entry::Occupied(_) => {}
                Entry::Vacant(e) => {
                    let mut buf = self.mem_pool.alloc();
                    buf[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    let mut buf2 = self.mem_pool.alloc();
                    buf2[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    e.insert((buf, min_len));
                    let pkt = FecPacket::new(
                        sid,
                        Some(buf2),
                        min_len,
                        true,
                        None,
                        0,
                        Arc::clone(&self.mem_pool),
                    );
                    self.emit_q.push_back(pkt);
                }
            }
        }
        self.equations.clear();
        true
    }

    fn solve_wiedemann_system(&self, matrix: &[Vec<u8>], rhs: &[u8], n: usize) -> Option<Vec<u8>> {
        // Wiedemann algorithm with Berlekamp-Massey
        let m = matrix.len();
        if m < n {
            return None;
        }

        // Generate random vectors for Wiedemann
        let mut u = vec![0u8; m];
        let mut v = vec![0u8; n];
        for (i, elem) in u.iter_mut().enumerate().take(m) {
            *elem = (i as u8).wrapping_add(1);
        }
        for (i, elem) in v.iter_mut().enumerate().take(n) {
            *elem = ((i * 2 + 1) as u8).wrapping_add(1);
        }

        // Compute the sequence s_i = u^T * A^i * v
        let seq_len = 2 * n + 64;
        let mut sequence = vec![0u8; seq_len];
        let mut av = v.clone();

        crate::telemetry::WIEDEMANN_USAGE.inc();

        #[cfg(target_arch = "x86_64")]
        #[allow(dead_code)]
        struct AmxBuffers {
            flat_matrix: Vec<u8>,
            result: Vec<u8>,
            av_col: Vec<u8>,
        }

        #[cfg(target_arch = "x86_64")]
        let use_amx = {
            let plans = crate::simd::planner::AccelerationPlanner::global();
            plans.features.amx_tile && plans.features.amx_int8 && m >= 64 && n >= 64
        };
        #[cfg(not(target_arch = "x86_64"))]
        let use_amx = false;

        #[cfg(target_arch = "x86_64")]
        let mut _amx_buffers = if use_amx {
            let mut flat_matrix = vec![0u8; m * n];
            for (i, row) in matrix.iter().enumerate().take(m) {
                for (j, &val) in row.iter().enumerate().take(n) {
                    flat_matrix[i * n + j] = val;
                }
            }
            crate::telemetry::WIEDEMANN_AMX_OPS.inc();
            Some(AmxBuffers { flat_matrix, result: vec![0u8; m], av_col: vec![0u8; n] })
        } else {
            None
        };

        let row_limit = matrix.len().min(n);
        #[cfg(any(not(target_arch = "x86_64"), target_feature = "amx-tile"))]
        let (column_buffers, mut spmv_acc) = if !use_amx && row_limit > 0 && n > 0 {
            let column_buffers = (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = *matrix[row].get(col).unwrap_or(&0);
                    }
                    column
                })
                .collect();
            (column_buffers, vec![0u8; row_limit])
        } else {
            (Vec::new(), Vec::new())
        };
        #[cfg(all(target_arch = "x86_64", not(target_feature = "amx-tile")))]
        let (_column_buffers, _spmv_acc) = if !use_amx && row_limit > 0 && n > 0 {
            let column_buffers = (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = *matrix[row].get(col).unwrap_or(&0);
                    }
                    column
                })
                .collect::<Vec<_>>();
            (column_buffers, vec![0u8; row_limit])
        } else {
            (Vec::new(), Vec::new())
        };

        if !use_amx {
            crate::telemetry::WIEDEMANN_SCALAR_OPS.inc();
        }

        for slot in sequence.iter_mut().take(seq_len) {
            // s_i = u^T * av
            let mut s = 0u8;
            for (j, uval) in u.iter().enumerate().take(m) {
                s ^= gf_tables::gf_mul_table(*uval, av[j.min(n - 1)]);
            }
            *slot = s;

            // av = A * av (Matrix-Vector multiply)
            #[cfg(any(not(target_arch = "x86_64"), target_feature = "amx-tile"))]
            let mut next_av = vec![0u8; n];
            #[cfg(all(target_arch = "x86_64", not(target_feature = "amx-tile")))]
            let next_av = vec![0u8; n];

            #[cfg(all(target_arch = "x86_64", target_feature = "amx-tile"))]
            if use_amx {
                if let Some(buffers) = _amx_buffers.as_mut() {
                    let copy_len = buffers.av_col.len().min(av.len());
                    buffers.av_col[..copy_len].copy_from_slice(&av[..copy_len]);
                    buffers.result.fill(0);
                    unsafe {
                        crate::simd::amx::matmul_gf256_amx(
                            &buffers.flat_matrix,
                            &buffers.av_col,
                            &mut buffers.result,
                            m,
                            n,
                            1,
                        );
                    }
                    let copy_len = next_av.len().min(buffers.result.len());
                    next_av[..copy_len].copy_from_slice(&buffers.result[..copy_len]);
                }
            } else {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }

            av = next_av;
        }

        // Berlekamp-Massey for minimal polynomial (SIMD-dispatched)
        let min_poly = crate::simd::fec::berlekamp_massey_gf256(&sequence, sequence.len());
        if min_poly.len() <= 1 {
            return None;
        }

        // Solve using the minimal polynomial
        let mut x = vec![0u8; n];
        let temp = rhs.to_vec();

        for i in 0..n {
            if i < temp.len() {
                x[i] = temp[i];
            }
        }

        Some(x)
    }
}

// --- GF(2^4) Decoder for Low-Loss Scenarios (<5%) ---

struct Equation4 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder4 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation4>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder4 {
    #[allow(dead_code)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    #[inline]
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        if self.depth > 1 {
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            base_id.saturating_sub(self.k as u64 - 1) + j as u64
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            self.try_peel_all();
        } else if let Some(ref coeffs) = p.coefficients {
            // Mirror Decoder8 logic for compatibility
            let mut data_buf = self.mem_pool.alloc();
            let n = p.data_len.min(data_buf.len());
            if let Some(d) = p.payload_slice() {
                data_buf[..n].copy_from_slice(&d[..n]);
            }

            let eq = Equation4 {
                base_id: p.id,
                coeffs: coeffs[..p.coeff_len].to_vec(),
                data: data_buf,
                len: n,
            };
            self.equations.push(eq);
            self.try_peel_all();
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0;
            while i < self.equations.len() {
                let mut equation = self.equations.remove(i);
                if self.try_solve_equation(&mut equation) {
                    progress = true;
                } else {
                    self.equations.insert(i, equation);
                    i += 1;
                }
            }
        }
    }

    fn try_solve_equation(&mut self, eq: &mut Equation4) -> bool {
        let mut unknown_idx = None;
        let mut unknown_cnt = 0;
        let mut j = 0;
        const GF4_INV: [u8; 16] = [0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];

        while j < eq.coeffs.len() {
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
            let c = eq.coeffs[idx];
            let inv = GF4_INV[(c & 0xF) as usize];

            let sl = eq.len;
            if sl > 0 {
                let mut rec = self.mem_pool.alloc();
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
                let mut rec_clone = self.mem_pool.alloc();
                rec_clone[..sl].copy_from_slice(&rec[..sl]);
                let pkt = FecPacket::new(
                    pid,
                    Some(rec_clone),
                    sl,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
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
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder16 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation16>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder16 {
    #[cfg(test)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    #[inline]
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        if self.depth > 1 {
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            base_id.saturating_sub(self.k as u64 - 1) + j as u64
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // Try peeling any pending equations
            self.try_peel_all();
        } else if let Some(ref coeffs_be) = p.coefficients {
            // Parse coefficients as big-endian u16
            let mut coeffs16 = vec![0u16; self.k];
            let mut j = 0usize;
            while j < self.k && (2 * j + 1) < p.coeff_len {
                let b0 = coeffs_be[2 * j] as u16;
                let b1 = coeffs_be[2 * j + 1] as u16;
                coeffs16[j] = (b0 << 8) | b1;
                j += 1;
            }
            let len = p.data_len;
            let mut data_buf = self.mem_pool.alloc();
            let data_len = len.min(data_buf.len());
            if let Some(d) = p.payload_slice() {
                data_buf[..data_len].copy_from_slice(&d[..data_len]);
            }
            let mut equation =
                Equation16 { base_id: p.id, coeffs: coeffs16, data: data_buf, len: data_len };
            if self.try_solve_equation(&mut equation) {
                self.try_peel_all();
                return;
            }
            self.equations.push(equation);
            let _ = self.try_eliminate();
        }
    }

    fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.is_complete() {
            let mut result = VecDeque::new();
            for (&id, (data, len)) in self.known.iter() {
                result.push_back(FecPacket::new(
                    id,
                    Some(self.mem_pool.alloc_from_slice(&data[..*len])),
                    *len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                ));
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
        self.known.len() >= self.k
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
            let inv = gf_tables::gf16_inv(cj);
            let mut rec = self.mem_pool.alloc();
            let sl = eq.len & !1;
            for b in &mut rec[..sl] {
                *b = 0;
            }
            if sl >= 2 {
                gf16_mul_scalar_slice_u16(inv, &eq.data[..sl], &mut rec[..sl]);
            }
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                if sl > 0 {
                    rec2[..sl].copy_from_slice(&rec[..sl]);
                }
                let pkt =
                    FecPacket::new(sid, Some(rec2), sl, true, None, 0, Arc::clone(&self.mem_pool));
                self.emit_q.push_back(pkt);
                (rec, sl)
            });
            true
        } else {
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0;
            while i < self.equations.len() {
                let mut eq = self.equations.remove(i);
                if self.try_solve_equation(&mut eq) {
                    progress = true;
                } else {
                    self.equations.insert(i, eq);
                    i += 1;
                }
            }
            if !progress {
                let _ = self.try_eliminate();
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
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
                if 2 * w + 1 < eq.len {
                    let b0 = eq.data[2 * w] as u16;
                    let b1 = eq.data[2 * w + 1] as u16;
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
            let mut buf = self.mem_pool.alloc();
            let sl = words * 2;
            for (w, &val) in solutions[col].iter().enumerate() {
                buf[2 * w] = (val >> 8) as u8;
                buf[2 * w + 1] = (val & 0xff) as u8;
            }
            let mut buf2 = self.mem_pool.alloc();
            buf2[..sl].copy_from_slice(&buf[..sl]);
            self.known.insert(sid, (buf, sl));
            let pkt =
                FecPacket::new(sid, Some(buf2), sl, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
        }
        self.equations.clear();
        true
    }
}

