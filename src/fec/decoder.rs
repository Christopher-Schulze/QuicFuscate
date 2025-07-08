// --- Encoder & Decoder ---

/// Generates repair packets from source packets using a Cauchy matrix for coefficients.
pub struct Encoder {
    k: usize, // Number of source packets
    n: usize, // Total packets (source + repair)
    source_window: VecDeque<Packet>,
}

pub struct Encoder16 {
    k: usize,
    n: usize,
    source_window: VecDeque<Packet>,
}

impl Encoder16 {
    fn new(k: usize, n: usize) -> Self {
        Self {
            k,
            n,
            source_window: VecDeque::with_capacity(k),
        }
    }

    fn add_source_packet(&mut self, packet: Packet) {
        if self.source_window.len() == self.k {
            self.source_window.pop_front();
        }
        self.source_window.push_back(packet);
    }

    fn generate_repair_packet(
        &self,
        repair_packet_index: usize,
        mem_pool: &Arc<MemoryPool>,
    ) -> Option<Packet> {
        if self.source_window.len() < self.k {
            return None;
        }
        let packet_len = self.source_window[0].len;
        let mut repair_data = mem_pool.alloc();
        repair_data.iter_mut().for_each(|b| *b = 0);

        let coeffs = self.generate_cauchy_coefficients(repair_packet_index);
        for (i, src) in self.source_window.iter().enumerate() {
            let coeff = coeffs[i];
            if coeff == 0 {
                continue;
            }
            let data = &src.data[..packet_len];
            let mut j = 0;
            while j + 1 < packet_len {
                let s = u16::from_be_bytes([data[j], data[j + 1]]);
                let r = u16::from_be_bytes([repair_data[j], repair_data[j + 1]]);
                let v = gf16_mul_add(coeff, s, r);
                let b = v.to_be_bytes();
                repair_data[j] = b[0];
                repair_data[j + 1] = b[1];
                j += 2;
            }
        }
        let mut coeff_block = mem_pool.alloc();
        for (i, c) in coeffs.iter().enumerate() {
            let bytes = c.to_be_bytes();
            coeff_block[2 * i] = bytes[0];
            coeff_block[2 * i + 1] = bytes[1];
        }
        Some(Packet {
            id: self.source_window.back().unwrap().id + 1 + repair_packet_index as u64,
            data: repair_data,
            len: packet_len,
            is_systematic: false,
            coefficients: Some(coeff_block),
            coeff_len: coeffs.len() * 2,
            mem_pool: Arc::clone(mem_pool),
        })
    }

    fn generate_cauchy_coefficients(&self, repair_index: usize) -> Vec<u16> {
        let y = (self.k + repair_index) as u16;
        (0..self.k).map(|i| gf16_inv(i as u16 ^ y)).collect()
    }
}

enum EncoderVariant {
    G8(Encoder),
    G16(Encoder16),
}

impl EncoderVariant {
    fn new(mode: FecMode, k: usize, n: usize) -> Self {
        if mode == FecMode::Extreme {
            EncoderVariant::G16(Encoder16::new(k, n))
        } else {
            EncoderVariant::G8(Encoder::new(k, n))
        }
    }

    fn add_source_packet(&mut self, pkt: Packet) {
        match self {
            EncoderVariant::G8(e) => e.add_source_packet(pkt),
            EncoderVariant::G16(e) => e.add_source_packet(pkt),
        }
    }

    fn generate_repair_packet(&self, idx: usize, pool: &Arc<MemoryPool>) -> Option<Packet> {
        match self {
            EncoderVariant::G8(e) => e.generate_repair_packet(idx, pool),
            EncoderVariant::G16(e) => e.generate_repair_packet(idx, pool),
        }
    }
}

enum DecoderVariant {
    G8(Decoder),
    G16(Decoder16),
}

impl DecoderVariant {
    fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
        if mode == FecMode::Extreme {
            DecoderVariant::G16(Decoder16::new(k, pool))
        } else {
            DecoderVariant::G8(Decoder::new(k, pool))
        }
    }

    fn add_packet(&mut self, pkt: Packet) -> Result<bool, &'static str> {
        match self {
            DecoderVariant::G8(d) => d.add_packet(pkt),
            DecoderVariant::G16(d) => d.add_packet(pkt),
        }
    }

    fn get_decoded_packets(&mut self) -> Vec<Packet> {
        match self {
            DecoderVariant::G8(d) => d.get_decoded_packets(),
            DecoderVariant::G16(d) => d.get_decoded_packets(),
        }
    }

    fn is_decoded(&self) -> bool {
        match self {
            DecoderVariant::G8(d) => d.is_decoded,
            DecoderVariant::G16(d) => d.is_decoded,
        }
    }
}

impl Encoder {
    fn new(k: usize, n: usize) -> Self {
        Self {
            k,
            n,
            source_window: VecDeque::with_capacity(k),
        }
    }

    fn add_source_packet(&mut self, packet: Packet) {
        if self.source_window.len() == self.k {
            self.source_window.pop_front();
        }
        self.source_window.push_back(packet);
    }

    /// Generates a repair packet for the current window.
    fn generate_repair_packet(
        &self,
        repair_packet_index: usize,
        mem_pool: &Arc<MemoryPool>,
    ) -> Option<Packet> {
        if self.source_window.len() < self.k {
            return None;
        }

        let packet_len = self.source_window[0].len;
        let mut repair_data = mem_pool.alloc();
        repair_data.iter_mut().for_each(|b| *b = 0);

        let coeffs = self.generate_cauchy_coefficients(repair_packet_index);

        optimize::dispatch(|policy| {
            if policy.as_any().is::<optimize::Avx2>() || policy.as_any().is::<optimize::Neon>() {
                use rayon::prelude::*;
                self.source_window
                    .par_iter()
                    .enumerate()
                    .for_each(|(i, source_packet)| {
                        let coeff = coeffs[i];
                        if coeff == 0 {
                            return;
                        }
                        let source_data =
                            &source_packet.data.as_ref().expect("packet data missing")
                                [..source_packet.len];
                        for j in 0..packet_len {
                            repair_data[j] = gf_mul_add(coeff, source_data[j], repair_data[j]);
                        }
                    });
            } else {
                for (i, source_packet) in self.source_window.iter().enumerate() {
                    let coeff = coeffs[i];
                    if coeff == 0 {
                        continue;
                    }
                    let source_data = &source_packet.data.as_ref().expect("packet data missing")
                        [..source_packet.len];
                    for j in 0..packet_len {
                        repair_data[j] = gf_mul_add(coeff, source_data[j], repair_data[j]);
                    }
                }
            }
        });

        let mut coeff_block = mem_pool.alloc();
        coeff_block[..coeffs.len()].copy_from_slice(&coeffs);
        Some(Packet {
            id: self.source_window.back().unwrap().id + 1 + repair_packet_index as u64,
            data: Some(repair_data),
            len: packet_len,
            is_systematic: false,
            coefficients: Some(coeff_block),
            coeff_len: coeffs.len(),
            mem_pool: Arc::clone(mem_pool),
        })
    }

    /// Generates a row of coefficients from a Cauchy matrix.
    /// `X_i = i` for `i < k`, `Y_j = j` for `j < (n-k)`.
    /// `C_ji = 1 / (X_i + Y_j)`.
    fn generate_cauchy_coefficients(&self, repair_index: usize) -> Vec<u8> {
        let y = (self.k + repair_index) as u8;
        let mut coeffs = Vec::with_capacity(self.k);
        if self.k == 0 {
            return coeffs;
        }
        unsafe {
            prefetch_log((0u8 ^ y) as usize);
        }
        for i in 0..self.k {
            if i + 1 < self.k {
                unsafe {
                    prefetch_log(((i + 1) as u8 ^ y) as usize);
                }
            }
            coeffs.push(gf_inv_prefetch(i as u8 ^ y));
        }
        coeffs
    }
}
/// Represents a sparse matrix in Compressed-Sparse-Row (CSR) format.
pub struct CsrMatrix {
    /// Non-zero values of the matrix.
    values: Vec<u8>,
    /// Column indices of the non-zero values.
    col_indices: Vec<usize>,
    /// Pointer to the start of each row in `values` and `col_indices`.
    row_ptr: Vec<usize>,
    /// Payloads associated with each row (for repair packets).
    payloads: Vec<Option<AlignedBox<[u8]>>>,
    num_cols: usize,
}

impl CsrMatrix {
    fn new(num_cols: usize) -> Self {
        Self {
            values: Vec::new(),
            col_indices: Vec::new(),
            row_ptr: vec![0],
            payloads: Vec::new(),
            num_cols,
        }
    }

    fn num_rows(&self) -> usize {
        self.row_ptr.len() - 1
    }

    /// Appends a dense row to the CSR matrix.
    fn append_row(&mut self, row: &[u8], payload: Option<AlignedBox<[u8]>>) {
        for (col_idx, &val) in row.iter().enumerate() {
            if val != 0 {
                self.values.push(val);
                self.col_indices.push(col_idx);
            }
        }
        self.row_ptr.push(self.values.len());
        self.payloads.push(payload);
    }

    fn get_val(&self, row: usize, col: usize) -> u8 {
        let row_start = self.row_ptr[row];
        let row_end = self.row_ptr[row + 1];
        for i in row_start..row_end {
            if self.col_indices[i] == col {
                return self.values[i];
            }
        }
        0
    }

    fn get_payload(&self, row: usize) -> &Option<AlignedBox<[u8]>> {
        &self.payloads[row]
    }

    fn row_entries(&self, row: usize) -> Vec<(usize, u8)> {
        let start = self.row_ptr[row];
        let end = self.row_ptr[row + 1];
        (start..end)
            .map(|i| (self.col_indices[i], self.values[i]))
            .collect()
    }

    fn clear_row(&mut self, row: usize) {
        let start = self.row_ptr[row];
        let end = self.row_ptr[row + 1];
        let diff = end - start;
        if diff == 0 {
            return;
        }
        self.values.drain(start..end);
        self.col_indices.drain(start..end);
        for ptr in self.row_ptr.iter_mut().skip(row + 1) {
            *ptr -= diff;
        }
    }

    fn insert_row(&mut self, row: usize, entries: &[(usize, u8)]) {
        let start = self.row_ptr[row];
        for (col, val) in entries.iter().rev() {
            self.values.insert(start, *val);
            self.col_indices.insert(start, *col);
        }
        let diff = entries.len();
        for ptr in self.row_ptr.iter_mut().skip(row + 1) {
            *ptr += diff;
        }
    }

    fn swap_rows(&mut self, r1: usize, r2: usize) {
        if r1 == r2 {
            return;
        }
        let row1 = self.row_entries(r1);
        let row2 = self.row_entries(r2);
        let (hi, lo, hi_row, lo_row) = if r1 > r2 {
            (r1, r2, row1, row2)
        } else {
            (r2, r1, row2, row1)
        };
        self.clear_row(hi);
        self.clear_row(lo);
        self.insert_row(hi, &lo_row);
        self.insert_row(lo, &hi_row);
        self.payloads.swap(r1, r2);
    }

    fn scale_row(&mut self, row: usize, factor: u8) {
        let row_start = self.row_ptr[row];
        let row_end = self.row_ptr[row + 1];
        optimize::dispatch(|policy| {
            if policy.as_any().is::<optimize::Avx2>() || policy.as_any().is::<optimize::Neon>() {
                self.values[row_start..row_end]
                    .par_iter_mut()
                    .for_each(|v| *v = gf_mul(*v, factor));
                if let Some(ref mut payload) = self.payloads[row] {
                    payload.par_iter_mut().for_each(|b| *b = gf_mul(*b, factor));
                }
            } else {
                for i in row_start..row_end {
                    self.values[i] = gf_mul(self.values[i], factor);
                }
                if let Some(ref mut payload) = self.payloads[row] {
                    for b in payload.iter_mut() {
                        *b = gf_mul(*b, factor);
                    }
                }
            }
        });
    }

    fn add_scaled_row(&mut self, target_row: usize, source_row: usize, factor: u8) {
        optimize::dispatch(|policy| {
            let mut dense = vec![0u8; self.num_cols];
            for (c, v) in self.row_entries(target_row) {
                dense[c] = v;
            }
            for (c, v) in self.row_entries(source_row) {
                dense[c] ^= gf_mul(v, factor);
            }
            self.clear_row(target_row);
            let entries: Vec<(usize, u8)> = dense
                .iter()
                .enumerate()
                .filter(|&(_, &v)| v != 0)
                .map(|(c, &v)| (c, v))
                .collect();
            self.insert_row(target_row, &entries);

            if let (Some(src), Some(tgt)) = (
                self.payloads[source_row].as_ref(),
                self.payloads[target_row].as_mut(),
            ) {
                if policy.as_any().is::<optimize::Avx2>() || policy.as_any().is::<optimize::Neon>()
                {
                    tgt.par_iter_mut()
                        .zip(src.par_iter())
                        .for_each(|(t, &s)| *t = gf_mul_add(factor, s, *t));
                } else {
                    for i in 0..tgt.len().min(src.len()) {
                        tgt[i] = gf_mul_add(factor, src[i], tgt[i]);
                    }
                }
            }
        });
    }
}

/// Represents the chosen decoding algorithm based on window size.
enum DecodingStrategy {
    GaussianElimination,
    Wiedemann,
}

/// Recovers original packets using the most appropriate high-performance algorithm.
pub struct Decoder {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoding_matrix: CsrMatrix,
    systematic_packets: Vec<Option<Packet>>,
    is_decoded: bool,
    strategy: DecodingStrategy,
}

pub struct Decoder16 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    matrix: Vec<Vec<u16>>, // dense for simplicity
    payloads: Vec<Option<AlignedBox<[u8]>>>,
    is_decoded: bool,
}

impl Decoder16 {
    fn new(k: usize, mem_pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool,
            matrix: Vec::new(),
            payloads: Vec::new(),
            is_decoded: false,
        }
    }

    fn add_packet(&mut self, packet: Packet) -> Result<bool, &'static str> {
        if self.is_decoded || self.matrix.len() >= self.k {
            return Ok(self.is_decoded);
        }
        let coeffs = if packet.is_systematic {
            let mut row = vec![0u16; self.k];
            let idx = (packet.id as usize) % self.k;
            row[idx] = 1;
            self.matrix.push(row);
            self.payloads.push(None);
            return Ok(false);
        } else if let Some(c) = packet.coefficients {
            let mut row = Vec::with_capacity(self.k);
            for i in 0..self.k {
                let hi = c[2 * i];
                let lo = c[2 * i + 1];
                row.push(u16::from_be_bytes([hi, lo]));
            }
            self.matrix.push(row);
            self.payloads.push(Some(packet.data));
            row
        } else {
            return Err("missing coeffs");
        };
        Ok(self.try_decode())
    }

    fn try_decode(&mut self) -> bool {
        if self.matrix.len() < self.k {
            return false;
        }
        let k = self.k;
        for i in 0..k {
            // pivot search
            let mut pivot = i;
            while pivot < k && self.matrix[pivot][i] == 0 {
                pivot += 1;
            }
            if pivot == k {
                return false;
            }
            self.matrix.swap(i, pivot);
            self.payloads.swap(i, pivot);
            let inv = gf16_inv(self.matrix[i][i]);
            for val in self.matrix[i].iter_mut() {
                *val = gf16_mul(*val, inv);
            }
            if let Some(ref mut p) = self.payloads[i] {
                let mut j = 0;
                while j + 1 < p.len() {
                    let v = u16::from_be_bytes([p[j], p[j + 1]]);
                    let v = gf16_mul(v, inv);
                    let b = v.to_be_bytes();
                    p[j] = b[0];
                    p[j + 1] = b[1];
                    j += 2;
                }
            }
            for r in 0..k {
                if r != i && self.matrix[r][i] != 0 {
                    let factor = self.matrix[r][i];
                    for c in 0..k {
                        let t = gf16_mul(factor, self.matrix[i][c]);
                        self.matrix[r][c] ^= t;
                    }
                    if let (Some(ref src), Some(ref mut tgt)) =
                        (&self.payloads[i], &mut self.payloads[r])
                    {
                        let mut j = 0;
                        while j + 1 < src.len() {
                            let s = u16::from_be_bytes([src[j], src[j + 1]]);
                            let t = u16::from_be_bytes([tgt[j], tgt[j + 1]]);
                            let val = gf16_mul_add(factor, s, t);
                            let b = val.to_be_bytes();
                            tgt[j] = b[0];
                            tgt[j + 1] = b[1];
                            j += 2;
                        }
                    }
                }
            }
        }
        self.is_decoded = true;
        true
    }

    fn get_decoded_packets(&mut self) -> Vec<Packet> {
        let mut out = Vec::new();
        for (i, payload) in self.payloads.iter_mut().enumerate() {
            if let Some(data) = payload.take() {
                out.push(Packet {
                    id: i as u64,
                    data,
                    len: data.len(),
                    is_systematic: true,
                    coefficients: None,
                });
            }
        }
        out
    }
}

impl Decoder {
    fn new(k: usize, mem_pool: Arc<MemoryPool>) -> Self {
        // Select the decoding strategy based on the window size `k`.
        let strategy = if k > 256 {
            DecodingStrategy::Wiedemann
        } else {
            DecodingStrategy::GaussianElimination
        };

        Self {
            k,
            mem_pool,
            decoding_matrix: CsrMatrix::new(k), // The matrix size is k x k for coefficients
            systematic_packets: vec![None; k],
            is_decoded: false,
            strategy,
        }
    }

    /// Adds a packet to the decoder, building the decoding matrix.
    fn add_packet(&mut self, packet: Packet) -> Result<bool, &'static str> {
        if self.is_decoded || self.decoding_matrix.num_rows() >= self.k {
            return Ok(self.is_decoded);
        }

        if packet.is_systematic {
            let index = (packet.id as usize) % self.k;
            let mut identity_row = vec![0; self.k];
            identity_row[index] = 1;
            if self.systematic_packets[index].is_none() {
                self.systematic_packets[index] = Some(packet);
            } else {
                return Ok(self.is_decoded); // Duplicate packet
            }
            self.decoding_matrix.append_row(&identity_row, None);
            Ok(self.try_decode())
        } else if let Some(coeffs) = packet.coefficients {
            self.decoding_matrix
                .append_row(&coeffs[..packet.coeff_len], packet.data);
            Ok(self.try_decode())
        } else {
            Err("Repair packet missing coefficients.")
        }
    }

    /// Attempts to decode once enough packets (K) have been received.
    fn try_decode(&mut self) -> bool {
        if self.is_decoded {
            return true;
        }
        if self.decoding_matrix.num_rows() < self.k {
            return false;
        }

        // --- High-performance decoding pipeline ---
        match self.strategy {
            DecodingStrategy::GaussianElimination => self.gaussian_elimination(),
            DecodingStrategy::Wiedemann => self.wiedemann_algorithm(),
        }
    }

    /// Performs Sparse Gaussian elimination on the CSR matrix.
    fn gaussian_elimination(&mut self) -> bool {
        // This is a simplified sparse implementation. A truly high-performance version
        // would require more complex data structures and operations to minimize cache misses.
        let start = std::time::Instant::now();
        let k = self.k;
        let mut rank = 0;

        for i in 0..k {
            // Find pivot
            let pivot_row_opt = (i..self.decoding_matrix.num_rows())
                .find(|&r| self.decoding_matrix.get_val(r, i) != 0);

            if let Some(pivot_row) = pivot_row_opt {
                self.decoding_matrix.swap_rows(i, pivot_row);

                let pivot_val = self.decoding_matrix.get_val(i, i);
                let pivot_inv = gf_inv(pivot_val);
                self.decoding_matrix.scale_row(i, pivot_inv);

                for row_idx in 0..self.decoding_matrix.num_rows() {
                    if i == row_idx {
                        continue;
                    }
                    let factor = self.decoding_matrix.get_val(row_idx, i);
                    if factor != 0 {
                        self.decoding_matrix.add_scaled_row(row_idx, i, factor);
                    }
                }
                rank += 1;
                if rank == k {
                    // Early Exit: Matrix is full rank, solution found.
                    break;
                }
            }
        }

        if rank < k {
            return false; // Matrix is singular
        }

        self.is_decoded = true;
        // The `decoding_matrix` now contains the solved data on its right-hand side.
        // Reconstruct packets from this solved data.
        for i in 0..k {
            if self.systematic_packets[i].is_none() {
                if let Some(data_slice) = self.decoding_matrix.get_payload(i) {
                    let data_len = data_slice.len();
                    let mut packet_data = self.mem_pool.alloc();
                    packet_data[..data_len].copy_from_slice(&data_slice);

                    self.systematic_packets[i] = Some(Packet {
                        id: i as u64, // NOTE: Assumes packet ID aligns with matrix index.
                        data: Some(packet_data),
                        len: data_len,
                        is_systematic: true,
                        coefficients: None,
                        mem_pool: Arc::clone(&self.mem_pool),
                    });
                }
            }
        }
        telemetry!(telemetry::DECODING_TIME_MS.set(start.elapsed().as_millis() as i64));
        true
    }

    fn get_decoded_packets(&mut self) -> Vec<Packet> {
        // Drain the buffer to return the fully reconstructed set of packets
        self.systematic_packets
            .iter_mut()
            .filter_map(|p| p.take())
            .collect()
    }

    /// Solves the decoding problem using a block-Lanczos based Wiedemann algorithm.
    fn wiedemann_algorithm(&mut self) -> bool {
        telemetry!(crate::telemetry::WIEDEMANN_USAGE.inc());
        let start = std::time::Instant::now();

        let k = self.k;

        // Choose block size depending on window size
        let block = (k / 256).max(1).min(32);
        let mut init = Vec::with_capacity(block);
        for b in 0..block {
            let mut v = vec![0u8; k];
            for i in 0..k {
                // deterministic init vectors
                v[i] = ((i + b + 1) % 255) as u8;
            }
            init.push(v);
        }

        let seq = self.block_lanczos_iteration(&init);

        // Build dense matrix of coefficients
        let mut a = vec![vec![0u8; k]; k];
        for row in 0..k {
            for (col, val) in self.decoding_matrix.row_entries(row) {
                a[row][col] = val;
            }
        }

        // Build payload matrix
        let max_len = self
            .decoding_matrix
            .payloads
            .iter()
            .filter_map(|p| p.as_ref().map(|d| d.len()))
            .max()
            .unwrap_or(0);
        let mut b_mat = vec![vec![0u8; max_len]; k];
        for (r, payload) in self.decoding_matrix.payloads.iter().enumerate() {
            if let Some(p) = payload {
                for (i, &val) in p.iter().enumerate() {
                    b_mat[r][i] = val;
                }
            }
        }

        // Minimal polynomial from first Lanczos sequence
        let poly = match self.berlekamp_massey(&seq[0]) {
            Some(p) => p,
            None => return false,
        };

        if poly.len() <= 1 || poly[0] == 0 {
            return false;
        }

        // Compute matrix powers of A
        let mut powers: Vec<Vec<Vec<u8>>> = Vec::with_capacity(poly.len());
        // A^0 = I
        let mut id = vec![vec![0u8; k]; k];
        for i in 0..k {
            id[i][i] = 1;
        }
        powers.push(id);
        for _ in 1..poly.len() {
            let prev = powers.last().unwrap();
            powers.push(mat_mul(prev, &a));
        }

        // Compute inverse via polynomial
        let c0_inv = gf_inv(poly[0]);
        let mut a_inv = vec![vec![0u8; k]; k];
        for (idx, coef) in poly.iter().enumerate().skip(1) {
            let coef = gf_mul(*coef, c0_inv);
            let mat = &powers[idx - 1];
            for r in 0..k {
                for c in 0..k {
                    a_inv[r][c] ^= gf_mul(coef, mat[r][c]);
                }
            }
        }

        // Multiply inverse with payload matrix to get original data
        let result = mat_mul(&a_inv, &b_mat);

        for (i, data_row) in result.into_iter().enumerate() {
            if self.systematic_packets[i].is_none() {
                let mut packet_data = self.mem_pool.alloc();
                for (j, &v) in data_row.iter().enumerate() {
                    packet_data[j] = v;
                }
                self.systematic_packets[i] = Some(Packet {
                    id: i as u64,
                    data: Some(packet_data),
                    len: max_len,
                    is_systematic: true,
                    coefficients: None,
                    mem_pool: Arc::clone(&self.mem_pool),
                });
            }
        }
        self.is_decoded = true;
        telemetry!(crate::telemetry::DECODING_TIME_MS.set(start.elapsed().as_millis() as i64));
        true
    }

    /// Performs a block-Lanczos iteration used for the Wiedemann sequence generation.
    fn block_lanczos_iteration(&self, init: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let k = self.k;
        let block = init.len();
        let mut seq = vec![vec![0u8; 2 * k]; block];

        // dense matrix of coefficients
        let mut a = vec![vec![0u8; k]; k];
        for row in 0..k {
            for (col, val) in self.decoding_matrix.row_entries(row) {
                a[row][col] = val;
            }
        }

        fn mat_vec_mul(a: &[Vec<u8>], x: &[u8]) -> Vec<u8> {
            let n = x.len();
            let mut out = vec![0u8; n];
            for r in 0..n {
                let mut acc = 0u8;
                for c in 0..n {
                    if a[r][c] != 0 {
                        acc ^= gf_mul(a[r][c], x[c]);
                    }
                }
                out[r] = acc;
            }
            out
        }

        for b in 0..block {
            let mut v = init[b].clone();
            for t in 0..(2 * k) {
                let mut dot = 0u8;
                for i in 0..k {
                    dot ^= gf_mul(init[b][i], v[i]);
                }
                seq[b][t] = dot;
                v = mat_vec_mul(&a, &v);
            }
        }

        seq
    }

    /// Implements the Berlekamp-Massey algorithm to find the minimal polynomial.
    fn berlekamp_massey(&self, s: &[u8]) -> Option<Vec<u8>> {
        let n = s.len();
        let mut c = vec![0u8; n + 1];
        let mut b = vec![0u8; n + 1];
        c[0] = 1;
        b[0] = 1;
        let mut l = 0usize;
        let mut m = 0usize;
        let mut bb = b.clone();
        for i in 0..n {
            let mut d = s[i];
            for j in 1..=l {
                d ^= gf_mul(c[j], s[i - j]);
            }
            if d != 0 {
                let mut t = c.clone();
                let coef = gf_mul(d, gf_inv(bb[0]));
                let shift = i - m;
                for j in 0..(n - shift) {
                    c[j + shift] ^= gf_mul(coef, bb[j]);
                }
                if 2 * l <= i {
                    l = i + 1 - l;
                    m = i;
                    bb = t;
                }
            }
        }
        c.truncate(l + 1);
        Some(c)
    }
}

/// Multiplies two dense matrices over GF(2^8).
fn mat_mul(a: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let rows = a.len();
    let cols = b[0].len();
    let mid = b.len();
    let mut out = vec![vec![0u8; cols]; rows];
    for i in 0..rows {
        for k in 0..mid {
            if a[i][k] == 0 {
                continue;
            }
            for j in 0..cols {
                out[i][j] ^= gf_mul(a[i][k], b[k][j]);
            }
        }
    }
    out
}

/// Computes a dense matrix inverse using block recursive inversion.
fn recursive_inverse(m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    if n == 0 {
        return None;
    }
    if n == 1 {
        let inv = gf_inv(m[0][0]);
        return Some(vec![vec![inv]]);
    }
    let mid = n / 2;
    let mut a = vec![vec![0u8; mid]; mid];
    let mut b = vec![vec![0u8; n - mid]; mid];
    let mut c = vec![vec![0u8; mid]; n - mid];
    let mut d = vec![vec![0u8; n - mid]; n - mid];
    for i in 0..mid {
        for j in 0..mid {
            a[i][j] = m[i][j];
        }
        for j in mid..n {
            b[i][j - mid] = m[i][j];
        }
    }
    for i in mid..n {
        for j in 0..mid {
            c[i - mid][j] = m[i][j];
        }
        for j in mid..n {
            d[i - mid][j - mid] = m[i][j];
        }
    }

    let a_inv = recursive_inverse(&a)?;
    let ca_inv = mat_mul(&c, &a_inv);
    let temp = mat_mul(&ca_inv, &b);
    let mut schur = vec![vec![0u8; d[0].len()]; d.len()];
    for i in 0..d.len() {
        for j in 0..d[0].len() {
            schur[i][j] = d[i][j] ^ temp[i][j];
        }
    }
    let schur_inv = recursive_inverse(&schur)?;
    let mut upper_right = mat_mul(&a_inv, &b);
    upper_right = mat_mul(&upper_right, &schur_inv);
    for row in &mut upper_right {
        for val in row.iter_mut() {
            *val = gf_mul(*val, 1); // ensure field
        }
    }
    let mut lower_left = mat_mul(&schur_inv, &ca_inv);
    let mut upper_left = mat_mul(&a_inv, &b);
    upper_left = mat_mul(&upper_left, &schur_inv);
    upper_left = mat_mul(&upper_left, &ca_inv);
    let mut id = vec![vec![0u8; a_inv.len()]; a_inv.len()];
    for i in 0..a_inv.len() {
        id[i][i] = 1;
    }
    let mut res_a = vec![vec![0u8; a_inv.len()]; a_inv.len()];
    for i in 0..a_inv.len() {
        for j in 0..a_inv.len() {
            res_a[i][j] = a_inv[i][j] ^ upper_left[i][j];
        }
    }
    let mut out = vec![vec![0u8; n]; n];
    for i in 0..mid {
        for j in 0..mid {
            out[i][j] = res_a[i][j];
        }
        for j in mid..n {
            out[i][j] = upper_right[i][j - mid];
        }
    }
    for i in mid..n {
        for j in 0..mid {
            out[i][j] = lower_left[i - mid][j];
        }
        for j in mid..n {
            out[i][j] = schur_inv[i - mid][j - mid];
        }
    }
    Some(out)
}

// --- Main Public Interface ---
