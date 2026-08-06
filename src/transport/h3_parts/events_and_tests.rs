
/// HTTP/3 events
#[derive(Debug, Clone)]
pub enum Event {
    Headers {
        list: Vec<Header>,
        has_body: bool,
    },
    Data,
    /// MASQUE capsule received on CONNECT-UDP stream
    MasqueCapsule {
        capsule_type: u64,
        payload: Vec<u8>,
    },
    Finished,
    /// Server Push Promise event for stealth cover traffic
    PushPromise {
        push_id: u64,
        headers: Vec<Header>,
    },
    Reset(u64),
    PriorityUpdate,
    GoAway,
}

/// QPACK encoder/decoder module with dynamic table support
pub(crate) mod qpack {
    use super::*;

    // HPACK/QPACK Huffman coding tables (RFC 7541 Appendix B)
    // codes and code lengths for 257 symbols (0..=255 plus EOS=256)
    // Note: For brevity, only a compact subset is shown here. For production,
    // a full table is required. Here we inline the complete tables.
    pub(crate) const HUFF_CODES: [u32; 257] = [
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa,
        0xffffffb, // 32..63
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa,
        0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb,
        0x7ffc, 0x20, 0xffb, 0x3fc, // 64..95
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
        0x1ffc, 0x3ffc, 0x22, // 96..127
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a,
        0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd,
        0x1ffd, 0xffffffc, // 128..159
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6,
        0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed,
        0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8,
        0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, // 160..191
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea,
        0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1,
        0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3,
        0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, // 192..223
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2,
        0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2,
        0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4,
        0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        // 224..255
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea,
        0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
        0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
        0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
        // EOS 256
        0x3fffffff,
    ];
    pub(crate) const HUFF_LENS: [u8; 257] = [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5,
        7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22,
        22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23,
        22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22,
        21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26,
        26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20,
        24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27,
        27, 28, 27, 27, 27, 27, 27, 26, 30,
    ];

    #[inline]
    pub(crate) fn huff_estimate_len(s: &[u8]) -> usize {
        let mut bits: usize = 0;
        for &b in s {
            bits += HUFF_LENS[b as usize] as usize;
        }
        // EOS padding to next 8 bits
        bits.div_ceil(8)
    }

    #[inline]
    pub(crate) fn huff_encode_into(s: &[u8], out: &mut [u8]) -> usize {
        let mut acc: u64 = 0;
        let mut acc_bits: usize = 0;
        let mut written = 0usize;
        for &b in s {
            let code = HUFF_CODES[b as usize] as u64;
            let clen = HUFF_LENS[b as usize] as usize;
            acc = (acc << clen) | code;
            acc_bits += clen;
            while acc_bits >= 8 {
                let shift = acc_bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                out[written] = byte;
                written += 1;
                acc_bits -= 8;
                acc &= (1u64 << shift) - 1;
            }
        }
        if acc_bits > 0 {
            let pad = (1u64 << (8 - acc_bits)) - 1; // EOS padding with ones
            let byte = ((acc << (8 - acc_bits)) | pad) as u8;
            out[written] = byte;
            written += 1;
        }
        written
    }

    #[derive(Default)]
    struct Node {
        next: [i32; 2],
        sym: i32,
    }
    pub(crate) fn huff_decode_into(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // Build a simple decode trie at runtime (cached)
        fn build_trie() -> Vec<Node> {
            let mut trie = vec![Node { next: [-1, -1], sym: -1 }];
            for sym in 0..257u32 {
                let code = HUFF_CODES[sym as usize] as u64;
                let clen = HUFF_LENS[sym as usize] as usize;
                let mut idx = 0usize;
                for i in (0..clen).rev() {
                    let bit = ((code >> i) & 1) as usize;
                    let next = trie[idx].next[bit];
                    if next == -1 {
                        trie[idx].next[bit] = trie.len() as i32;
                        trie.push(Node { next: [-1, -1], sym: -1 });
                        idx = trie.len() - 1;
                    } else {
                        idx = next as usize;
                    }
                }
                trie[idx].sym = sym as i32;
            }
            trie
        }
        use std::sync::OnceLock;
        static TRIE: OnceLock<Vec<Node>> = OnceLock::new();
        let trie = TRIE.get_or_init(build_trie);
        let mut idx = 0usize;
        let mut written = 0usize;
        let mut pending_bits = 0usize;
        let mut pending_value = 0u8;
        for &byte in data {
            for i in (0..8).rev() {
                let bit = ((byte >> i) & 1) as usize;
                pending_bits += 1;
                pending_value = (pending_value << 1) | bit as u8;
                let next = trie[idx].next[bit];
                if next < 0 {
                    return Err(Error::QpackDecompressionFailed);
                }
                idx = next as usize;
                let sym = trie[idx].sym;
                if sym >= 0 {
                    if sym == 256 {
                        return Err(Error::QpackDecompressionFailed);
                    }
                    if written >= out.len() {
                        return Err(Error::BufferTooShort);
                    }
                    out[written] = sym as u8;
                    written += 1;
                    idx = 0;
                    pending_bits = 0;
                    pending_value = 0;
                }
            }
        }
        if idx == 0 || (pending_bits <= 7 && pending_value == ((1u16 << pending_bits) - 1) as u8) {
            Ok(written)
        } else {
            Err(Error::QpackDecompressionFailed)
        }
    }

    fn huff_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; huff_estimate_len(data).saturating_mul(2).max(32)];
        match huff_decode_into(data, &mut buf) {
            Ok(written) => {
                buf.truncate(written);
                Ok(buf)
            }
            Err(Error::BufferTooShort) => {
                // grow to worst-case 3x and retry once
                buf.resize(data.len().saturating_mul(3).max(64), 0);
                let written = huff_decode_into(data, &mut buf)?;
                buf.truncate(written);
                Ok(buf)
            }
            Err(e) => Err(e),
        }
    }

    /// Static table entries for common headers and frequent values
    /// Note: This combines a pragmatic superset for our use-case; indices are internal.
    const STATIC_TABLE: &[(&[u8], &[u8])] = &[
        // Frequently used realistic pairs for stealth cover traffic
        (b"content-type", b"text/css"),
        (b"content-type", b"application/javascript"),
        (b"content-type", b"application/json"),
        (b"content-type", b"image/jpeg"),
        (b"content-type", b"image/png"),
        (b"cache-control", b"public, max-age=31536000"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"accept", b"*/*"),
        (b"x-cdn-cache", b"HIT"),
        (b":authority", b""),
        (b":path", b"/"),
        (b":method", b"GET"),
        (b":method", b"POST"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"200"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"304"),
        (b":status", b"400"),
        (b":status", b"404"),
        (b":status", b"500"),
        (b"accept-charset", b""),
        (b"accept-encoding", b"gzip, deflate"),
        (b"accept-language", b""),
        (b"accept-ranges", b""),
        (b"accept", b""),
        (b"access-control-allow-origin", b""),
        (b"age", b""),
        (b"allow", b""),
        (b"authorization", b""),
        (b"cache-control", b""),
        (b"content-disposition", b""),
        (b"content-encoding", b""),
        (b"content-language", b""),
        (b"content-length", b""),
        (b"content-location", b""),
        (b"content-range", b""),
        (b"content-type", b""),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"expect", b""),
        (b"expires", b""),
        (b"from", b""),
        (b"host", b""),
        (b"if-match", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"if-range", b""),
        (b"if-unmodified-since", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"max-forwards", b""),
        (b"proxy-authenticate", b""),
        (b"proxy-authorization", b""),
        (b"range", b""),
        (b"referer", b""),
        (b"refresh", b""),
        (b"retry-after", b""),
        (b"server", b""),
        (b"set-cookie", b""),
        (b"strict-transport-security", b""),
        (b"transfer-encoding", b""),
        (b"user-agent", b""),
        (b"vary", b""),
        (b"via", b""),
        (b"www-authenticate", b""),
    ];

    /// QPACK encoder with dynamic table
    pub(crate) struct Encoder {
        dynamic_table: Vec<(Vec<u8>, Vec<u8>)>,
        dyn_index: std::collections::HashMap<u64, usize>,
        _max_table_capacity: usize,
        _current_capacity: usize,
        _inserted_count: u64,
        _evicted_count: u64,
        index_prefer: Vec<Vec<u8>>, // header names to prefer ordering/indexing
    }
    impl Default for Encoder {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Encoder {
        pub(crate) fn new() -> Self {
            Self::with_capacity(0)
        }
        pub(crate) fn with_capacity(capacity: u64) -> Self {
            let mut s = Self {
                dynamic_table: Vec::new(),
                dyn_index: std::collections::HashMap::new(),
                _max_table_capacity: capacity as usize,
                _current_capacity: 0,
                _inserted_count: 0,
                _evicted_count: 0,
                index_prefer: Vec::new(),
            };
            // Seed dictionary with common (name,value) pairs if there is capacity
            if capacity >= 1024 {
                s.seed_default_dictionary();
            }
            s
        }

        #[inline]
        fn hash_nv(name: &[u8], value: &[u8]) -> u64 {
            let mut h: u64 = 1469598103934665603; // FNV-1a 64-bit offset basis
            for b in name.iter().chain(value.iter()) {
                h ^= *b as u64;
                h = h.wrapping_mul(1099511628211);
            }
            h
        }
        /// Seed dynamic table with frequent pairs to reduce first-flight size.
        fn seed_default_dictionary(&mut self) {
            const SEEDS: &[(&[u8], &[u8])] = &[
                (b"content-type", b"text/css"),
                (b"content-type", b"application/javascript"),
                (b"content-type", b"application/json"),
                (b"content-type", b"image/jpeg"),
                (b"content-type", b"image/png"),
                (b"cache-control", b"public, max-age=31536000"),
                (b"accept-encoding", b"gzip, deflate, br"),
                (b"accept", b"*/*"),
                (b"x-cdn-cache", b"HIT"),
            ];
            for &(n, v) in SEEDS {
                let key = Self::hash_nv(n, v);
                let idx = self.dynamic_table.len();
                self.dynamic_table.push((n.to_vec(), v.to_vec()));
                self.dyn_index.insert(key, idx);
                self._inserted_count = self._inserted_count.saturating_add(1);
            }
        }
        pub(super) fn set_index_policy(&mut self, prefer: &[&[u8]]) {
            self.index_prefer = prefer.iter().map(|s| s.to_vec()).collect();
        }
        pub(crate) fn encode(
            &mut self,
            headers: &[Header],
            out: &mut [u8],
        ) -> Result<usize, Error> {
            let mut written = 0;
            if out.len() < 2 {
                return Err(Error::BufferTooShort);
            }
            out[written] = self._inserted_count as u8;
            out[written + 1] = self._inserted_count as u8;
            written += 2;
            // Persona policy: keep preferred headers first.
            let mut ordered: Vec<&Header> = headers.iter().collect();
            if !self.index_prefer.is_empty() {
                ordered.sort_by_key(|h| {
                    let name = h.name();
                    self.index_prefer
                        .iter()
                        .position(|p| p.as_slice() == name)
                        .unwrap_or(self.index_prefer.len())
                });
            }
            for header in ordered {
                let name = header.name();
                let value = header.value();
                let mut encoded = false;
                for (i, (static_name, static_value)) in STATIC_TABLE.iter().enumerate() {
                    if name == *static_name && value == *static_value {
                        if written >= out.len() {
                            return Err(Error::BufferTooShort);
                        }
                        out[written] = 0x80 | (i as u8);
                        written += 1;
                        encoded = true;
                        break;
                    }
                }
                if encoded {
                    continue;
                }
                for (i, (static_name, static_value)) in STATIC_TABLE.iter().enumerate() {
                    if name == *static_name && static_value.is_empty() {
                        if written + 1 > out.len() {
                            return Err(Error::BufferTooShort);
                        }
                        out[written] = 0x40 | (i as u8);
                        written += 1;
                        written += Self::encode_string(value, &mut out[written..])?;
                        encoded = true;
                        break;
                    }
                }
                if encoded {
                    continue;
                }
                // O(1) lookup in dynamic table via hash index
                let mut idx_opt = None;
                let key = Self::hash_nv(name, value);
                if let Some(&idx) = self.dyn_index.get(&key) {
                    if let Some((n, v)) = self.dynamic_table.get(idx) {
                        if n.as_slice() == name && v.as_slice() == value {
                            idx_opt = Some(idx);
                        }
                    }
                }
                if idx_opt.is_none() {
                    if let Some(idx) = self
                        .dynamic_table
                        .iter()
                        .position(|(n, v)| n.as_slice() == name && v.as_slice() == value)
                    {
                        self.dyn_index.insert(key, idx);
                        idx_opt = Some(idx);
                    }
                }
                if let Some(idx) = idx_opt {
                    if written + 2 > out.len() {
                        return Err(Error::BufferTooShort);
                    }
                    out[written] = 0xA0;
                    written += 1;
                    if idx < 128 {
                        if written + 1 > out.len() {
                            return Err(Error::BufferTooShort);
                        }
                        out[written] = idx as u8;
                        written += 1;
                    } else {
                        if written + 2 > out.len() {
                            return Err(Error::BufferTooShort);
                        }
                        out[written] = 0x80 | ((idx >> 8) as u8);
                        out[written + 1] = (idx & 0xff) as u8;
                        written += 2;
                    }
                    continue;
                }
                if written + 3 + name.len() + value.len() > out.len() {
                    return Err(Error::BufferTooShort);
                }
                out[written] = 0x20;
                written += 1;
                written += Self::encode_string(name, &mut out[written..])?;
                written += Self::encode_string(value, &mut out[written..])?;
                if self._max_table_capacity > 0 {
                    let idx_new = self.dynamic_table.len();
                    self.dynamic_table.push((name.to_vec(), value.to_vec()));
                    self.dyn_index.insert(Self::hash_nv(name, value), idx_new);
                    self._inserted_count += 1;
                    let capacity = (self._max_table_capacity / 64).max(16);
                    while self.dynamic_table.len() > capacity {
                        self.dynamic_table.remove(0);
                        // Rebuild index lazily when needed
                        self.dyn_index.clear();
                        for (i, (n, v)) in self.dynamic_table.iter().enumerate() {
                            self.dyn_index.insert(Self::hash_nv(n, v), i);
                        }
                        self._evicted_count += 1;
                    }
                }
            }
            Ok(written)
        }
        fn write_int_prefix7(
            mut val: usize,
            first: &mut u8,
            tail: &mut [u8],
        ) -> Result<usize, Error> {
            let mut pos = 1;
            let prefix_max = 0x7f;
            if val < prefix_max {
                *first |= val as u8;
                return Ok(1);
            }
            *first |= prefix_max as u8;
            val -= prefix_max;
            while val >= 128 {
                if pos > tail.len() {
                    return Err(Error::BufferTooShort);
                }
                tail[pos - 1] = ((val as u8) & 0x7f) | 0x80;
                pos += 1;
                val >>= 7;
            }
            if pos > tail.len() {
                return Err(Error::BufferTooShort);
            }
            tail[pos - 1] = val as u8;
            Ok(pos + 1)
        }

        fn read_int_prefix7(first: u8, data: &[u8]) -> Result<(usize, usize), Error> {
            let mut val = (first & 0x7f) as usize;
            if val < 0x7f {
                return Ok((val, 0));
            }
            let mut m = 0;
            let mut pos = 0;
            loop {
                if pos >= data.len() {
                    return Err(Error::BufferTooShort);
                }
                let b = data[pos];
                pos += 1;
                val += ((b & 0x7f) as usize) << m;
                if b & 0x80 == 0 {
                    break;
                }
                m += 7;
                if m > 28 {
                    return Err(Error::InternalError);
                }
            }
            Ok((val, pos))
        }

        fn encode_string(s: &[u8], out: &mut [u8]) -> Result<usize, Error> {
            let raw_len = s.len();
            let huff_len = huff_estimate_len(s);
            let use_huff = huff_len < raw_len;
            let encoded_len = if use_huff { huff_len } else { raw_len };
            if out.is_empty() {
                return Err(Error::BufferTooShort);
            }
            let mut first: u8 = 0;
            if use_huff {
                first |= 0x80;
            }
            // Compose header in a small buffer to avoid aliasing borrows
            let mut hdr = [0u8; 10];
            let header_len = {
                let mut f = first;
                let used = Self::write_int_prefix7(encoded_len, &mut f, &mut hdr[1..])?;
                hdr[0] = f;
                used
            };
            if out.len() < header_len {
                return Err(Error::BufferTooShort);
            }
            out[..header_len].copy_from_slice(&hdr[..header_len]);
            if use_huff {
                if out.len() < header_len + encoded_len {
                    return Err(Error::BufferTooShort);
                }
                // Prefer SIMD runtime-dispatched QPACK Huffman encoding
                let used = crate::simd::qpack::encode_huff_into(
                    s,
                    &mut out[header_len..header_len + encoded_len],
                );
                Ok(header_len + used)
            } else {
                if out.len() < header_len + raw_len {
                    return Err(Error::BufferTooShort);
                }
                out[header_len..header_len + raw_len].copy_from_slice(s);
                Ok(header_len + raw_len)
            }
        }
    }

    /// QPACK decoder with dynamic table
    pub(crate) struct Decoder {
        dynamic_table: Vec<(Vec<u8>, Vec<u8>)>,
        _max_table_capacity: usize,
        _current_capacity: usize,
        _inserted_count: u64,
        _evicted_count: u64,
    }
    impl Default for Decoder {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Decoder {
        pub(crate) fn new() -> Self {
            Self::with_capacity(0)
        }
        pub(crate) fn with_capacity(capacity: u64) -> Self {
            Self {
                dynamic_table: Vec::new(),
                _max_table_capacity: capacity as usize,
                _current_capacity: 0,
                _inserted_count: 0,
                _evicted_count: 0,
            }
        }
        pub(crate) fn decode(&mut self, data: &[u8]) -> Result<Vec<Header>, Error> {
            if data.len() < 2 {
                return Err(Error::BufferTooShort);
            }
            let mut headers = Vec::new();
            let mut offset = 0;
            let ric = data[0] as u64;
            let base = data[1] as u64;
            let _ = base;
            self._inserted_count = self._inserted_count.max(ric);
            offset += 2;
            while offset < data.len() {
                let first = data[offset];
                offset += 1;
                if first & 0x80 != 0 {
                    let index = (first & 0x7f) as usize;
                    if index < STATIC_TABLE.len() {
                        let (name, value) = STATIC_TABLE[index];
                        headers.push(Header::new(name, value));
                    } else if index < STATIC_TABLE.len() + self.dynamic_table.len() {
                        let dyn_index = index - STATIC_TABLE.len();
                        if let Some((name, value)) = self.dynamic_table.get(dyn_index) {
                            headers.push(Header::new(name, value));
                        }
                    }
                } else if first & 0x40 != 0 {
                    let index = (first & 0x3f) as usize;
                    if index < STATIC_TABLE.len() {
                        let (name, _) = STATIC_TABLE[index];
                        let (value, consumed) = Self::decode_string(&data[offset..])?;
                        offset += consumed;
                        headers.push(Header::new(name, &value));
                    }
                } else if first & 0x20 != 0 {
                    let (name, consumed1) = Self::decode_string(&data[offset..])?;
                    offset += consumed1;
                    let (value, consumed2) = Self::decode_string(&data[offset..])?;
                    offset += consumed2;
                    headers.push(Header::new(&name, &value));
                }
            }
            Ok(headers)
        }
        fn decode_string(data: &[u8]) -> Result<(Vec<u8>, usize), Error> {
            if data.is_empty() {
                return Err(Error::BufferTooShort);
            }
            let first = data[0];
            let is_huff = (first & 0x80) != 0;
            let (len, used_tail) = Encoder::read_int_prefix7(first, &data[1..])?;
            let off = 1 + used_tail;
            if data.len() < off + len {
                return Err(Error::BufferTooShort);
            }
            let payload = &data[off..off + len];
            if is_huff {
                Ok((huff_decode(payload)?, off + len))
            } else {
                Ok((payload.to_vec(), off + len))
            }
        }
    }
}

/// Generate fake CSS content for stealth cover traffic
fn generate_fake_css(size_bytes: usize) -> Vec<u8> {
    let base_css = b"/* Generated CSS for cover traffic */\nbody{margin:0;padding:0;font-family:Arial,sans-serif}\n.container{max-width:1200px;margin:0 auto;padding:20px}\n.header{background:#333;color:#fff;padding:10px}\n.content{padding:20px;line-height:1.6}\n.footer{background:#f4f4f4;padding:10px;text-align:center}\n";
    let mut result = base_css.to_vec();

    // Pad with realistic CSS rules to reach target size
    while result.len() < size_bytes {
        let padding_rule = format!(
            ".rule-{}{{display:block;margin:{}px;padding:{}px;}}\n",
            result.len() % 1000,
            (result.len() % 20) + 5,
            (result.len() % 15) + 3
        );
        result.extend_from_slice(padding_rule.as_bytes());
    }
    result.truncate(size_bytes);
    result
}

/// Generate fake JavaScript content for stealth cover traffic
fn generate_fake_js(size_bytes: usize) -> Vec<u8> {
    let base_js = b"// Generated JS for cover traffic\n(function(){\n'use strict';\nvar app={init:function(){console.log('App initialized')},utils:{debounce:function(func,wait){var timeout;return function(){clearTimeout(timeout);timeout=setTimeout(func,wait)}}}};\napp.init();\n";
    let mut result = base_js.to_vec();

    // Pad with realistic JS functions
    while result.len() < size_bytes {
        let func_name = format!("func{}", result.len() % 1000);
        let padding_func = format!("function {}(){{return {};}}\n", func_name, result.len() % 100);
        result.extend_from_slice(padding_func.as_bytes());
    }
    result.truncate(size_bytes);
    result
}

/// Generate fake image data for stealth cover traffic
fn generate_fake_image_data(size_bytes: usize) -> Vec<u8> {
    // Fake JPEG header + random data
    let mut result = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG magic
    result.extend_from_slice(&[0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]); // JFIF

    // Fill with pseudo-random data that looks like compressed image
    let mut seed = 0x12345678u32;
    while result.len() < size_bytes - 2 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        result.push((seed >> 16) as u8);
    }

    // JPEG end marker
    result.extend_from_slice(&[0xFF, 0xD9]);
    result.truncate(size_bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PROTOCOL_VERSION;

    fn make_conn() -> super::super::Connection {
        let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [0u8; 8];
        crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
    }

    fn make_conn_with_limits(
        initial_max_data: u64,
        initial_max_stream_data_remote: u64,
    ) -> super::super::Connection {
        let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_initial_max_data(initial_max_data);
        cfg.set_initial_max_stream_data_bidi_remote(initial_max_stream_data_remote);
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [1u8; 8];
        crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
    }

    fn make_conn_with_max_udp_payload_size(max_udp_payload_size: usize) -> super::super::Connection {
        let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_max_recv_udp_payload_size(max_udp_payload_size);
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [2u8; 8];
        crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
    }

    fn current_rss_bytes() -> Option<u64> {
        #[cfg(unix)]
        {
            let pid = std::process::id().to_string();
            let output = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &pid])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let rss_kib = String::from_utf8(output.stdout).ok()?.trim().parse::<u64>().ok()?;
            rss_kib.checked_mul(1024)
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    #[test]
    fn scheduled_push_stays_promised_when_headers_send_fails() {
        let mut conn = make_conn_with_limits(0, 0);
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

        let push_id =
            h3.create_stealth_push_promise("/blocked.css", "text/css", 512).expect("push");
        if let Some(promise) = h3.push_streams.get_mut(&push_id) {
            promise.scheduled_at = std::time::Instant::now() - std::time::Duration::from_millis(1);
        }

        h3.process_scheduled_push_streams(&mut conn);

        assert_eq!(h3.push_streams.get(&push_id).map(|p| p.state), Some(PushState::Promised));
        assert!(!h3.streams.contains_key(&push_id));
        assert!(!h3.pending_events.iter().any(|(sid, _)| *sid == push_id));
    }

    #[test]
    fn push_data_progress_tracks_payload_bytes() {
        const CHUNK: usize = 16 * 1024;
        let mut conn = make_conn();
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

        let push_id = h3
            .create_stealth_push_promise("/big.js", "application/javascript", CHUNK + 10)
            .expect("push");
        if let Some(promise) = h3.push_streams.get_mut(&push_id) {
            promise.scheduled_at = std::time::Instant::now() - std::time::Duration::from_millis(1);
        }

        h3.process_scheduled_push_streams(&mut conn);
        h3.process_push_data(&mut conn);

        let st = h3.streams.get(&push_id).expect("push stream");
        assert_eq!(st.sent_bytes, CHUNK);
        assert!(!st.fin_sent);
    }

    #[test]
    fn poll_gc_prunes_auxiliary_state_under_stream_churn() {
        const ITERATIONS: u64 = 96;
        const COVER_BYTES: usize = 320 * 1024;

        let mut conn = make_conn();
        let cfg = super::Config::new().expect("cfg");
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let rss_before = current_rss_bytes();

        for iteration in 0..ITERATIONS {
            let stream_id = 10_000 + iteration * 4;
            h3.streams.insert(
                stream_id,
                StreamState {
                    _headers: Vec::new(),
                    body_buffer: Vec::new(),
                    frame_buffer: Vec::new(),
                    _received_bytes: 0,
                    _stream_type: StreamType::Masque,
                    sent_bytes: 0,
                    fin_sent: true,
                    fin_received: true,
                    masque_established: true,
                    masque_capsule_buffer: Vec::new(),
                },
            );
            h3.finished_streams.insert(stream_id);
            h3.masque_flow.insert(stream_id, iteration);

            let push_id = 1_000_000 + iteration * 4;
            h3.push_streams.insert(
                push_id,
                PushPromise {
                    headers: Vec::new(),
                    state: PushState::Complete,
                    cover_payload: vec![0u8; COVER_BYTES],
                    scheduled_at: std::time::Instant::now(),
                },
            );
            h3.streams.insert(
                push_id,
                StreamState {
                    _headers: Vec::new(),
                    body_buffer: vec![0u8; COVER_BYTES],
                    frame_buffer: Vec::new(),
                    _received_bytes: 0,
                    _stream_type: StreamType::Push,
                    sent_bytes: COVER_BYTES,
                    fin_sent: true,
                    fin_received: false,
                    masque_established: false,
                    masque_capsule_buffer: Vec::new(),
                },
            );
            h3.finished_streams.insert(push_id);
            h3.masque_flow.insert(push_id, iteration);

            let _ = h3.poll(&mut conn);
            assert!(!h3.streams.contains_key(&stream_id));
            assert!(!h3.streams.contains_key(&push_id));
            assert!(!h3.finished_streams.contains(&stream_id));
            assert!(!h3.finished_streams.contains(&push_id));
            assert!(!h3.masque_flow.contains_key(&stream_id));
            assert!(!h3.masque_flow.contains_key(&push_id));
            assert!(!h3.push_streams.contains_key(&push_id));
        }

        assert!(h3.finished_streams.is_empty(), "finished stream IDs must not accumulate");
        assert!(h3.masque_flow.is_empty(), "MASQUE flow IDs must not accumulate");
        assert!(h3.push_streams.is_empty(), "completed push promises must be released");
        assert!(h3
            .streams
            .keys()
            .all(|id| Some(*id) == h3.control_stream_id), "only the client control stream may remain");

        if let (Some(before), Some(after)) = (rss_before, current_rss_bytes()) {
            const RSS_GROWTH_LIMIT: u64 = 32 * 1024 * 1024;
            assert!(
                after <= before.saturating_add(RSS_GROWTH_LIMIT),
                "H3 churn RSS grew from {before} to {after} bytes"
            );
        }
    }

    #[test]
    fn h3_constructor_does_not_mutate_fec_environment() {
        let _env_lock = crate::fec::test_support::acquire_env_lock();
        let before = std::env::var_os("QUICFUSCATE_FEC_SWITCH_THRESH");
        let mut conn = make_conn();
        let cfg = super::Config::new().expect("cfg");
        let _h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        assert_eq!(std::env::var_os("QUICFUSCATE_FEC_SWITCH_THRESH"), before);
    }

    #[test]
    fn h3_receive_buffers_follow_transport_payload_limits() {
        const MAX_PAYLOAD: usize = 16 * 1024;
        let mut conn = make_conn_with_max_udp_payload_size(MAX_PAYLOAD);
        let cfg = super::Config::new().expect("cfg");
        let h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

        assert_eq!(conn.max_recv_udp_payload_size(), MAX_PAYLOAD);
        assert_eq!(h3.masque_recv_buffer.len(), MAX_PAYLOAD);
        assert_eq!(h3.stream_recv_buffer.len(), 64 * 1024);
    }

    #[test]
    fn stealth_cover_resource_plan_varies_by_seed_with_bounds() {
        let a = super::h3::Connection::build_stealth_cover_resource_plan(
            "/assets",
            0x1234_5678_9abc_def0,
        );
        let b = super::h3::Connection::build_stealth_cover_resource_plan(
            "/assets",
            0x9876_5432_10fe_dcba,
        );

        assert_ne!(a, b, "cover resource plans should vary by seed");
        for plan in [&a, &b] {
            assert!((3..=7).contains(&plan.len()), "cover plan size out of bounds");
            for (path, content_type, size) in plan {
                assert!(path.starts_with("/assets/"));
                assert!(!content_type.is_empty());
                assert!((1024..=320_000).contains(size));
            }
        }
    }

    #[test]
    fn webtransport_cover_session_marks_cover_stream_type() {
        let mut conn = make_conn();
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

        let sid = h3
            .open_webtransport_cover_session(&mut conn, "cdn.example.com", "/assets/wt/session")
            .expect("webtransport cover");
        let st = h3.streams.get(&sid).expect("cover stream state");
        assert!(matches!(st._stream_type, StreamType::WebTransportCover));
    }

    #[test]
    fn masque_capsule_decode_single() {
        // Build buffer: [type=0x00][len=0x03][payload 3 bytes]
        let mut buf = Vec::new();
        Connection::encode_varint(0, &mut buf);
        Connection::encode_varint(3, &mut buf);
        buf.extend_from_slice(&[1, 2, 3]);
        let (ctype, used, payload) = Connection::decode_capsule(&buf[..]).expect("decode");
        assert_eq!(ctype, 0);
        assert_eq!(used, buf.len());
        assert_eq!(payload, vec![1, 2, 3]);
    }

    #[test]
    fn connect_udp_marks_stream_type_masque() {
        let mut conn = make_conn();
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let sid = h3
            .connect_udp(&mut conn, "masque.example.com", "target.example.com:443")
            .expect("connect_udp");
        let st = h3.streams.get(&sid).expect("state");
        assert!(matches!(st._stream_type, StreamType::Masque));
        let flow_id = h3.enable_masque_datagram(&mut conn, sid).expect("enable datagram");
        assert_eq!(Some(&flow_id), h3.masque_flow.get(&sid));
        assert_eq!(h3.masque_flow_id(sid), Some(0));
        assert_eq!(h3.masque_flow_id(sid + 4), None);
        assert_eq!(0, conn.dgram_send_queue_len());

        h3.send_masque_datagram(&mut conn, sid, &[0xAA, 0xBB, 0xCC]).expect("datagram enqueue");
        assert_eq!(1, conn.dgram_send_queue_len());
    }

    #[test]
    fn connect_udp_with_headers_preserves_auth_header() {
        let mut conn = make_conn();
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let sid = h3
            .connect_udp_with_headers(
                &mut conn,
                "masque.example.com",
                "target.example.com:443",
                &[Header::new(b"x-qf-auth", b"token-123")],
            )
            .expect("connect_udp");
        let st = h3.streams.get(&sid).expect("state");
        assert!(st._headers.iter().any(|h| h.name() == b"x-qf-auth" && h.value() == b"token-123"));
    }

    #[test]
    fn masque_datagram_e2e_roundtrip() {
        // E2E Test: Create connection, establish MASQUE, send datagram, verify queue
        let mut conn = make_conn();
        let mut cfg = super::Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

        // Establish CONNECT-UDP
        let sid =
            h3.connect_udp(&mut conn, "proxy.example.com", "192.168.1.1:53").expect("connect_udp");

        // Enable datagrams
        let flow_id = h3.enable_masque_datagram(&mut conn, sid).expect("enable datagram");
        assert_eq!(flow_id, 0); // Default flow ID is 0

        // Send multiple datagrams
        let payloads = [
            b"DNS query payload 1".to_vec(),
            b"DNS query payload 2 longer".to_vec(),
            vec![0xDE, 0xAD, 0xBE, 0xEF], // Binary payload
        ];

        for (i, payload) in payloads.iter().enumerate() {
            h3.send_masque_datagram(&mut conn, sid, payload).expect("datagram send");
            assert_eq!(i + 1, conn.dgram_send_queue_len(), "datagram {} queued", i);
        }

        // Verify MASQUE state
        assert!(h3.masque_flow_active(), "masque flow should be active");
        assert_eq!(Some(&0u64), h3.masque_flow.get(&sid));

        // Verify stream type
        let st = h3.streams.get(&sid).expect("stream state");
        assert!(matches!(st._stream_type, StreamType::Masque));
    }

    #[test]
    fn masque_capsule_encode_decode_roundtrip() {
        // Test capsule encoding and decoding for various types
        let test_cases = vec![
            (0x00u64, b"datagram payload".to_vec()), // DATAGRAM
            (0x21u64, b"compressed data".to_vec()),  // Compressed
            (0x22u64, b"dict compressed".to_vec()),  // Dict compressed
            (0x30u64, vec![0, 1, 2, 3, 4, 5, 6, 7]), // Register context
        ];

        for (ctype, payload) in test_cases {
            let capsule = Connection::encode_capsule(ctype, &payload);
            let (decoded_type, used, decoded_payload) =
                Connection::decode_capsule(&capsule).expect("decode capsule");

            assert_eq!(decoded_type, ctype, "capsule type mismatch");
            assert_eq!(used, capsule.len(), "used bytes mismatch");
            assert_eq!(decoded_payload, payload, "payload mismatch for type {}", ctype);
        }
    }

    #[test]
    fn masque_varint_roundtrip_covers_all_wire_widths() {
        let cases = [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1 << 30, 8),
            ((1 << 62) - 1, 8),
        ];

        for (value, expected_len) in cases {
            let mut encoded = Vec::new();
            Connection::encode_varint(value, &mut encoded);
            assert_eq!(encoded.len(), expected_len, "wire width for {value}");
            let (decoded, used) = Connection::decode_varint(&encoded).expect("decode varint");
            assert_eq!(decoded, value);
            assert_eq!(used, encoded.len());
        }
    }

    #[test]
    fn masque_capsule_roundtrip_supports_16384_byte_payload() {
        let payload = vec![0xA5; 16_384];
        let capsule = Connection::encode_capsule(0x00, &payload);
        assert_eq!(capsule[1] & 0xC0, 0x80, "payload length must use a four-byte varint");
        let (capsule_type, used, decoded) =
            Connection::decode_capsule(&capsule).expect("decode large capsule");
        assert_eq!(capsule_type, 0x00);
        assert_eq!(used, capsule.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn masque_capsule_decoder_retains_split_tail_and_rejects_oversized_length() {
        let mut split = vec![0x00, 0x40];
        let events = Connection::decode_masque_capsules(&mut split).expect("split tail");
        assert!(events.is_empty());
        assert_eq!(split, vec![0x00, 0x40]);

        let mut oversized = vec![0x00, 0xC0, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            Connection::decode_masque_capsules(&mut oversized),
            Err(Error::ExcessiveLoad)
        ));
    }

    #[test]
    fn masque_flow_id_varint_encoding() {
        // Verify flow ID is correctly encoded/decoded with varint
        let mut conn = make_conn();
        conn.enable_datagrams(256, 256);

        // Encode flow_id + payload manually and verify format
        let flow_id = 42u64;
        let payload = b"test udp payload";
        let mut buf = Vec::with_capacity(9 + payload.len());
        Connection::encode_varint(flow_id, &mut buf);
        buf.extend_from_slice(payload);

        // Decode and verify
        let (decoded_flow, used) = Connection::decode_varint(&buf).expect("decode varint");
        assert_eq!(decoded_flow, flow_id);
        assert_eq!(&buf[used..], payload);
    }

    #[cfg(feature = "masque-tests")]
    #[test]
    fn masque_capsule_loopback_roundtrip() {
        // Build a capsule and decode it back
        let mut buf = Vec::new();
        Connection::encode_varint(0x00, &mut buf); // DATAGRAM capsule
        let payload: Vec<u8> = (0..32u8).collect();
        Connection::encode_varint(payload.len() as u64, &mut buf);
        buf.extend_from_slice(&payload);
        let (ctype, used, pl) = Connection::decode_capsule(&buf).expect("capsule");
        assert_eq!(ctype, 0x00);
        assert_eq!(used, buf.len());
        assert_eq!(pl, payload);
    }

    #[cfg(feature = "masque-tests")]
    #[test]
    fn masque_dict_capsule_roundtrip() {
        use crate::compress;
        compress::set_current_persona("test/dict");
        // Train a small dict from samples.
        let base_samples: [&[u8]; 3] = [
            br#"{"a":1,"b":2,"c":3}"#.as_ref(),
            br#"{"foo":"bar","x":4}"#.as_ref(),
            br#"{"long":"somewhat longer json payload to help training"}"#.as_ref(),
        ];
        // Repeat small JSON samples to provide enough corpus for a stable test dictionary.
        let refs: Vec<&[u8]> = (0..96).map(|i| base_samples[i % base_samples.len()]).collect();
        // simulate training outcome by building dict from samples
        let dict_bytes = zstd::dict::from_samples(&refs, 8 * 1024).expect("dict");
        let pool = compress::body_pool();
        let payload = br#"{"msg":"hello json world","n":12345}"#;
        let (blk, used) =
            compress::compress_with_dict(&pool, payload, 5, &dict_bytes, 1).expect("compress");
        // Build a 0x22 capsule.
        let cap = super::h3::Connection::encode_capsule(0x22, &blk[..used]);
        // Parse the header inside the payload and decompress.
        assert!(cap.len() > 3);
        // Skip varints: 0x22 (type) + len -> payload starts at the end.
        // Here we directly test decompress_with_dict.
        let (_ctype, off) = {
            // grob varint decoding
            let mut off = 0usize;
            let first = cap[off];
            off += 1;
            let _ = first; // type
                           // len varint grob
            let mut used = 1;
            if cap[off] & 0x40 != 0 {
                used = 2;
            }
            off += used;
            (0x22u64, off)
        };
        let payload2 = &cap[off..];
        let (_out, n) =
            compress::decompress_with_dict(&pool, payload2, &dict_bytes).expect("decompress");
        assert_eq!(&payload[..], &_out[..n]);
    }

    #[cfg(feature = "masque-tests")]
    #[test]
    fn masque_capsule_rx_counters() {
        use crate::optimize::telemetry;
        let before21 = telemetry::MASQUE_CAPSULE_21.get();
        let before22 = telemetry::MASQUE_CAPSULE_22.get();
        // Build two capsules and pass to decode_capsule (RX counters are incremented there)
        let cap21 = super::h3::Connection::encode_capsule(0x21, b"abcd");
        let _ = Connection::decode_capsule(&cap21).expect("capsule21");
        let cap22 = super::h3::Connection::encode_capsule(0x22, b"efgh");
        let _ = Connection::decode_capsule(&cap22).expect("capsule22");
        assert!(telemetry::MASQUE_CAPSULE_21.get() > before21);
        assert!(telemetry::MASQUE_CAPSULE_22.get() > before22);
    }

    #[test]
    fn test_header_new_accessors() {
        let h = Header::new(b"content-type", b"text/html");
        assert_eq!(h.name(), b"content-type");
        assert_eq!(h.value(), b"text/html");

        let h2 = Header::new(b":status", b"200");
        assert_eq!(h2.name(), b":status");
        assert_eq!(h2.value(), b"200");

        // Empty value
        let h3 = Header::new(b"x-empty", b"");
        assert_eq!(h3.name(), b"x-empty");
        assert_eq!(h3.value(), b"");
    }

    #[test]
    fn test_config_new_defaults() {
        let cfg = Config::new().expect("Config::new");
        // Verify defaults are sane (non-zero max_field_section_size)
        assert_eq!(cfg.qpack_max_table_capacity, 0);
        assert_eq!(cfg.qpack_blocked_streams, 0);
        assert_eq!(cfg.max_field_section_size, 1024 * 1024);
    }

    #[test]
    fn test_encode_capsule_roundtrip() {
        let payload = b"test capsule payload data";
        let capsule = Connection::encode_capsule(0x00, payload);
        let (ctype, used, decoded) =
            Connection::decode_capsule(&capsule).expect("decode capsule roundtrip");
        assert_eq!(ctype, 0x00);
        assert_eq!(used, capsule.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_encode_capsule_empty_payload() {
        let capsule = Connection::encode_capsule(0x21, &[]);
        let (ctype, used, decoded) =
            Connection::decode_capsule(&capsule).expect("decode empty capsule");
        assert_eq!(ctype, 0x21);
        assert_eq!(used, capsule.len());
        assert!(decoded.is_empty());
    }

    #[test]
    fn masque_response_status_accepts_only_valid_status_headers() {
        assert_eq!(
            Connection::masque_response_status(&[Header::new(b":status", b"200")]),
            Some(200)
        );
        assert_eq!(
            Connection::masque_response_status(&[Header::new(b":status", b"403")]),
            Some(403)
        );
        assert_eq!(
            Connection::masque_response_status(&[Header::new(b":status", b"invalid")]),
            None
        );
        assert_eq!(
            Connection::masque_response_status(&[Header::new(b"content-type", b"text/plain")]),
            None
        );
    }

    #[test]
    fn test_encode_udp_compress_capsule_contains_flow_id() {
        // encode_capsule with type 0x21 should start with varint 0x21
        let payload = b"some compressed data";
        let capsule = Connection::encode_capsule(0x21, payload);

        // First byte(s) encode the capsule type as varint.
        // 0x21 = 33 fits in a single-byte varint (< 64).
        assert!(!capsule.is_empty());
        let (decoded_type, _) = Connection::decode_varint(&capsule).expect("varint decode");
        assert_eq!(decoded_type, 0x21);

        // Full roundtrip confirms payload integrity
        let (ctype, _, decoded_payload) =
            Connection::decode_capsule(&capsule).expect("decode capsule");
        assert_eq!(ctype, 0x21);
        assert_eq!(decoded_payload, payload);
    }

    // ---- QPACK Encode/Decode Tests ---------------------------------------

    #[test]
    fn qpack_encode_decode_static_table_hit() {
        let mut enc = qpack::Encoder::new();
        let mut dec = qpack::Decoder::new();
        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":path", b"/"),
        ];
        let mut buf = vec![0u8; 4096];
        let written = enc.encode(&headers, &mut buf).expect("encode");
        assert!(written > 0, "encoder must produce output");

        let decoded = dec.decode(&buf[..written]).expect("decode");
        assert_eq!(decoded.len(), 3, "must decode 3 headers");
        assert_eq!(decoded[0].name(), b":method");
        assert_eq!(decoded[0].value(), b"GET");
    }

    #[test]
    fn qpack_encode_decode_literal_header() {
        let mut enc = qpack::Encoder::new();
        let mut dec = qpack::Decoder::new();
        let headers = vec![Header::new(b"x-custom-header", b"custom-value-123")];
        let mut buf = vec![0u8; 4096];
        let written = enc.encode(&headers, &mut buf).expect("encode");
        assert!(written > 2, "literal encoding must produce more than 2 bytes");

        let decoded = dec.decode(&buf[..written]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name(), b"x-custom-header");
        assert_eq!(decoded[0].value(), b"custom-value-123");
    }

    #[test]
    fn qpack_encode_empty_headers_produces_minimal_output() {
        let mut enc = qpack::Encoder::new();
        let headers: Vec<Header> = vec![];
        let mut buf = vec![0u8; 4096];
        let written = enc.encode(&headers, &mut buf).expect("encode empty");
        // At minimum, the 2-byte prefix (RIC + base)
        assert_eq!(written, 2, "empty headers should produce exactly 2-byte prefix");
    }

    #[test]
    fn qpack_encode_buffer_too_short_returns_error() {
        let mut enc = qpack::Encoder::new();
        let headers = vec![Header::new(b":method", b"GET")];
        let mut buf = vec![0u8; 1]; // Too small
        let result = enc.encode(&headers, &mut buf);
        assert!(matches!(result, Err(Error::BufferTooShort)));
    }

    // ---- HTTP/3 Frame Parsing: HEADERS, DATA, SETTINGS -------------------

    #[test]
    fn parse_frame_header_data_type() {
        // DATA frame: type=0x00, length=5
        let mut buf = vec![0x00]; // type
        Connection::encode_varint(5, &mut buf);
        buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        let (frame_type, frame_len, header_offset) =
            Connection::parse_frame_header(&buf).expect("parse");
        assert_eq!(frame_type, 0x00, "frame type must be DATA");
        assert_eq!(frame_len, 5, "frame length must be 5");
        assert!(header_offset > 0, "header offset must be positive");
    }

    #[test]
    fn parse_frame_header_headers_type() {
        let mut buf = vec![0x01]; // HEADERS type
        Connection::encode_varint(10, &mut buf);
        buf.extend_from_slice(&[0u8; 10]);
        let (frame_type, frame_len, _) = Connection::parse_frame_header(&buf).expect("parse");
        assert_eq!(frame_type, 0x01, "frame type must be HEADERS");
        assert_eq!(frame_len, 10);
    }

    #[test]
    fn parse_frame_header_settings_type() {
        let mut buf = vec![0x04]; // SETTINGS type
        Connection::encode_varint(0, &mut buf);
        let (frame_type, frame_len, _) = Connection::parse_frame_header(&buf).expect("parse");
        assert_eq!(frame_type, 0x04, "frame type must be SETTINGS");
        assert_eq!(frame_len, 0);
    }

    #[test]
    fn parse_frame_header_empty_buffer_returns_error() {
        let buf: Vec<u8> = vec![];
        let result = Connection::parse_frame_header(&buf);
        assert!(matches!(result, Err(Error::BufferTooShort)));
    }

    // ---- Stream Type Identification --------------------------------------

    #[test]
    fn connect_udp_assigns_masque_stream_type() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let sid = h3.connect_udp(&mut conn, "proxy.test", "target.test:443").expect("connect_udp");
        let st = h3.streams.get(&sid).expect("stream state");
        assert!(matches!(st._stream_type, StreamType::Masque));
    }

    #[test]
    fn send_response_assigns_response_stream_type() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let headers = vec![Header::new(b":status", b"200")];
        h3.send_response(&mut conn, 0, &headers, false).expect("send_response");
        let st = h3.streams.get(&0).expect("stream state");
        assert!(matches!(st._stream_type, StreamType::Response));
        assert!(st.sent_bytes > 0, "response HEADERS must reach the transport stream");
    }

    // ---- Settings Frame Encode/Decode ------------------------------------

    #[test]
    fn config_new_defaults_are_valid_for_with_transport() {
        let mut conn = make_conn();
        let cfg = Config::new().expect("cfg");
        // Default config has max_field_section_size = 1MiB which is valid
        let h3 = super::h3::Connection::with_transport(&mut conn, &cfg);
        assert!(h3.is_ok(), "default Config must produce valid H3 connection");
    }

    #[test]
    fn config_zero_max_field_section_rejects() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(0);
        let result = super::h3::Connection::with_transport(&mut conn, &cfg);
        assert!(
            matches!(result, Err(Error::ExcessiveLoad)),
            "zero max_field_section_size must be rejected"
        );
    }

    #[test]
    fn config_excessive_max_field_section_rejects() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(32 * 1024 * 1024); // 32 MiB > 16 MiB limit
        let result = super::h3::Connection::with_transport(&mut conn, &cfg);
        assert!(
            matches!(result, Err(Error::ExcessiveLoad)),
            "excessive max_field_section_size must be rejected"
        );
    }

    // ---- GOAWAY Handling -------------------------------------------------

    #[test]
    fn goaway_blocks_new_requests() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        h3.goaway_sent = true;
        let result = h3.send_request(&mut conn, &[Header::new(b":method", b"GET")], true);
        assert!(
            matches!(result, Err(Error::ClosedCriticalStream)),
            "send_request after GOAWAY must fail"
        );
    }

    #[test]
    fn goaway_received_blocks_new_requests() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        h3.goaway_received = true;
        let result = h3.send_request(&mut conn, &[Header::new(b":method", b"GET")], true);
        assert!(matches!(result, Err(Error::ClosedCriticalStream)));
    }

    // ---- Error Code Mapping ----------------------------------------------

    #[test]
    fn h3_error_from_transport_error() {
        let h3e: Error = Error::from(super::super::Error::BufferTooShort);
        assert!(matches!(h3e, Error::TransportError(_)));
        // Display works
        let s = format!("{}", h3e);
        assert!(!s.is_empty());
    }

    #[test]
    fn h3_error_display_variants() {
        let variants = vec![
            Error::Done,
            Error::BufferTooShort,
            Error::InternalError,
            Error::ExcessiveLoad,
            Error::IdError,
            Error::StreamCreationError,
            Error::ClosedCriticalStream,
            Error::FrameUnexpected,
            Error::FrameError,
            Error::QpackDecompressionFailed,
        ];
        for err in variants {
            let s = format!("{}", err);
            assert!(!s.is_empty(), "Display must produce non-empty string for {:?}", err);
        }
    }

    // ---- Request/Response Header Formatting ------------------------------

    #[test]
    fn send_request_allocates_stream_id() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
        ];
        let sid = h3.send_request(&mut conn, &headers, true).expect("send_request");
        assert!(h3.streams.contains_key(&sid));
        let st = h3.streams.get(&sid).expect("stream");
        assert!(matches!(st._stream_type, StreamType::Request));
        assert!(st.fin_sent, "fin must be set when fin=true");
    }

    #[test]
    fn send_body_on_finished_stream_returns_done() {
        let mut conn = make_conn();
        let mut cfg = Config::new().expect("cfg");
        cfg.set_max_field_section_size(1024 * 1024);
        let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        let headers = vec![Header::new(b":method", b"GET")];
        let sid = h3.send_request(&mut conn, &headers, true).expect("send_request");
        // Stream is finished (fin_sent=true)
        let result = h3.send_body(&mut conn, sid, b"body", false);
        assert!(
            matches!(result, Err(Error::Done)),
            "send_body on finished stream must return Done"
        );
    }

    // ---- Huffman Encoding ------------------------------------------------

    #[test]
    fn huffman_encode_decode_roundtrip() {
        let input = b"content-type";
        let est = qpack::huff_estimate_len(input);
        let mut encoded = vec![0u8; est + 8];
        let enc_len = qpack::huff_encode_into(input, &mut encoded);
        let mut decoded = vec![0u8; input.len() + 16];
        let dec_len =
            qpack::huff_decode_into(&encoded[..enc_len], &mut decoded).expect("huff decode");
        assert_eq!(&decoded[..dec_len], input);
    }

    #[test]
    fn huffman_all_byte_values_roundtrip() {
        let input: Vec<u8> = (0u8..=u8::MAX).collect();
        let mut encoded = vec![0u8; qpack::huff_estimate_len(&input)];
        let enc_len = qpack::huff_encode_into(&input, &mut encoded);
        assert_eq!(enc_len, encoded.len());

        let mut decoded = vec![0u8; input.len()];
        let dec_len = qpack::huff_decode_into(&encoded, &mut decoded).expect("huff decode");
        assert_eq!(dec_len, input.len());
        assert_eq!(decoded, input);
    }

    #[test]
    fn huffman_rfc_tail_symbols_encode_exactly() {
        let mut encoded = [0u8; 8];
        let len_228 = qpack::huff_encode_into(&[228], &mut encoded);
        assert_eq!(&encoded[..len_228], &[0xff, 0xff, 0xa7]);

        let len_255 = qpack::huff_encode_into(&[255], &mut encoded);
        assert_eq!(&encoded[..len_255], &[0xff, 0xff, 0xfb, 0xbf]);
    }

    #[test]
    fn huffman_rejects_eos_and_invalid_padding() {
        let mut decoded = [0u8; 16];
        assert!(matches!(
            qpack::huff_decode_into(&[0xff, 0xff, 0xff, 0xff], &mut decoded),
            Err(Error::QpackDecompressionFailed)
        ));
        assert!(matches!(
            qpack::huff_decode_into(&[0x1e], &mut decoded),
            Err(Error::QpackDecompressionFailed)
        ));
    }

    #[test]
    fn huffman_encode_ascii_range() {
        // Test encoding of common ASCII printable characters
        let input = b"GET /index.html HTTP/1.1";
        let est = qpack::huff_estimate_len(input);
        assert!(est > 0, "huffman estimate must be positive for non-empty input");
        assert!(est <= input.len(), "huffman should compress common HTTP text");
    }

    // ---- Varint Encoding/Decoding ----------------------------------------

    #[test]
    fn varint_roundtrip_small_values() {
        for val in [0u64, 1, 63, 127, 255] {
            let mut buf = Vec::new();
            Connection::encode_varint(val, &mut buf);
            let (decoded, used) = Connection::decode_varint(&buf).expect("decode");
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn varint_roundtrip_large_values() {
        for val in [16383u64, 16384, 1_000_000, u32::MAX as u64] {
            let mut buf = Vec::new();
            Connection::encode_varint(val, &mut buf);
            let (decoded, _) = Connection::decode_varint(&buf).expect("decode");
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
        }
    }

    // ---- Cover Traffic Generation ----------------------------------------

    #[test]
    fn fake_css_generates_correct_size() {
        let css = generate_fake_css(1000);
        assert_eq!(css.len(), 1000);
        // Should contain CSS-like content
        assert!(
            css.windows(4).any(|w| w == b"body" || w == b".rul"),
            "generated CSS must contain CSS-like text"
        );
    }

    #[test]
    fn fake_js_generates_correct_size() {
        let js = generate_fake_js(500);
        assert_eq!(js.len(), 500);
    }

    #[test]
    fn fake_image_starts_with_jpeg_magic() {
        let img = generate_fake_image_data(100);
        assert_eq!(&img[..2], &[0xFF, 0xD8], "fake image must start with JPEG magic bytes");
    }

    // ---- Header from_parts -----------------------------------------------

    #[test]
    fn header_from_parts_avoids_copy() {
        let name = b"x-test".to_vec();
        let value = b"value".to_vec();
        let h = Header::from_parts(name, value);
        assert_eq!(h.name(), b"x-test");
        assert_eq!(h.value(), b"value");
    }

    // ---- Control Stream --------------------------------------------------

    #[test]
    fn client_h3_initializes_control_stream() {
        let mut conn = make_conn(); // client
        let cfg = Config::new().expect("cfg");
        let h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
        assert!(h3.control_stream_id.is_some(), "client must initialize control stream");
        let csid = h3.control_stream_id.unwrap();
        assert!(h3.streams.contains_key(&csid), "control stream must be registered");
    }

    #[test]
    fn h3_config_default_field_section_size() {
        let cfg = Config::new().expect("default H3 config must succeed");
        assert!(cfg.max_field_section_size > 0, "default field section size must be positive");
    }

    #[test]
    fn masque_connect_udp_request_roundtrip_over_paired_1rtt() {
        use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
        let BenchConnectionPair { mut client, mut server, recv_info } =
            bench_paired_1rtt_connections();

        let mut client_h3_cfg = Config::new().expect("cfg");
        client_h3_cfg.set_max_field_section_size(1024 * 1024);
        let mut client_h3 =
            super::h3::Connection::with_transport(&mut client, &client_h3_cfg).unwrap();

        let mut server_h3_cfg = Config::new().expect("cfg");
        server_h3_cfg.set_max_field_section_size(1024 * 1024);
        let mut server_h3 =
            super::h3::Connection::with_transport(&mut server, &server_h3_cfg).unwrap();

        let sid = client_h3
            .connect_udp_with_headers(&mut client, "proxy.test", "target.test:443", &[])
            .expect("connect_udp");
        client_h3.enable_masque_datagram(&mut client, sid).expect("enable_masque_datagram");
        client_h3
            .register_datagram_context(&mut client, sid, 1, 0)
            .expect("register_datagram_context");

        let mut packet = [0u8; 2048];
        let (len, _) = client.send(&mut packet).expect("client send");
        server.recv(&mut packet[..len], &recv_info).expect("server recv");

        match server_h3.poll(&mut server) {
            Ok(Some((rx_sid, Event::Headers { list, .. }))) => {
                assert_eq!(rx_sid, sid, "server must see the same request stream id");
                assert!(
                    list.iter().any(|h| {
                        h.name().eq_ignore_ascii_case(b":method")
                            && h.value().eq_ignore_ascii_case(b"CONNECT")
                    }),
                    "expected CONNECT method in request headers"
                );
            }
            Ok(other) => panic!("expected Headers event, got {:?}", other),
            Err(error) => panic!("server H3 poll failed: {:?}", error),
        }

        assert!(
            server_h3.accept_masque_connect(&mut server, sid).expect("accept CONNECT-UDP"),
            "first accept must emit the readiness response"
        );
        assert!(server_h3.masque_established(sid));
        assert!(
            !server_h3.accept_masque_connect(&mut server, sid).expect("idempotent accept"),
            "accepted flow must not emit duplicate responses"
        );

        let (len, _) = server.send(&mut packet).expect("server response send");
        let client_recv_info = crate::transport::RecvInfo {
            from: recv_info.to,
            to: recv_info.from,
            ecn: None,
        };
        client
            .recv(&mut packet[..len], &client_recv_info)
            .expect("client response receive");
        match client_h3.poll(&mut client) {
            Ok(Some((rx_sid, Event::Headers { list, .. }))) => {
                assert_eq!(rx_sid, sid);
                assert!(list.iter().any(|header| {
                    header.name() == b":status" && header.value() == b"200"
                }));
            }
            Ok(other) => panic!("expected successful response Headers, got {:?}", other),
            Err(error) => panic!("client H3 poll failed: {:?}", error),
        }
        assert!(
            client_h3.masque_established(sid),
            "client readiness requires the peer's 2xx response"
        );
    }

    #[test]
    fn masque_connect_udp_rejection_never_establishes_client_flow() {
        use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
        let BenchConnectionPair { mut client, mut server, recv_info } =
            bench_paired_1rtt_connections();
        let mut client_h3 =
            Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
        let mut server_h3 =
            Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

        let sid = client_h3
            .connect_udp(&mut client, "proxy.test", "target.test:443")
            .expect("connect_udp");
        let mut packet = [0u8; 2048];
        let (len, _) = client.send(&mut packet).expect("client send");
        server.recv(&mut packet[..len], &recv_info).expect("server recv");
        assert!(matches!(
            server_h3.poll(&mut server),
            Ok(Some((_, Event::Headers { .. })))
        ));

        server_h3
            .send_response(
                &mut server,
                sid,
                &[Header::new(b":status", b"403")],
                false,
            )
            .expect("reject CONNECT-UDP");
        let (len, _) = server.send(&mut packet).expect("server response send");
        let client_recv_info = crate::transport::RecvInfo {
            from: recv_info.to,
            to: recv_info.from,
            ecn: None,
        };
        client
            .recv(&mut packet[..len], &client_recv_info)
            .expect("client response receive");
        assert!(matches!(
            client_h3.poll(&mut client),
            Ok(Some((_, Event::Headers { .. })))
        ));
        assert!(
            !client_h3.masque_established(sid),
            "non-2xx response must keep the data plane closed"
        );
    }

    #[test]
    fn masque_data_frame_rejects_truncated_suffix_without_partial_event() {
        use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
        let BenchConnectionPair { mut client, mut server, recv_info } =
            bench_paired_1rtt_connections();
        let _client_h3 =
            Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
        let mut server_h3 =
            Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

        const STREAM_ID: u64 = 248;
        server_h3.streams.insert(
            STREAM_ID,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::Masque,
                sent_bytes: 0,
                fin_sent: false,
                fin_received: false,
                masque_established: true,
                masque_capsule_buffer: Vec::new(),
            },
        );

        let mut capsule_data = Connection::encode_capsule(0x00, b"valid");
        capsule_data.extend_from_slice(&[0x00, 0x40]);
        let mut frame = vec![0x00];
        Connection::encode_varint(capsule_data.len() as u64, &mut frame);
        frame.extend_from_slice(&capsule_data);
        client
            .stream_send(STREAM_ID, &frame, true)
            .expect("send malformed MASQUE DATA frame");

        let mut packet = [0u8; 2048];
        let (len, _) = client.send(&mut packet).expect("client send");
        server.recv(&mut packet[..len], &recv_info).expect("server recv");

        assert!(matches!(server_h3.poll(&mut server), Err(Error::FrameError)));
        assert!(server_h3.pending_events.iter().all(|(_, event)| {
            !matches!(event, Event::MasqueCapsule { .. })
        }));
        assert_eq!(
            server_h3
                .streams
                .get(&STREAM_ID)
                .map(|stream| stream.masque_capsule_buffer.as_slice()),
            Some(&[0x00, 0x40][..])
        );
    }

    #[test]
    fn raw_non_h3_stream_data_is_rejected() {
        use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
        let BenchConnectionPair { mut client, mut server, recv_info } =
            bench_paired_1rtt_connections();

        let _client_h3 =
            Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
        let mut server_h3 =
            Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

        const RAW_STREAM_ID: u64 = 248;
        let raw = vec![0xd1, 0xaa, 0xf0, 0x1e, 0xe6, 0x93, 0x7e, 0xc6];
        client
            .stream_send(RAW_STREAM_ID, &raw, false)
            .expect("send malformed H3 stream data");

        let mut packet = [0u8; 2048];
        let (len, _) = client.send(&mut packet).expect("client send");
        server.recv(&mut packet[..len], &recv_info).expect("server recv");

        assert!(matches!(server_h3.poll(&mut server), Err(Error::ExcessiveLoad)));
    }
}
