/// RFC 9204 QPACK field-section and instruction-stream state.
pub(crate) mod qpack {
    use super::*;
    use std::collections::{HashMap, HashSet, VecDeque};

    const MAX_QPACK_INTEGER: u64 = (1u64 << 62) - 1;
    const MAX_INTEGER_OCTETS: usize = 10;
    const MAX_DECODER_STREAM_BUFFER: usize = 64;
    const MAX_PENDING_DECODER_INSTRUCTIONS: usize = 64 * 1024;
    const MAX_FIELD_SECTION_BYTES: usize = 1024 * 1024;
    const ENTRY_OVERHEAD: usize = 32;

    /// RFC 9204 Appendix A. Indices are stable and start at zero.
    const STATIC_TABLE: &[(&[u8], &[u8])] = &[
        (b":authority", b""),
        (b":path", b"/"),
        (b"age", b"0"),
        (b"content-disposition", b""),
        (b"content-length", b"0"),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"referer", b""),
        (b"set-cookie", b""),
        (b":method", b"CONNECT"),
        (b":method", b"DELETE"),
        (b":method", b"GET"),
        (b":method", b"HEAD"),
        (b":method", b"OPTIONS"),
        (b":method", b"POST"),
        (b":method", b"PUT"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"103"),
        (b":status", b"200"),
        (b":status", b"304"),
        (b":status", b"404"),
        (b":status", b"503"),
        (b"accept", b"*/*"),
        (b"accept", b"application/dns-message"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"accept-ranges", b"bytes"),
        (b"access-control-allow-headers", b"cache-control"),
        (b"access-control-allow-headers", b"content-type"),
        (b"access-control-allow-origin", b"*"),
        (b"cache-control", b"max-age=0"),
        (b"cache-control", b"max-age=2592000"),
        (b"cache-control", b"max-age=604800"),
        (b"cache-control", b"no-cache"),
        (b"cache-control", b"no-store"),
        (b"cache-control", b"public, max-age=31536000"),
        (b"content-encoding", b"br"),
        (b"content-encoding", b"gzip"),
        (b"content-type", b"application/dns-message"),
        (b"content-type", b"application/javascript"),
        (b"content-type", b"application/json"),
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-type", b"image/gif"),
        (b"content-type", b"image/jpeg"),
        (b"content-type", b"image/png"),
        (b"content-type", b"text/css"),
        (b"content-type", b"text/html; charset=utf-8"),
        (b"content-type", b"text/plain"),
        (b"content-type", b"text/plain;charset=utf-8"),
        (b"range", b"bytes=0-"),
        (b"strict-transport-security", b"max-age=31536000"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
        (b"vary", b"accept-encoding"),
        (b"vary", b"origin"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-xss-protection", b"1; mode=block"),
        (b":status", b"100"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"302"),
        (b":status", b"400"),
        (b":status", b"403"),
        (b":status", b"421"),
        (b":status", b"425"),
        (b":status", b"500"),
        (b"accept-language", b""),
        (b"access-control-allow-credentials", b"FALSE"),
        (b"access-control-allow-credentials", b"TRUE"),
        (b"access-control-allow-headers", b"*"),
        (b"access-control-allow-methods", b"get"),
        (b"access-control-allow-methods", b"get, post, options"),
        (b"access-control-allow-methods", b"options"),
        (b"access-control-expose-headers", b"content-length"),
        (b"access-control-request-headers", b"content-type"),
        (b"access-control-request-method", b"get"),
        (b"access-control-request-method", b"post"),
        (b"alt-svc", b"clear"),
        (b"authorization", b""),
        (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
        (b"early-data", b"1"),
        (b"expect-ct", b""),
        (b"forwarded", b""),
        (b"if-range", b""),
        (b"origin", b""),
        (b"purpose", b"prefetch"),
        (b"server", b""),
        (b"timing-allow-origin", b"*"),
        (b"upgrade-insecure-requests", b"1"),
        (b"user-agent", b""),
        (b"x-forwarded-for", b""),
        (b"x-frame-options", b"deny"),
        (b"x-frame-options", b"sameorigin"),
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ParseError {
        Incomplete,
        Invalid,
    }

    #[derive(Debug, Clone)]
    struct DynamicEntry {
        absolute_index: u64,
        name: Vec<u8>,
        value: Vec<u8>,
        size: usize,
        references: u64,
    }

    #[derive(Debug, Clone)]
    struct DynamicTable {
        entries: VecDeque<DynamicEntry>,
        maximum_capacity: usize,
        capacity: usize,
        size: usize,
        insert_count: u64,
    }

    impl DynamicTable {
        fn new(maximum_capacity: u64) -> Self {
            let maximum_capacity = maximum_capacity.min(usize::MAX as u64) as usize;
            Self {
                entries: VecDeque::new(),
                maximum_capacity,
                capacity: 0,
                size: 0,
                insert_count: 0,
            }
        }

        fn replace_maximum_capacity(&mut self, maximum_capacity: u64) -> Result<(), Error> {
            if !self.entries.is_empty() || self.capacity != 0 {
                return Err(Error::SettingsError);
            }
            self.maximum_capacity =
                usize::try_from(maximum_capacity).map_err(|_| Error::ExcessiveLoad)?;
            Ok(())
        }

        fn max_entries(&self) -> u64 {
            (self.maximum_capacity / ENTRY_OVERHEAD) as u64
        }

        fn set_capacity(
            &mut self,
            capacity: u64,
            acknowledged_insert_count: Option<u64>,
        ) -> Result<(), ()> {
            let capacity = usize::try_from(capacity).map_err(|_| ())?;
            if capacity > self.maximum_capacity {
                return Err(());
            }
            self.evict_until_fits(0, capacity, acknowledged_insert_count)?;
            self.capacity = capacity;
            Ok(())
        }

        fn entry_size(name: &[u8], value: &[u8]) -> Option<usize> {
            name.len().checked_add(value.len())?.checked_add(ENTRY_OVERHEAD)
        }

        fn can_insert(
            &self,
            name: &[u8],
            value: &[u8],
            acknowledged_insert_count: Option<u64>,
        ) -> bool {
            let Some(size) = Self::entry_size(name, value) else { return false };
            if size > self.capacity {
                return false;
            }
            let required = self.size.saturating_add(size).saturating_sub(self.capacity);
            let mut reclaimable = 0usize;
            for entry in &self.entries {
                let acknowledged = acknowledged_insert_count
                    .is_none_or(|count| entry.absolute_index < count);
                if entry.references != 0 || !acknowledged {
                    break;
                }
                reclaimable = reclaimable.saturating_add(entry.size);
                if reclaimable >= required {
                    return true;
                }
            }
            required == 0
        }

        fn insert(
            &mut self,
            name: Vec<u8>,
            value: Vec<u8>,
            acknowledged_insert_count: Option<u64>,
        ) -> Result<u64, ()> {
            let size = Self::entry_size(&name, &value).ok_or(())?;
            if size > self.capacity {
                return Err(());
            }
            self.evict_until_fits(size, self.capacity, acknowledged_insert_count)?;
            let absolute_index = self.insert_count;
            self.insert_count = self.insert_count.checked_add(1).ok_or(())?;
            self.size = self.size.checked_add(size).ok_or(())?;
            self.entries.push_back(DynamicEntry {
                absolute_index,
                name,
                value,
                size,
                references: 0,
            });
            Ok(absolute_index)
        }

        fn evict_until_fits(
            &mut self,
            additional: usize,
            capacity: usize,
            acknowledged_insert_count: Option<u64>,
        ) -> Result<(), ()> {
            while self.size.checked_add(additional).ok_or(())? > capacity {
                let front = self.entries.front().ok_or(())?;
                let acknowledged = acknowledged_insert_count
                    .is_none_or(|count| front.absolute_index < count);
                if front.references != 0 || !acknowledged {
                    return Err(());
                }
                let evicted = self.entries.pop_front().ok_or(())?;
                self.size = self.size.checked_sub(evicted.size).ok_or(())?;
            }
            Ok(())
        }

        fn get(&self, absolute_index: u64) -> Option<&DynamicEntry> {
            let oldest = self.entries.front()?.absolute_index;
            let offset = absolute_index.checked_sub(oldest)?;
            self.entries.get(usize::try_from(offset).ok()?)
        }

        fn get_mut(&mut self, absolute_index: u64) -> Option<&mut DynamicEntry> {
            let oldest = self.entries.front()?.absolute_index;
            let offset = absolute_index.checked_sub(oldest)?;
            self.entries.get_mut(usize::try_from(offset).ok()?)
        }

        fn find_exact(&self, name: &[u8], value: &[u8]) -> Option<u64> {
            self.entries
                .iter()
                .rev()
                .find(|entry| entry.name == name && entry.value == value)
                .map(|entry| entry.absolute_index)
        }

        fn find_name(&self, name: &[u8]) -> Option<u64> {
            self.entries
                .iter()
                .rev()
                .find(|entry| entry.name == name)
                .map(|entry| entry.absolute_index)
        }

        fn relative_index(&self, absolute_index: u64) -> Option<u64> {
            self.insert_count.checked_sub(absolute_index)?.checked_sub(1)
        }
    }

    #[derive(Debug, Clone)]
    struct OutstandingSection {
        required_insert_count: u64,
        references: Vec<u64>,
    }

    #[derive(Clone)]
    pub(crate) struct Encoder {
        table: DynamicTable,
        peer_maximum_capacity: u64,
        peer_blocked_streams: u64,
        known_received_count: u64,
        outstanding: HashMap<u64, VecDeque<OutstandingSection>>,
        decoder_stream_buffer: Vec<u8>,
        index_prefer: Vec<Vec<u8>>,
    }

    pub(crate) struct EncodePlan {
        pub(super) field_section: Vec<u8>,
        pub(super) encoder_instructions: Vec<u8>,
        next: Encoder,
        stream_id: u64,
        owns_section: bool,
    }

    impl EncodePlan {
        pub(super) fn commit(self, encoder: &mut Encoder) -> (Vec<u8>, bool, u64) {
            *encoder = self.next;
            (self.field_section, self.owns_section, self.stream_id)
        }
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

        /// Constructs an encoder before peer SETTINGS are available.
        ///
        /// The argument is retained for compatibility with internal tests. Dynamic encoding is
        /// enabled only after `configure_peer` publishes the peer's advertised limits.
        pub(crate) fn with_capacity(_capacity: u64) -> Self {
            Self {
                table: DynamicTable::new(0),
                peer_maximum_capacity: 0,
                peer_blocked_streams: 0,
                known_received_count: 0,
                outstanding: HashMap::new(),
                decoder_stream_buffer: Vec::new(),
                index_prefer: Vec::new(),
            }
        }

        pub(super) fn configure_peer(
            &mut self,
            maximum_capacity: u64,
            blocked_streams: u64,
        ) -> Result<(), Error> {
            self.table.replace_maximum_capacity(maximum_capacity)?;
            self.peer_maximum_capacity = maximum_capacity;
            self.peer_blocked_streams = blocked_streams;
            Ok(())
        }

        pub(super) fn set_index_policy(&mut self, prefer: &[&[u8]]) {
            self.index_prefer = prefer.iter().map(|name| name.to_vec()).collect();
        }

        pub(super) fn prepare(
            &self,
            stream_id: u64,
            headers: &[Header],
        ) -> Result<EncodePlan, Error> {
            let field_section_size = headers.iter().try_fold(0usize, |total, header| {
                total
                    .checked_add(DynamicTable::entry_size(header.name(), header.value())?)
            });
            if field_section_size.is_none_or(|size| size > MAX_FIELD_SECTION_BYTES) {
                return Err(Error::ExcessiveLoad);
            }

            let mut next = self.clone();
            let base = next.table.insert_count;
            let mut encoder_instructions = Vec::new();
            let mut field_lines = Vec::new();
            let mut references = HashSet::new();
            let stream_already_blocked = next.stream_is_blocked(stream_id);
            let blocked_slot_available = stream_already_blocked
                || next.blocked_stream_count() < next.peer_blocked_streams;

            let mut ordered: Vec<&Header> = headers.iter().collect();
            if !next.index_prefer.is_empty() {
                ordered.sort_by_key(|header| {
                    let mut rank = next.index_prefer.len();
                    for (position, preferred) in next.index_prefer.iter().enumerate() {
                        if preferred.as_slice() == header.name() {
                            rank = position;
                            break;
                        }
                    }
                    rank
                });
            }

            for header in ordered {
                let name = header.name();
                let value = header.value();
                let sensitive = is_sensitive(name);
                match static_exact_index(name, value) {
                    Some(index) if !sensitive => {
                        encode_prefixed_integer(&mut field_lines, 0xc0, 6, index as u64)?;
                        continue;
                    }
                    _ => {}
                }

                let mut dynamic_index = next.table.find_exact(name, value);
                if dynamic_index.is_none()
                    && !sensitive
                    && next.peer_maximum_capacity > 0
                    && DynamicTable::entry_size(name, value)
                        .is_some_and(|size| size <= next.peer_maximum_capacity as usize)
                {
                    if next.table.capacity == 0 {
                        next.table
                            .set_capacity(next.peer_maximum_capacity, Some(next.known_received_count))
                            .map_err(|_| Error::InternalError)?;
                        encode_prefixed_integer(
                            &mut encoder_instructions,
                            0x20,
                            5,
                            next.peer_maximum_capacity,
                        )?;
                    }
                    if next.table.can_insert(
                        name,
                        value,
                        Some(next.known_received_count),
                    ) {
                        next.encode_insert(name, value, &mut encoder_instructions)?;
                        dynamic_index = Some(
                            next.table
                                .insert(
                                    name.to_vec(),
                                    value.to_vec(),
                                    Some(next.known_received_count),
                                )
                                .map_err(|_| Error::InternalError)?,
                        );
                    }
                }

                if let Some(absolute_index) = dynamic_index {
                    let acknowledged = absolute_index < next.known_received_count;
                    if acknowledged || blocked_slot_available {
                        encode_dynamic_index(&mut field_lines, absolute_index, base)?;
                        references.insert(absolute_index);
                        continue;
                    }
                }

                encode_literal_field(&mut field_lines, name, value, sensitive)?;
            }

            let required_insert_count = references
                .iter()
                .copied()
                .try_fold(0u64, |maximum, index| {
                    index
                        .checked_add(1)
                        .map(|count| maximum.max(count))
                        .ok_or(Error::InternalError)
                })?;
            let mut field_section = Vec::with_capacity(field_lines.len().saturating_add(16));
            encode_field_section_prefix(
                &mut field_section,
                required_insert_count,
                base,
                next.table.max_entries(),
            )?;
            field_section.extend_from_slice(&field_lines);
            if field_section.len() > MAX_FIELD_SECTION_BYTES
                || encoder_instructions.len() > MAX_FIELD_SECTION_BYTES
            {
                return Err(Error::ExcessiveLoad);
            }

            let mut owns_section = false;
            if !references.is_empty() {
                let mut references: Vec<u64> = references.into_iter().collect();
                references.sort_unstable();
                for absolute_index in &references {
                    let entry = next.table.get_mut(*absolute_index).ok_or(Error::InternalError)?;
                    entry.references = entry.references.checked_add(1).ok_or(Error::InternalError)?;
                }
                next.outstanding.entry(stream_id).or_default().push_back(OutstandingSection {
                    required_insert_count,
                    references,
                });
                owns_section = true;
            }

            Ok(EncodePlan {
                field_section,
                encoder_instructions,
                next,
                stream_id,
                owns_section,
            })
        }

        fn encode_insert(
            &self,
            name: &[u8],
            value: &[u8],
            out: &mut Vec<u8>,
        ) -> Result<(), Error> {
            if let Some(index) = static_name_index(name) {
                encode_prefixed_integer(out, 0xc0, 6, index as u64)?;
                encode_string(out, value, 0, 7, 0x80)?;
                return Ok(());
            }
            if let Some(absolute_index) = self.table.find_name(name) {
                let relative_index = self
                    .table
                    .relative_index(absolute_index)
                    .ok_or(Error::InternalError)?;
                encode_prefixed_integer(out, 0x80, 6, relative_index)?;
                encode_string(out, value, 0, 7, 0x80)?;
                return Ok(());
            }
            encode_string(out, name, 0x40, 5, 0x20)?;
            encode_string(out, value, 0, 7, 0x80)
        }

        fn stream_is_blocked(&self, stream_id: u64) -> bool {
            self.outstanding.get(&stream_id).is_some_and(|sections| {
                sections
                    .iter()
                    .any(|section| section.required_insert_count > self.known_received_count)
            })
        }

        fn blocked_stream_count(&self) -> u64 {
            self.outstanding
                .values()
                .filter(|sections| {
                    sections
                        .iter()
                        .any(|section| section.required_insert_count > self.known_received_count)
                })
                .count() as u64
        }

        pub(super) fn rollback_latest_section(&mut self, stream_id: u64) {
            let section = self.outstanding.get_mut(&stream_id).and_then(VecDeque::pop_back);
            if self.outstanding.get(&stream_id).is_some_and(VecDeque::is_empty) {
                self.outstanding.remove(&stream_id);
            }
            if let Some(section) = section {
                self.release_references(&section.references);
            }
        }

        fn release_references(&mut self, references: &[u64]) {
            for absolute_index in references {
                if let Some(entry) = self.table.get_mut(*absolute_index) {
                    entry.references = entry.references.saturating_sub(1);
                }
            }
        }

        pub(super) fn process_decoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
            let buffered_len = self
                .decoder_stream_buffer
                .len()
                .checked_add(data.len())
                .ok_or(Error::QpackDecoderStreamError)?;
            if buffered_len > MAX_DECODER_STREAM_BUFFER {
                return Err(Error::QpackDecoderStreamError);
            }
            self.decoder_stream_buffer.extend_from_slice(data);
            let mut offset = 0usize;
            while offset < self.decoder_stream_buffer.len() {
                let instruction = match parse_decoder_instruction(&self.decoder_stream_buffer[offset..]) {
                    Ok(instruction) => instruction,
                    Err(ParseError::Incomplete) => break,
                    Err(ParseError::Invalid) => return Err(Error::QpackDecoderStreamError),
                };
                self.apply_decoder_instruction(instruction.0)?;
                offset = offset
                    .checked_add(instruction.1)
                    .ok_or(Error::QpackDecoderStreamError)?;
            }
            if offset > 0 {
                self.decoder_stream_buffer.drain(..offset);
            }
            Ok(())
        }

        fn apply_decoder_instruction(&mut self, instruction: DecoderInstruction) -> Result<(), Error> {
            match instruction {
                DecoderInstruction::SectionAcknowledgement(stream_id) => {
                    let section = self
                        .outstanding
                        .get_mut(&stream_id)
                        .and_then(VecDeque::pop_front)
                        .ok_or(Error::QpackDecoderStreamError)?;
                    if self.outstanding.get(&stream_id).is_some_and(VecDeque::is_empty) {
                        self.outstanding.remove(&stream_id);
                    }
                    self.known_received_count =
                        self.known_received_count.max(section.required_insert_count);
                    if self.known_received_count > self.table.insert_count {
                        return Err(Error::QpackDecoderStreamError);
                    }
                    self.release_references(&section.references);
                }
                DecoderInstruction::StreamCancellation(stream_id) => {
                    let sections = self
                        .outstanding
                        .remove(&stream_id)
                        .ok_or(Error::QpackDecoderStreamError)?;
                    for section in sections {
                        self.release_references(&section.references);
                    }
                }
                DecoderInstruction::InsertCountIncrement(increment) => {
                    if increment == 0 {
                        return Err(Error::QpackDecoderStreamError);
                    }
                    self.known_received_count = self
                        .known_received_count
                        .checked_add(increment)
                        .filter(|count| *count <= self.table.insert_count)
                        .ok_or(Error::QpackDecoderStreamError)?;
                }
            }
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn insert_count(&self) -> u64 {
            self.table.insert_count
        }

        #[cfg(test)]
        pub(super) fn known_received_count(&self) -> u64 {
            self.known_received_count
        }

        #[cfg(test)]
        pub(super) fn outstanding_section_count(&self) -> usize {
            self.outstanding.values().map(VecDeque::len).sum()
        }
    }

    enum DecoderInstruction {
        SectionAcknowledgement(u64),
        StreamCancellation(u64),
        InsertCountIncrement(u64),
    }

    fn parse_decoder_instruction(data: &[u8]) -> Result<(DecoderInstruction, usize), ParseError> {
        let first = *data.first().ok_or(ParseError::Incomplete)?;
        if first & 0x80 != 0 {
            let (stream_id, used) = decode_prefixed_integer(data, 7)?;
            Ok((DecoderInstruction::SectionAcknowledgement(stream_id), used))
        } else if first & 0x40 != 0 {
            let (stream_id, used) = decode_prefixed_integer(data, 6)?;
            Ok((DecoderInstruction::StreamCancellation(stream_id), used))
        } else {
            let (increment, used) = decode_prefixed_integer(data, 6)?;
            if increment == 0 {
                return Err(ParseError::Invalid);
            }
            Ok((DecoderInstruction::InsertCountIncrement(increment), used))
        }
    }

    pub(crate) enum DecodeOutcome {
        Decoded(Vec<Header>),
        Blocked,
    }

    pub(crate) struct Decoder {
        table: DynamicTable,
        maximum_blocked_streams: u64,
        blocked_streams: HashMap<u64, u64>,
        encoder_stream_buffer: Vec<u8>,
        pending_decoder_instructions: Vec<u8>,
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
            Self::with_limits(capacity, 0)
        }

        pub(super) fn with_limits(capacity: u64, maximum_blocked_streams: u64) -> Self {
            Self {
                table: DynamicTable::new(capacity),
                maximum_blocked_streams,
                blocked_streams: HashMap::new(),
                encoder_stream_buffer: Vec::new(),
                pending_decoder_instructions: Vec::new(),
            }
        }

        pub(super) fn process_encoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
            let maximum_buffer = self.table.maximum_capacity.saturating_add(64).max(256);
            let buffered_len = self
                .encoder_stream_buffer
                .len()
                .checked_add(data.len())
                .ok_or(Error::QpackEncoderStreamError)?;
            if buffered_len > maximum_buffer {
                return Err(Error::QpackEncoderStreamError);
            }
            self.encoder_stream_buffer.extend_from_slice(data);
            let mut offset = 0usize;
            let mut inserted = 0u64;
            while offset < self.encoder_stream_buffer.len() {
                let instruction = match self.parse_encoder_instruction(
                    &self.encoder_stream_buffer[offset..],
                ) {
                    Ok(instruction) => instruction,
                    Err(ParseError::Incomplete) => break,
                    Err(ParseError::Invalid) => return Err(Error::QpackEncoderStreamError),
                };
                inserted = inserted
                    .checked_add(self.apply_encoder_instruction(instruction.0)?)
                    .ok_or(Error::QpackEncoderStreamError)?;
                offset = offset
                    .checked_add(instruction.1)
                    .ok_or(Error::QpackEncoderStreamError)?;
            }
            if offset > 0 {
                self.encoder_stream_buffer.drain(..offset);
            }
            if inserted > 0 {
                let mut instruction = Vec::new();
                encode_prefixed_integer(&mut instruction, 0, 6, inserted)
                    .map_err(|_| Error::QpackEncoderStreamError)?;
                self.queue_decoder_instruction(&instruction)?;
            }
            Ok(())
        }

        fn parse_encoder_instruction(
            &self,
            data: &[u8],
        ) -> Result<(EncoderInstruction, usize), ParseError> {
            let first = *data.first().ok_or(ParseError::Incomplete)?;
            if first & 0x80 != 0 {
                let (name_index, index_used) = decode_prefixed_integer(data, 6)?;
                let (value, value_used) = parse_string(
                    &data[index_used..],
                    7,
                    0x80,
                    self.table.maximum_capacity,
                )?;
                let used = index_used.checked_add(value_used).ok_or(ParseError::Invalid)?;
                return Ok((
                    EncoderInstruction::InsertNameReference {
                        static_table: first & 0x40 != 0,
                        name_index,
                        value,
                    },
                    used,
                ));
            }
            if first & 0x40 != 0 {
                let (name, name_used) = parse_string(
                    data,
                    5,
                    0x20,
                    self.table.maximum_capacity,
                )?;
                let (value, value_used) = parse_string(
                    &data[name_used..],
                    7,
                    0x80,
                    self.table.maximum_capacity,
                )?;
                let used = name_used.checked_add(value_used).ok_or(ParseError::Invalid)?;
                return Ok((EncoderInstruction::InsertLiteralName { name, value }, used));
            }
            if first & 0x20 != 0 {
                let (capacity, used) = decode_prefixed_integer(data, 5)?;
                return Ok((EncoderInstruction::SetCapacity(capacity), used));
            }
            let (relative_index, used) = decode_prefixed_integer(data, 5)?;
            Ok((EncoderInstruction::Duplicate(relative_index), used))
        }

        fn apply_encoder_instruction(
            &mut self,
            instruction: EncoderInstruction,
        ) -> Result<u64, Error> {
            match instruction {
                EncoderInstruction::SetCapacity(capacity) => {
                    self.table
                        .set_capacity(capacity, None)
                        .map_err(|_| Error::QpackEncoderStreamError)?;
                    Ok(0)
                }
                EncoderInstruction::InsertNameReference {
                    static_table,
                    name_index,
                    value,
                } => {
                    let name = if static_table {
                        STATIC_TABLE
                            .get(usize::try_from(name_index).map_err(|_| Error::QpackEncoderStreamError)?)
                            .map(|(name, _)| name.to_vec())
                            .ok_or(Error::QpackEncoderStreamError)?
                    } else {
                        let absolute_index = self
                            .table
                            .insert_count
                            .checked_sub(name_index)
                            .and_then(|count| count.checked_sub(1))
                            .ok_or(Error::QpackEncoderStreamError)?;
                        self.table
                            .get(absolute_index)
                            .map(|entry| entry.name.clone())
                            .ok_or(Error::QpackEncoderStreamError)?
                    };
                    self.table
                        .insert(name, value, None)
                        .map_err(|_| Error::QpackEncoderStreamError)?;
                    Ok(1)
                }
                EncoderInstruction::InsertLiteralName { name, value } => {
                    self.table
                        .insert(name, value, None)
                        .map_err(|_| Error::QpackEncoderStreamError)?;
                    Ok(1)
                }
                EncoderInstruction::Duplicate(relative_index) => {
                    let absolute_index = self
                        .table
                        .insert_count
                        .checked_sub(relative_index)
                        .and_then(|count| count.checked_sub(1))
                        .ok_or(Error::QpackEncoderStreamError)?;
                    let entry = self
                        .table
                        .get(absolute_index)
                        .cloned()
                        .ok_or(Error::QpackEncoderStreamError)?;
                    self.table
                        .insert(entry.name, entry.value, None)
                        .map_err(|_| Error::QpackEncoderStreamError)?;
                    Ok(1)
                }
            }
        }

        pub(super) fn decode(
            &mut self,
            stream_id: u64,
            data: &[u8],
        ) -> Result<DecodeOutcome, Error> {
            let (encoded_required_insert_count, ric_used) =
                decode_prefixed_integer(data, 8).map_err(|_| Error::QpackDecompressionFailed)?;
            let prefix_tail = data.get(ric_used..).ok_or(Error::QpackDecompressionFailed)?;
            let sign = prefix_tail
                .first()
                .is_some_and(|first| first & 0x80 != 0);
            let (delta_base, base_used) =
                decode_prefixed_integer(prefix_tail, 7).map_err(|_| Error::QpackDecompressionFailed)?;
            let required_insert_count = self.decode_required_insert_count(encoded_required_insert_count)?;
            let base = if sign {
                required_insert_count
                    .checked_sub(delta_base)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or(Error::QpackDecompressionFailed)?
            } else {
                required_insert_count
                    .checked_add(delta_base)
                    .filter(|value| *value <= MAX_QPACK_INTEGER)
                    .ok_or(Error::QpackDecompressionFailed)?
            };
            if required_insert_count == 0 && base != 0 {
                return Err(Error::QpackDecompressionFailed);
            }
            if required_insert_count > self.table.insert_count {
                if !self.blocked_streams.contains_key(&stream_id)
                    && self.blocked_streams.len() as u64 >= self.maximum_blocked_streams
                {
                    return Err(Error::QpackDecompressionFailed);
                }
                self.blocked_streams.insert(stream_id, required_insert_count);
                return Ok(DecodeOutcome::Blocked);
            }

            self.blocked_streams.remove(&stream_id);
            let body_offset = ric_used
                .checked_add(base_used)
                .ok_or(Error::QpackDecompressionFailed)?;
            let body = data.get(body_offset..).ok_or(Error::QpackDecompressionFailed)?;
            let (headers, referenced) =
                self.decode_field_lines(body, required_insert_count, base)?;
            if required_insert_count == 0 {
                if !referenced.is_empty() {
                    return Err(Error::QpackDecompressionFailed);
                }
            } else if referenced
                .iter()
                .copied()
                .max()
                .and_then(|index| index.checked_add(1))
                != Some(required_insert_count)
            {
                return Err(Error::QpackDecompressionFailed);
            }
            if !referenced.is_empty() {
                let mut acknowledgement = Vec::new();
                encode_prefixed_integer(&mut acknowledgement, 0x80, 7, stream_id)
                    .map_err(|_| Error::QpackDecompressionFailed)?;
                self.queue_decoder_instruction(&acknowledgement)?;
            }
            Ok(DecodeOutcome::Decoded(headers))
        }

        fn decode_required_insert_count(&self, encoded: u64) -> Result<u64, Error> {
            if encoded == 0 {
                return Ok(0);
            }
            let max_entries = self.table.max_entries();
            let full_range = max_entries
                .checked_mul(2)
                .filter(|range| *range > 0)
                .ok_or(Error::QpackDecompressionFailed)?;
            if encoded > full_range {
                return Err(Error::QpackDecompressionFailed);
            }
            let max_value = self
                .table
                .insert_count
                .checked_add(max_entries)
                .ok_or(Error::QpackDecompressionFailed)?;
            let max_wrapped = max_value / full_range * full_range;
            let mut required = max_wrapped
                .checked_add(encoded)
                .and_then(|value| value.checked_sub(1))
                .ok_or(Error::QpackDecompressionFailed)?;
            if required > max_value {
                required = required
                    .checked_sub(full_range)
                    .ok_or(Error::QpackDecompressionFailed)?;
            }
            if required == 0 {
                return Err(Error::QpackDecompressionFailed);
            }
            Ok(required)
        }

        fn decode_field_lines(
            &self,
            data: &[u8],
            required_insert_count: u64,
            base: u64,
        ) -> Result<(Vec<Header>, HashSet<u64>), Error> {
            let mut offset = 0usize;
            let mut headers = Vec::new();
            let mut referenced = HashSet::new();
            while offset < data.len() {
                let first = data[offset];
                if first & 0x80 != 0 {
                    let (index, used) = decode_prefixed_integer(&data[offset..], 6)
                        .map_err(|_| Error::QpackDecompressionFailed)?;
                    if first & 0x40 != 0 {
                        let (name, value) = static_entry(index)?;
                        headers.push(Header::new(name, value));
                    } else {
                        let absolute_index = base
                            .checked_sub(index)
                            .and_then(|value| value.checked_sub(1))
                            .ok_or(Error::QpackDecompressionFailed)?;
                        let entry = self.dynamic_reference(absolute_index, required_insert_count)?;
                        referenced.insert(absolute_index);
                        headers.push(Header::new(&entry.name, &entry.value));
                    }
                    offset = offset.checked_add(used).ok_or(Error::QpackDecompressionFailed)?;
                    continue;
                }
                if first & 0x40 != 0 {
                    let (name_index, name_used) = decode_prefixed_integer(&data[offset..], 4)
                        .map_err(|_| Error::QpackDecompressionFailed)?;
                    let name = if first & 0x10 != 0 {
                        static_entry(name_index)?.0.to_vec()
                    } else {
                        let absolute_index = base
                            .checked_sub(name_index)
                            .and_then(|value| value.checked_sub(1))
                            .ok_or(Error::QpackDecompressionFailed)?;
                        let entry = self.dynamic_reference(absolute_index, required_insert_count)?;
                        referenced.insert(absolute_index);
                        entry.name.clone()
                    };
                    let (value, value_used) = parse_string(
                        data.get(offset + name_used..).ok_or(Error::QpackDecompressionFailed)?,
                        7,
                        0x80,
                        MAX_FIELD_SECTION_BYTES,
                    ).map_err(|_| Error::QpackDecompressionFailed)?;
                    headers.push(Header::from_parts(name, value));
                    offset = offset
                        .checked_add(name_used)
                        .and_then(|value| value.checked_add(value_used))
                        .ok_or(Error::QpackDecompressionFailed)?;
                    continue;
                }
                if first & 0x20 != 0 {
                    let (name, name_used) = parse_string(
                        &data[offset..],
                        3,
                        0x08,
                        MAX_FIELD_SECTION_BYTES,
                    ).map_err(|_| Error::QpackDecompressionFailed)?;
                    let (value, value_used) = parse_string(
                        data.get(offset + name_used..).ok_or(Error::QpackDecompressionFailed)?,
                        7,
                        0x80,
                        MAX_FIELD_SECTION_BYTES,
                    ).map_err(|_| Error::QpackDecompressionFailed)?;
                    headers.push(Header::from_parts(name, value));
                    offset = offset
                        .checked_add(name_used)
                        .and_then(|value| value.checked_add(value_used))
                        .ok_or(Error::QpackDecompressionFailed)?;
                    continue;
                }
                if first & 0x10 != 0 {
                    let (post_base_index, used) = decode_prefixed_integer(&data[offset..], 4)
                        .map_err(|_| Error::QpackDecompressionFailed)?;
                    let absolute_index = base
                        .checked_add(post_base_index)
                        .ok_or(Error::QpackDecompressionFailed)?;
                    let entry = self.dynamic_reference(absolute_index, required_insert_count)?;
                    referenced.insert(absolute_index);
                    headers.push(Header::new(&entry.name, &entry.value));
                    offset = offset.checked_add(used).ok_or(Error::QpackDecompressionFailed)?;
                    continue;
                }
                let (post_base_index, name_used) = decode_prefixed_integer(&data[offset..], 3)
                    .map_err(|_| Error::QpackDecompressionFailed)?;
                let absolute_index = base
                    .checked_add(post_base_index)
                    .ok_or(Error::QpackDecompressionFailed)?;
                let name = self
                    .dynamic_reference(absolute_index, required_insert_count)?
                    .name
                    .clone();
                referenced.insert(absolute_index);
                let (value, value_used) = parse_string(
                    data.get(offset + name_used..).ok_or(Error::QpackDecompressionFailed)?,
                    7,
                    0x80,
                    MAX_FIELD_SECTION_BYTES,
                ).map_err(|_| Error::QpackDecompressionFailed)?;
                headers.push(Header::from_parts(name, value));
                offset = offset
                    .checked_add(name_used)
                    .and_then(|value| value.checked_add(value_used))
                    .ok_or(Error::QpackDecompressionFailed)?;
            }
            Ok((headers, referenced))
        }

        fn dynamic_reference(
            &self,
            absolute_index: u64,
            required_insert_count: u64,
        ) -> Result<&DynamicEntry, Error> {
            if absolute_index >= required_insert_count {
                return Err(Error::QpackDecompressionFailed);
            }
            self.table.get(absolute_index).ok_or(Error::QpackDecompressionFailed)
        }

        fn queue_decoder_instruction(&mut self, instruction: &[u8]) -> Result<(), Error> {
            let new_len = self
                .pending_decoder_instructions
                .len()
                .checked_add(instruction.len())
                .ok_or(Error::ExcessiveLoad)?;
            if new_len > MAX_PENDING_DECODER_INSTRUCTIONS {
                return Err(Error::ExcessiveLoad);
            }
            self.pending_decoder_instructions.extend_from_slice(instruction);
            Ok(())
        }

        pub(super) fn pending_decoder_instructions(&self) -> &[u8] {
            &self.pending_decoder_instructions
        }

        pub(super) fn consume_decoder_instructions(&mut self, count: usize) {
            self.pending_decoder_instructions.drain(..count);
        }

        pub(super) fn take_unblocked_streams(&mut self) -> Vec<u64> {
            let ready: Vec<u64> = self
                .blocked_streams
                .iter()
                .filter_map(|(stream_id, required)| {
                    (*required <= self.table.insert_count).then_some(*stream_id)
                })
                .collect();
            for stream_id in &ready {
                self.blocked_streams.remove(stream_id);
            }
            ready
        }

        pub(super) fn cancel_stream(&mut self, stream_id: u64) -> Result<bool, Error> {
            if self.blocked_streams.remove(&stream_id).is_none() {
                return Ok(false);
            }
            let mut instruction = Vec::new();
            encode_prefixed_integer(&mut instruction, 0x40, 6, stream_id)
                .map_err(|_| Error::InternalError)?;
            self.queue_decoder_instruction(&instruction)?;
            Ok(true)
        }

        #[cfg(test)]
        pub(super) fn insert_count(&self) -> u64 {
            self.table.insert_count
        }

        #[cfg(test)]
        fn table_size(&self) -> usize {
            self.table.size
        }
    }

    enum EncoderInstruction {
        SetCapacity(u64),
        InsertNameReference {
            static_table: bool,
            name_index: u64,
            value: Vec<u8>,
        },
        InsertLiteralName {
            name: Vec<u8>,
            value: Vec<u8>,
        },
        Duplicate(u64),
    }

    fn encode_dynamic_index(
        out: &mut Vec<u8>,
        absolute_index: u64,
        base: u64,
    ) -> Result<(), Error> {
        if absolute_index < base {
            let relative = base
                .checked_sub(absolute_index)
                .and_then(|value| value.checked_sub(1))
                .ok_or(Error::InternalError)?;
            encode_prefixed_integer(out, 0x80, 6, relative)
        } else {
            let post_base = absolute_index.checked_sub(base).ok_or(Error::InternalError)?;
            encode_prefixed_integer(out, 0x10, 4, post_base)
        }
    }

    fn encode_literal_field(
        out: &mut Vec<u8>,
        name: &[u8],
        value: &[u8],
        sensitive: bool,
    ) -> Result<(), Error> {
        if let Some(index) = static_name_index(name) {
            let first = 0x50 | if sensitive { 0x20 } else { 0 };
            encode_prefixed_integer(out, first, 4, index as u64)?;
        } else {
            let first = 0x20 | if sensitive { 0x10 } else { 0 };
            encode_string(out, name, first, 3, 0x08)?;
        }
        encode_string(out, value, 0, 7, 0x80)
    }

    fn encode_field_section_prefix(
        out: &mut Vec<u8>,
        required_insert_count: u64,
        base: u64,
        max_entries: u64,
    ) -> Result<(), Error> {
        let encoded = if required_insert_count == 0 {
            0
        } else {
            let full_range = max_entries
                .checked_mul(2)
                .filter(|range| *range > 0)
                .ok_or(Error::InternalError)?;
            required_insert_count % full_range + 1
        };
        encode_prefixed_integer(out, 0, 8, encoded)?;
        if base >= required_insert_count {
            encode_prefixed_integer(out, 0, 7, base - required_insert_count)
        } else {
            let delta = required_insert_count
                .checked_sub(base)
                .and_then(|value| value.checked_sub(1))
                .ok_or(Error::InternalError)?;
            encode_prefixed_integer(out, 0x80, 7, delta)
        }
    }

    fn static_exact_index(name: &[u8], value: &[u8]) -> Option<usize> {
        STATIC_TABLE.iter().position(|entry| entry.0 == name && entry.1 == value)
    }

    fn static_name_index(name: &[u8]) -> Option<usize> {
        STATIC_TABLE.iter().position(|entry| entry.0 == name)
    }

    fn static_entry(index: u64) -> Result<(&'static [u8], &'static [u8]), Error> {
        STATIC_TABLE
            .get(usize::try_from(index).map_err(|_| Error::QpackDecompressionFailed)?)
            .copied()
            .ok_or(Error::QpackDecompressionFailed)
    }

    fn is_sensitive(name: &[u8]) -> bool {
        const SENSITIVE_NAMES: &[&[u8]] = &[
            b"authorization",
            b"cookie",
            b"set-cookie",
            b"proxy-authorization",
            b"x-qf-auth",
            b"x-api-key",
        ];
        SENSITIVE_NAMES
            .iter()
            .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
    }

    fn encode_prefixed_integer(
        out: &mut Vec<u8>,
        first: u8,
        prefix_bits: u8,
        value: u64,
    ) -> Result<(), Error> {
        if !(1..=8).contains(&prefix_bits) || value > MAX_QPACK_INTEGER {
            return Err(Error::InternalError);
        }
        let prefix_max = if prefix_bits == 8 {
            u8::MAX as u64
        } else {
            (1u64 << prefix_bits) - 1
        };
        if value < prefix_max {
            out.push(first | value as u8);
            return Ok(());
        }
        out.push(first | prefix_max as u8);
        let mut remainder = value - prefix_max;
        while remainder >= 128 {
            out.push((remainder as u8 & 0x7f) | 0x80);
            remainder >>= 7;
        }
        out.push(remainder as u8);
        Ok(())
    }

    fn decode_prefixed_integer(data: &[u8], prefix_bits: u8) -> Result<(u64, usize), ParseError> {
        if !(1..=8).contains(&prefix_bits) {
            return Err(ParseError::Invalid);
        }
        let first = *data.first().ok_or(ParseError::Incomplete)?;
        let prefix_max = if prefix_bits == 8 {
            u8::MAX as u64
        } else {
            (1u64 << prefix_bits) - 1
        };
        let mut value = (first as u64) & prefix_max;
        if value < prefix_max {
            return Ok((value, 1));
        }
        let mut shift = 0u32;
        let mut used = 1usize;
        loop {
            if used >= MAX_INTEGER_OCTETS {
                return Err(ParseError::Invalid);
            }
            let byte = *data.get(used).ok_or(ParseError::Incomplete)?;
            let contribution = u64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or(ParseError::Invalid)?;
            value = value.checked_add(contribution).ok_or(ParseError::Invalid)?;
            used += 1;
            if value > MAX_QPACK_INTEGER {
                return Err(ParseError::Invalid);
            }
            if byte & 0x80 == 0 {
                return Ok((value, used));
            }
            shift = shift.checked_add(7).ok_or(ParseError::Invalid)?;
            if shift >= 63 {
                return Err(ParseError::Invalid);
            }
        }
    }

    fn encode_string(
        out: &mut Vec<u8>,
        value: &[u8],
        first: u8,
        prefix_bits: u8,
        huffman_mask: u8,
    ) -> Result<(), Error> {
        let huffman_len = huff_estimate_len(value);
        if huffman_len < value.len() {
            encode_prefixed_integer(out, first | huffman_mask, prefix_bits, huffman_len as u64)?;
            let start = out.len();
            out.resize(start.checked_add(huffman_len).ok_or(Error::ExcessiveLoad)?, 0);
            let written = huff_encode_into(value, &mut out[start..]);
            if written != huffman_len {
                return Err(Error::InternalError);
            }
        } else {
            encode_prefixed_integer(out, first, prefix_bits, value.len() as u64)?;
            out.extend_from_slice(value);
        }
        Ok(())
    }

    fn parse_string(
        data: &[u8],
        prefix_bits: u8,
        huffman_mask: u8,
        maximum_decoded_len: usize,
    ) -> Result<(Vec<u8>, usize), ParseError> {
        let first = *data.first().ok_or(ParseError::Incomplete)?;
        let huffman = first & huffman_mask != 0;
        let (encoded_len, prefix_used) = decode_prefixed_integer(data, prefix_bits)?;
        let encoded_len = usize::try_from(encoded_len).map_err(|_| ParseError::Invalid)?;
        if encoded_len > maximum_decoded_len {
            return Err(ParseError::Invalid);
        }
        let end = prefix_used.checked_add(encoded_len).ok_or(ParseError::Invalid)?;
        let encoded = data.get(prefix_used..end).ok_or(ParseError::Incomplete)?;
        if !huffman {
            return Ok((encoded.to_vec(), end));
        }
        let estimated_len = encoded_len.saturating_mul(2).saturating_add(1);
        let initial_len = estimated_len.min(maximum_decoded_len).max(1);
        let mut decoded = vec![0u8; initial_len];
        match huff_decode_into(encoded, &mut decoded) {
            Ok(written) => decoded.truncate(written),
            Err(Error::BufferTooShort) if initial_len < maximum_decoded_len => {
                decoded.resize(maximum_decoded_len, 0);
                let written = huff_decode_into(encoded, &mut decoded)
                    .map_err(|_| ParseError::Invalid)?;
                decoded.truncate(written);
            }
            Err(_) => return Err(ParseError::Invalid),
        }
        Ok((decoded, end))
    }

    #[inline]
    pub(crate) fn huff_estimate_len(input: &[u8]) -> usize {
        qf_simd::qpack::huff_estimate_len(input)
    }

    #[inline]
    pub(crate) fn huff_encode_into(input: &[u8], output: &mut [u8]) -> usize {
        qf_simd::qpack::huff_encode_into(input, output)
    }

    pub(crate) fn huff_decode_into(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        qf_simd::qpack::huff_decode_into(data, out).map_err(|error| match error {
            qf_simd::qpack::HuffmanError::BufferTooShort => Error::BufferTooShort,
            qf_simd::qpack::HuffmanError::InvalidEncoding => Error::QpackDecompressionFailed,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn must_succeed<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
            match result {
                Ok(value) => value,
                Err(error) => panic!("operation failed: {error:?}"),
            }
        }

        fn appendix_b_encoder_stream() -> Vec<u8> {
            let mut bytes = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
            bytes.extend_from_slice(b"www.example.com");
            bytes.extend_from_slice(&[0xc1, 0x0c]);
            bytes.extend_from_slice(b"/sample/path");
            bytes
        }

        fn total_insert_count_increment(instructions: &[u8]) -> u64 {
            let mut offset = 0usize;
            let mut total = 0u64;
            while offset < instructions.len() {
                let (instruction, used) =
                    must_succeed(parse_decoder_instruction(&instructions[offset..]));
                let increment = match instruction {
                    DecoderInstruction::InsertCountIncrement(value) => value,
                    _ => panic!("fragmented inserts must only emit insert-count feedback"),
                };
                total = match total.checked_add(increment) {
                    Some(value) => value,
                    None => panic!("insert-count feedback overflowed"),
                };
                offset += used;
            }
            total
        }

        #[test]
        fn static_table_matches_rfc_9204_appendix_a() {
            assert_eq!(STATIC_TABLE.len(), 99);
            assert_eq!(STATIC_TABLE[0], (&b":authority"[..], &b""[..]));
            assert_eq!(STATIC_TABLE[41], (&b"cache-control"[..], &b"public, max-age=31536000"[..]));
            assert_eq!(STATIC_TABLE[98], (&b"x-frame-options"[..], &b"sameorigin"[..]));
        }

        #[test]
        fn appendix_b_dynamic_section_blocks_then_decodes_and_acknowledges() {
            let mut decoder = Decoder::with_limits(220, 1);
            let field_section = [0x03, 0x81, 0x10, 0x11];
            assert!(matches!(
                must_succeed(decoder.decode(4, &field_section)),
                DecodeOutcome::Blocked
            ));

            must_succeed(decoder.process_encoder_stream(&appendix_b_encoder_stream()));
            assert_eq!(decoder.insert_count(), 2);
            assert_eq!(decoder.take_unblocked_streams(), [4]);
            let headers = match must_succeed(decoder.decode(4, &field_section)) {
                DecodeOutcome::Decoded(headers) => headers,
                DecodeOutcome::Blocked => panic!("insertions must release the blocked section"),
            };
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].name(), b":authority");
            assert_eq!(headers[0].value(), b"www.example.com");
            assert_eq!(headers[1].name(), b":path");
            assert_eq!(headers[1].value(), b"/sample/path");
            assert_eq!(decoder.pending_decoder_instructions(), [0x02, 0x84]);
        }

        #[test]
        fn encoder_stream_parser_retains_every_fragment_boundary() {
            let mut decoder = Decoder::with_limits(220, 1);
            for byte in appendix_b_encoder_stream() {
                must_succeed(decoder.process_encoder_stream(&[byte]));
            }
            assert_eq!(decoder.insert_count(), 2);
            assert_eq!(
                total_insert_count_increment(decoder.pending_decoder_instructions()),
                2
            );
        }

        #[test]
        fn prepared_dynamic_section_roundtrips_and_releases_references() {
            let mut encoder = Encoder::new();
            must_succeed(encoder.configure_peer(220, 1));
            let headers = [
                Header::new(b":authority", b"www.example.com"),
                Header::new(b":path", b"/sample/path"),
            ];
            let plan = must_succeed(encoder.prepare(4, &headers));
            let instructions = plan.encoder_instructions.clone();
            assert!(!instructions.is_empty());
            let (field_section, owns_section, stream_id) = plan.commit(&mut encoder);
            assert!(owns_section);
            assert_eq!(stream_id, 4);
            assert_eq!(encoder.insert_count(), 2);

            let mut decoder = Decoder::with_limits(220, 1);
            must_succeed(decoder.process_encoder_stream(&instructions));
            let decoded = match must_succeed(decoder.decode(4, &field_section)) {
                DecodeOutcome::Decoded(headers) => headers,
                DecodeOutcome::Blocked => panic!("instructions precede the field section"),
            };
            assert_eq!(decoded.len(), 2);
            assert_eq!(decoded[0].value(), b"www.example.com");
            assert_eq!(decoded[1].value(), b"/sample/path");

            must_succeed(
                encoder.process_decoder_stream(decoder.pending_decoder_instructions()),
            );
            assert_eq!(encoder.known_received_count(), 2);
            assert!(!encoder.outstanding.contains_key(&4));
            assert!(encoder.table.entries.iter().all(|entry| entry.references == 0));
        }

        #[test]
        fn sensitive_static_matches_use_never_indexed_literals() {
            let encoder = Encoder::new();
            let plan = must_succeed(encoder.prepare(0, &[Header::new(b"authorization", b"")]));
            assert!(plan.encoder_instructions.is_empty());
            assert_eq!(plan.field_section[2] & 0xe0, 0x60);
        }

        #[test]
        fn capacity_eviction_is_byte_exact_and_oldest_first() {
            let mut decoder = Decoder::with_limits(64, 0);
            let instructions = [
                0x3f, 0x21, // Set Dynamic Table Capacity = 64.
                0x41, b'a', 0x01, b'1', // a=1, size 34.
                0x41, b'b', 0x01, b'2', // b=2, evicts a=1.
            ];
            must_succeed(decoder.process_encoder_stream(&instructions));
            assert_eq!(decoder.insert_count(), 2);
            assert_eq!(decoder.table_size(), 34);
            assert!(decoder.table.get(0).is_none());
            assert_eq!(decoder.table.get(1).map(|entry| entry.name.as_slice()), Some(&b"b"[..]));
        }

        #[test]
        fn malformed_instruction_streams_map_to_their_distinct_errors() {
            let mut decoder = Decoder::with_limits(64, 0);
            assert!(matches!(
                decoder.process_encoder_stream(&[0x3f, 0x22]),
                Err(Error::QpackEncoderStreamError)
            ));

            let mut encoder = Encoder::new();
            must_succeed(encoder.configure_peer(64, 1));
            assert!(matches!(
                encoder.process_decoder_stream(&[0x00]),
                Err(Error::QpackDecoderStreamError)
            ));
            assert!(matches!(
                encoder.process_decoder_stream(&[0x01]),
                Err(Error::QpackDecoderStreamError)
            ));
        }

        #[test]
        fn blocked_stream_cancellation_releases_encoder_ownership() {
            let mut encoder = Encoder::new();
            must_succeed(encoder.configure_peer(64, 1));
            let plan = must_succeed(encoder.prepare(8, &[Header::new(b"x-owned", b"value")]));
            let (field_section, owns_section, _) = plan.commit(&mut encoder);
            assert!(owns_section);

            let mut decoder = Decoder::with_limits(64, 1);
            assert!(matches!(
                must_succeed(decoder.decode(8, &field_section)),
                DecodeOutcome::Blocked
            ));
            assert!(must_succeed(decoder.cancel_stream(8)));
            assert_eq!(decoder.pending_decoder_instructions(), [0x48]);
            must_succeed(encoder.process_decoder_stream(&[0x48]));
            assert!(!encoder.outstanding.contains_key(&8));
            assert!(encoder.table.entries.iter().all(|entry| entry.references == 0));
        }

        #[test]
        fn blocked_stream_limit_and_impossible_references_fail_decompression() {
            let mut decoder = Decoder::with_limits(64, 0);
            assert!(matches!(
                decoder.decode(0, &[0x02, 0x80, 0x10]),
                Err(Error::QpackDecompressionFailed)
            ));
            assert!(matches!(
                decoder.decode(0, &[0x05, 0x00]),
                Err(Error::QpackDecompressionFailed)
            ));
        }
    }
}
