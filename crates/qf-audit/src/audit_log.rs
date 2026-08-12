use super::*;

impl AuditLog {
    /// Create a new audit log at the given path.
    ///
    /// If the file already exists, the chain is resumed from the last entry's
    /// hash. Otherwise, a new chain is started with a genesis hash of all-zeros.
    pub fn open(path: PathBuf) -> Result<Self, AuditError> {
        Self::open_with_options(path, AuditOptions::default())
    }

    /// Create a new audit owner with explicit bounded persistence settings.
    pub fn open_with_options(path: PathBuf, options: AuditOptions) -> Result<Self, AuditError> {
        options.validate()?;
        if path.exists() {
            let metadata = std::fs::symlink_metadata(&path).map_err(AuditError::IoError)?;
            if !metadata.file_type().is_file() {
                return Err(AuditError::HashError(format!(
                    "audit path must be a regular file: {}",
                    path.display()
                )));
            }
        }
        recover_interrupted_rotation(&path)?;
        let has_checkpoint = checkpoint_path(&path).exists();
        let (next_seq, last_hash) = if path.exists() || has_checkpoint {
            read_tail_state(&path)?
        } else {
            (0, "0".repeat(64))
        };

        let file = open_private_append_file(&path, false).map_err(AuditError::IoError)?;
        let active_bytes = file.metadata().map_err(AuditError::IoError)?.len();
        let active_start_seq =
            if active_bytes == 0 { next_seq } else { read_first_sequence(&path)? };
        let rotated_segments = discover_rotated_segments(&path)?;

        let dropped_events = Arc::new(AtomicU64::new(0));
        let queue_full_events = Arc::new(AtomicU64::new(0));
        let worker_closing_events = Arc::new(AtomicU64::new(0));
        let worker_disconnect_events = Arc::new(AtomicU64::new(0));
        let payload_rejections = Arc::new(AtomicU64::new(0));
        let state = Arc::new(AuditState::default());
        let (sender, receiver) = crossbeam_channel::bounded(options.queue_capacity);
        let worker_state = state.clone();
        let worker_timeout = options.flush_timeout;
        let worker = std::thread::Builder::new()
            .name("qf-audit-writer".to_string())
            .spawn(move || {
                run_audit_writer(
                    receiver,
                    AuditWriter {
                        file: Some(BufWriter::new(file)),
                        path,
                        active_bytes,
                        active_start_seq,
                        max_segment_bytes: options.max_segment_bytes,
                        max_segments: options.max_segments,
                        rotated_segments,
                        next_seq,
                        last_hash,
                        state: worker_state,
                    },
                    worker_timeout,
                );
            })
            .map_err(AuditError::WorkerSpawnError)?;

        Ok(Self {
            sender,
            dropped_events,
            queue_full_events,
            worker_closing_events,
            worker_disconnect_events,
            payload_rejections,
            state,
            admission_state: AtomicUsize::new(AUDIT_ADMISSION_OPEN),
            worker: Mutex::new(Some(worker)),
            flush_timeout: options.flush_timeout,
        })
    }

    /// Enqueue an audit event without performing producer-side hashing or file I/O.
    pub fn log(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<&str>,
        client_id: Option<&str>,
        message: &str,
    ) -> Result<(), AuditError> {
        self.log_typed(
            event_type,
            severity,
            source_ip,
            client_id,
            default_context(event_type, message),
            message,
        )
    }

    /// Reserve one producer admission while the lifecycle is still open.
    ///
    /// The successful CAS increments the in-flight admission count. Shutdown
    /// changes the low state bits to `CLOSING` with a CAS and waits for this
    /// count to reach zero before sending its final flush barrier. This keeps
    /// the producer path non-blocking while giving close a single
    /// linearization point.
    pub(super) fn begin_event_admission(&self) -> Result<AuditAdmissionGuard<'_>, AuditError> {
        let mut state = self.admission_state.load(Ordering::Acquire);
        loop {
            match state & AUDIT_ADMISSION_STATE_MASK {
                AUDIT_ADMISSION_OPEN => {
                    if state > usize::MAX - AUDIT_ADMISSION_COUNT_UNIT {
                        return Err(AuditError::WorkerClosing);
                    }
                    let next = state + AUDIT_ADMISSION_COUNT_UNIT;
                    match self.admission_state.compare_exchange_weak(
                        state,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Ok(AuditAdmissionGuard { state: &self.admission_state }),
                        Err(observed) => state = observed,
                    }
                }
                AUDIT_ADMISSION_CLOSING => return Err(AuditError::WorkerClosing),
                AUDIT_ADMISSION_CLOSED => return Err(AuditError::WorkerDisconnected),
                _ => unreachable!("invalid audit admission state"),
            }
        }
    }

    /// Close producer admission and wait for already-admitted producers.
    fn close_event_admission_and_wait(&self) {
        let mut state = self.admission_state.load(Ordering::Acquire);
        loop {
            match state & AUDIT_ADMISSION_STATE_MASK {
                AUDIT_ADMISSION_OPEN => {
                    match self.admission_state.compare_exchange_weak(
                        state,
                        state | AUDIT_ADMISSION_CLOSING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(observed) => state = observed,
                    }
                }
                AUDIT_ADMISSION_CLOSING | AUDIT_ADMISSION_CLOSED => break,
                _ => unreachable!("invalid audit admission state"),
            }
        }
        while self.admission_state.load(Ordering::Acquire) >> AUDIT_ADMISSION_COUNT_SHIFT != 0 {
            std::thread::yield_now();
        }
    }

    /// Publish the terminal state after the worker has stopped.
    fn mark_event_admission_closed(&self) {
        debug_assert_eq!(
            self.admission_state.load(Ordering::Acquire) >> AUDIT_ADMISSION_COUNT_SHIFT,
            0
        );
        self.admission_state.store(AUDIT_ADMISSION_CLOSED, Ordering::Release);
    }

    /// Enqueue one fully typed audit event.
    pub fn log_typed(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<&str>,
        client_id: Option<&str>,
        context: AuditContext<'_>,
        message: &str,
    ) -> Result<(), AuditError> {
        if let Some(failure) = self.state.terminal_error() {
            self.state.terminal_dropped_events.fetch_add(1, Ordering::Relaxed);
            return Err(failure.to_error());
        }
        if let Err(error) = validate_audit_payload(source_ip, client_id, context, message) {
            self.payload_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        let _admission = match self.begin_event_admission() {
            Ok(admission) => admission,
            Err(error) => {
                self.record_dropped_event(&error);
                return Err(error);
            }
        };
        if let Some(failure) = self.state.terminal_error() {
            self.state.terminal_dropped_events.fetch_add(1, Ordering::Relaxed);
            return Err(failure.to_error());
        }
        let event = PendingAuditEvent {
            event_type,
            severity,
            source_ip: source_ip.map(String::from),
            client_id: client_id.map(String::from),
            message: message.to_string(),
            actor: context.actor,
            target: context.target,
            outcome: context.outcome,
            reason: context.reason.map(String::from),
        };
        match self.sender.try_send(AuditCommand::Event(event)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.record_dropped_event(&AuditError::QueueFull);
                Err(AuditError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.record_dropped_event(&AuditError::WorkerDisconnected);
                Err(AuditError::WorkerDisconnected)
            }
        }
    }

    /// Count one pre-persistence rejection under its cause and in the aggregate.
    ///
    /// A full queue means the writer is behind, a closing worker means shutdown is in
    /// progress, and a disconnected worker means audit is gone until the process is
    /// restarted. One shared counter cannot tell an operator which of those happened,
    /// so each is counted separately and the aggregate is kept as the total.
    fn record_dropped_event(&self, error: &AuditError) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
        let counter = match error {
            AuditError::QueueFull => &self.queue_full_events,
            AuditError::WorkerClosing => &self.worker_closing_events,
            AuditError::WorkerDisconnected => &self.worker_disconnect_events,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Flush all events accepted before this bounded barrier.
    pub fn flush(&self) -> Result<(), AuditError> {
        self.flush_internal().map_err(|failure| failure.to_error())
    }

    fn flush_internal(&self) -> Result<(), AuditFailure> {
        if let Some(failure) = self.state.terminal_error() {
            return Err(failure);
        }
        let (ack_tx, ack_rx) = crossbeam_channel::bounded(1);
        self.sender
            .send_timeout(AuditCommand::Flush(ack_tx), self.flush_timeout)
            .map_err(|error| AuditFailure::FlushTimeout(error.to_string()))?;
        ack_rx
            .recv_timeout(self.flush_timeout)
            .map_err(|error| AuditFailure::FlushTimeout(error.to_string()))?
    }

    /// Return bounded-queue and persistence-failure counters.
    pub fn stats(&self) -> AuditStats {
        AuditStats {
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            queue_full_events: self.queue_full_events.load(Ordering::Relaxed),
            worker_closing_events: self.worker_closing_events.load(Ordering::Relaxed),
            worker_disconnect_events: self.worker_disconnect_events.load(Ordering::Relaxed),
            payload_rejections: self.payload_rejections.load(Ordering::Relaxed),
            persistence_errors: self.state.persistence_errors.load(Ordering::Relaxed),
            terminal_dropped_events: self.state.terminal_dropped_events.load(Ordering::Relaxed),
            slow_flushes: self.state.slow_flushes.load(Ordering::Relaxed),
            shutdown_failures: self.state.shutdown_failures.load(Ordering::Relaxed),
        }
    }

    fn wait_for_worker(
        worker: &mut Option<JoinHandle<()>>,
        timeout: Duration,
    ) -> Result<(), AuditFailure> {
        let Some(handle) = worker.as_ref() else {
            return Ok(());
        };
        let deadline = Instant::now() + timeout;
        while !handle.is_finished() {
            if Instant::now() >= deadline {
                return Err(AuditFailure::ShutdownTimeout(format!(
                    "audit writer did not stop within {} ms",
                    timeout.as_millis()
                )));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let Some(handle) = worker.take() else {
            return Ok(());
        };
        if handle.join().is_err() {
            Err(AuditFailure::WorkerDisconnected)
        } else {
            Ok(())
        }
    }

    /// Flush accepted events and stop the owned writer thread.
    pub fn shutdown(&self) -> Result<(), AuditError> {
        let mut worker = self.worker.lock().unwrap_or_else(|error| error.into_inner());
        if worker.is_none() {
            self.close_event_admission_and_wait();
            self.mark_event_admission_closed();
            return self.state.sticky_failure().map_or(Ok(()), |failure| Err(failure.to_error()));
        }
        self.close_event_admission_and_wait();
        let flush_result = self.state.terminal_error().map_or_else(|| self.flush_internal(), Err);
        let shutdown_result = self
            .sender
            .send_timeout(AuditCommand::Shutdown, self.flush_timeout)
            .map_err(|error| AuditFailure::ShutdownTimeout(error.to_string()));
        let join_result = Self::wait_for_worker(&mut worker, self.flush_timeout);
        self.mark_event_admission_closed();
        let failure = match flush_result {
            Err(error) => Some(error),
            Ok(()) => match shutdown_result {
                Err(error) => Some(error),
                Ok(()) => join_result.err(),
            },
        };
        match failure {
            Some(failure) => Err(self.state.record_shutdown_failure(failure).to_error()),
            None => Ok(()),
        }
    }

    /// Verify the integrity of the hash chain. Returns Ok(()) if the chain
    /// is intact, or Err with the first broken entry's sequence number.
    pub fn verify_chain(path: &Path) -> Result<(), AuditError> {
        match read_checkpoint(path)? {
            Some(checkpoint) => verify_checkpointed_chain(path, &checkpoint),
            None => verify_legacy_chain(path),
        }
    }
}
