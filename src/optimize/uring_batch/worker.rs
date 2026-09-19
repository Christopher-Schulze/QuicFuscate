use super::*;
use std::sync::Mutex;

enum WorkerRequest {
    Connected {
        fd: RawFd,
        /// All payloads concatenated once; `spans` holds `(start, len)` per
        /// input so submission crosses the channel with a single allocation
        /// instead of one `Vec` per packet.
        flat: Vec<u8>,
        spans: Vec<(usize, usize)>,
        reply: tokio::sync::oneshot::Sender<Result<BatchSendResult, BatchSendError>>,
    },
    To {
        fd: RawFd,
        flat: Vec<u8>,
        /// `(addr, start, len)` per packet into `flat`.
        spans: Vec<(SocketAddr, usize, usize)>,
        reply: tokio::sync::oneshot::Sender<Result<BatchSendResult, BatchSendError>>,
    },
    /// Caller already staged the burst into owned buffers: the sender adopts
    /// them in place (zero payload copies) and hands them back emptied in the
    /// reply so the caller can reuse capacity and resend the unsent tail.
    ToFlat {
        fd: RawFd,
        flat: Vec<u8>,
        /// `(addr, start, len)` per packet into `flat`.
        spans: Vec<(SocketAddr, usize, usize)>,
        reply: tokio::sync::oneshot::Sender<FlatToReply>,
    },
    /// Connected-socket twin of `ToFlat`: owned `(start, len)` spans into an
    /// owned flat buffer (which may be a larger reusable slab; only the span
    /// extent is sent), adopted in place and returned intact in the reply.
    ConnectedFlat {
        fd: RawFd,
        flat: Vec<u8>,
        spans: Vec<(usize, usize)>,
        reply: tokio::sync::oneshot::Sender<FlatReply>,
    },
}

/// Reply to a `ToFlat` submission: the batch outcome plus the submission
/// buffers handed back intact - the caller still needs their contents to
/// resend the unsent tail through the per-packet fallback. Buffers are empty
/// only when the request could not return them (worker shutdown before
/// adoption, channel loss, response timeout).
pub struct FlatToReply {
    /// Per-slot send dispositions, or the submission-level error.
    pub result: Result<BatchSendResult, BatchSendError>,
    /// The staged payload buffer with its contents preserved.
    pub flat: Vec<u8>,
    /// The `(addr, start, len)` span table with its contents preserved.
    pub spans: Vec<(SocketAddr, usize, usize)>,
}

/// Reply to a `ConnectedFlat` submission: same contract as `FlatToReply`,
/// with `(start, len)` spans because a connected socket needs no per-packet
/// destination table.
pub struct FlatReply {
    /// Per-slot send dispositions, or the submission-level error.
    pub result: Result<BatchSendResult, BatchSendError>,
    /// The staged payload buffer with its contents preserved.
    pub flat: Vec<u8>,
    /// The `(start, len)` span table with its contents preserved.
    pub spans: Vec<(usize, usize)>,
}

/// Runtime-owned blocking executor for synchronous io_uring sends.
///
/// Exactly one OS thread owns the sender and at most one request waits in its
/// bounded Tokio channel. The worker disables SendMsgZc because a delayed
/// notification must never outlive the operation deadline or the runtime
/// shutdown owner. A controlled sender operation polls CQEs with a deadline,
/// quarantines the ring on cancellation/timeout, and retains pointer-bearing
/// storage until the worker terminates.
pub struct UringBatchWorker {
    request_tx: Mutex<Option<tokio::sync::mpsc::Sender<WorkerRequest>>>,
    shutdown: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl UringBatchWorker {
    /// Start one bounded worker with the default sender depth.
    pub fn with_defaults() -> Option<Self> {
        Self::new(DEFAULT_QUEUE_DEPTH)
    }

    /// Start one bounded worker with a sender queue depth.
    pub fn new(queue_depth: u32) -> Option<Self> {
        let sender = UringBatchSender::new_inner(queue_depth, false)?;
        // Depth 1 is deliberate, not a missing knob: exactly one sender owns
        // the ring and its pointer-backed staging, so requests serialize anyway.
        // A deeper queue would only let a waiting batch exceed the caller's
        // response deadline (500 ms) behind a 250 ms operation - spurious
        // quarantines for zero throughput gain. Bounded depth 1 gives natural
        // backpressure: extra submitters take the per-packet fallback instead.
        let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let shutdown_for_worker = Arc::clone(&shutdown);
        let failed_for_worker = Arc::clone(&failed);
        let join = std::thread::Builder::new()
            .name("qf-io-uring-send".to_string())
            .spawn(move || {
                let mut sender = sender;
                while let Some(request) = request_rx.blocking_recv() {
                    match request {
                        WorkerRequest::Connected { fd, flat, spans, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(Err(BatchSendError::not_submitted(
                                    worker_shutdown_error(),
                                    spans.len(),
                                )));
                                continue;
                            }
                            let control = SendControl {
                                shutdown: &shutdown_for_worker,
                                deadline: Instant::now() + BLOCKING_WORKER_OPERATION_TIMEOUT,
                            };
                            let result = sender.send_batch_flat_with_wait(
                                fd,
                                flat,
                                spans,
                                Some(&control),
                                IovecFailureInjection::none(),
                            );
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(result);
                        }
                        WorkerRequest::To { fd, flat, spans, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(Err(BatchSendError::not_submitted(
                                    worker_shutdown_error(),
                                    spans.len(),
                                )));
                                continue;
                            }
                            let control = SendControl {
                                shutdown: &shutdown_for_worker,
                                deadline: Instant::now() + BLOCKING_WORKER_OPERATION_TIMEOUT,
                            };
                            let result = sender.send_batch_to_flat_with_wait(
                                fd,
                                flat,
                                spans,
                                Some(&control),
                                IovecFailureInjection::none(),
                            );
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(result);
                        }
                        WorkerRequest::ToFlat { fd, flat, spans, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(FlatToReply {
                                    result: Err(BatchSendError::not_submitted(
                                        worker_shutdown_error(),
                                        spans.len(),
                                    )),
                                    flat,
                                    spans,
                                });
                                continue;
                            }
                            let input_len = spans.len();
                            // Rejections before adoption keep the request
                            // buffers returnable; once the callee adopts them,
                            // they live in the sender's retained slots.
                            let (result, flat, spans) = if let Err(error) =
                                sender.ensure_usable()
                            {
                                (Err(BatchSendError::quarantined(error, input_len)), flat, spans)
                            } else if input_len == 0 {
                                (Ok(BatchSendResult::not_submitted(0)), flat, spans)
                            } else if sender.zc_supported {
                                (Err(BatchSendError::not_submitted(
                                    std::io::Error::new(
                                        std::io::ErrorKind::Unsupported,
                                        "controlled io_uring sends do not permit SendMsgZc notification ownership",
                                    ),
                                    input_len,
                                )), flat, spans)
                            } else if let Err(error) =
                                UringBatchSender::flat_spans_extent(
                                    spans.iter().map(|&(_, start, len)| (start, len)),
                                    flat.len(),
                                )
                                .and_then(|extent| {
                                    UringBatchSender::validate_batch_admission(input_len, extent)
                                })
                            {
                                (Err(BatchSendError::not_submitted(error, input_len)), flat, spans)
                            } else {
                                let control = SendControl {
                                    shutdown: &shutdown_for_worker,
                                    deadline: Instant::now()
                                        + BLOCKING_WORKER_OPERATION_TIMEOUT,
                                };
                                let result = sender.send_batch_to_flat_with_wait(
                                    fd,
                                    flat,
                                    spans,
                                    Some(&control),
                                    IovecFailureInjection::none(),
                                );
                                let (flat, spans) = match &result {
                                    // All CQEs were consumed on Ok: no in-flight
                                    // SQE still references the adopted buffers,
                                    // so they come back intact for fallback
                                    // resend and capacity reuse.
                                    Ok(_) => {
                                        let (flat, payload_spans, addrs) =
                                            sender.take_flat_payloads();
                                        let spans = payload_spans
                                            .into_iter()
                                            .zip(addrs)
                                            .map(|((start, len), addr)| (addr, start, len))
                                            .collect();
                                        (flat, spans)
                                    }
                                    // The adopted buffers stay inside the
                                    // possibly poisoned sender while accepted
                                    // SQEs may still reference them; clone the
                                    // retained slots out so the caller can
                                    // resend the full batch via the async
                                    // fallback, exactly as the borrowed-packet
                                    // path did.
                                    Err(_) => (
                                        sender.payload_flat.clone(),
                                        sender
                                            .payload_spans
                                            .iter()
                                            .copied()
                                            .zip(sender.packet_addrs.iter().copied())
                                            .map(|((start, len), addr)| (addr, start, len))
                                            .collect(),
                                    ),
                                };
                                (result, flat, spans)
                            };
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(FlatToReply { result, flat, spans });
                        }
                        WorkerRequest::ConnectedFlat { fd, flat, spans, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(FlatReply {
                                    result: Err(BatchSendError::not_submitted(
                                        worker_shutdown_error(),
                                        spans.len(),
                                    )),
                                    flat,
                                    spans,
                                });
                                continue;
                            }
                            let input_len = spans.len();
                            // Same pre-adoption gates as the callee, evaluated
                            // here so rejected requests keep their buffers.
                            let (result, flat, spans) = if let Err(error) =
                                sender.ensure_usable()
                            {
                                (Err(BatchSendError::quarantined(error, input_len)), flat, spans)
                            } else if input_len == 0 {
                                (Ok(BatchSendResult::not_submitted(0)), flat, spans)
                            } else if sender.zc_supported {
                                (Err(BatchSendError::not_submitted(
                                    std::io::Error::new(
                                        std::io::ErrorKind::Unsupported,
                                        "controlled io_uring sends do not permit SendMsgZc notification ownership",
                                    ),
                                    input_len,
                                )), flat, spans)
                            } else if let Err(error) =
                                UringBatchSender::flat_spans_extent(
                                    spans.iter().copied(),
                                    flat.len(),
                                )
                                .and_then(|extent| {
                                    UringBatchSender::validate_batch_admission(input_len, extent)
                                })
                            {
                                (Err(BatchSendError::not_submitted(error, input_len)), flat, spans)
                            } else {
                                let control = SendControl {
                                    shutdown: &shutdown_for_worker,
                                    deadline: Instant::now()
                                        + BLOCKING_WORKER_OPERATION_TIMEOUT,
                                };
                                let result = sender.send_batch_flat_with_wait(
                                    fd,
                                    flat,
                                    spans,
                                    Some(&control),
                                    IovecFailureInjection::none(),
                                );
                                let (flat, spans) = match &result {
                                    // Connected spans are adopted verbatim, so
                                    // the retained slots already carry the
                                    // caller's `(start, len)` shape.
                                    Ok(_) => {
                                        let (flat, payload_spans, _addrs) =
                                            sender.take_flat_payloads();
                                        (flat, payload_spans)
                                    }
                                    // Retained (possibly poisoned) buffers are
                                    // cloned out so the caller can resend the
                                    // whole batch through the fallback paths.
                                    Err(_) => (
                                        sender.payload_flat.clone(),
                                        sender.payload_spans.clone(),
                                    ),
                                };
                                (result, flat, spans)
                            };
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(FlatReply { result, flat, spans });
                        }
                    }
                }
            })
            .ok()?;

        Some(Self {
            request_tx: Mutex::new(Some(request_tx)),
            shutdown,
            failed,
            join: Mutex::new(Some(join)),
        })
    }

    /// True while the worker can accept a new request.
    pub fn is_available(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire) && !self.failed.load(Ordering::Acquire)
    }

    /// Send one request to the blocking worker and await its reply.
    /// `recover` rebuilds the reply payload when the request never reached the
    /// worker (worker down, queue full, channel closed) so owned submission
    /// buffers can be handed back to the caller instead of being dropped.
    async fn submit_request<T>(
        &self,
        request: WorkerRequest,
        reply: tokio::sync::oneshot::Receiver<T>,
        input_len: usize,
        recover: impl FnOnce(BatchSendError, WorkerRequest) -> T,
    ) -> Result<T, BatchSendError> {
        if !self.is_available() {
            return Ok(recover(
                BatchSendError::not_submitted(worker_shutdown_error(), input_len),
                request,
            ));
        }
        let request_tx = self
            .request_tx
            .lock()
            .map_err(|_| {
                BatchSendError::not_submitted(
                    std::io::Error::other("io_uring worker state lock poisoned"),
                    input_len,
                )
            })?
            .as_ref()
            .cloned()
            .ok_or_else(|| BatchSendError::not_submitted(worker_shutdown_error(), input_len))?;
        match request_tx.try_send(request) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(request)) => {
                return Ok(recover(
                    BatchSendError::not_submitted(
                        std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "io_uring blocking worker queue is full",
                        ),
                        input_len,
                    ),
                    request,
                ));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(request)) => {
                return Ok(recover(
                    BatchSendError::not_submitted(worker_shutdown_error(), input_len),
                    request,
                ));
            }
        }
        match tokio::time::timeout(BLOCKING_WORKER_RESPONSE_TIMEOUT, reply).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(BatchSendError::quarantined(
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "io_uring blocking worker dropped the request response",
                ),
                input_len,
            )),
            Err(_) => Err(BatchSendError::quarantined(
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "io_uring blocking worker response deadline exceeded",
                ),
                input_len,
            )),
        }
    }

    /// Submit a connected-socket batch with exact per-input dispositions.
    pub async fn send_batch_with_disposition(
        &self,
        fd: RawFd,
        payloads: &[&[u8]],
    ) -> Result<BatchSendResult, BatchSendError> {
        let input_len = payloads.len();
        let payload_bytes = UringBatchSender::checked_payload_bytes(payloads.iter().copied())
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        UringBatchSender::validate_batch_admission(payloads.len(), payload_bytes)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let mut flat = Vec::with_capacity(payload_bytes);
        let mut spans = Vec::with_capacity(input_len);
        for payload in payloads {
            let start = flat.len();
            flat.extend_from_slice(payload);
            spans.push((start, payload.len()));
        }
        self.submit_request(
            WorkerRequest::Connected { fd, flat, spans, reply: reply_tx },
            reply_rx,
            input_len,
            |error, _request| Err(error),
        )
        .await?
    }

    /// Submit a connected-socket batch without blocking the caller's executor.
    pub async fn send_batch(&self, fd: RawFd, payloads: &[&[u8]]) -> std::io::Result<usize> {
        self.send_batch_with_disposition(fd, payloads)
            .await
            .map(|result| result.sent_count())
            .map_err(BatchSendError::into_io_error)
    }

    /// Submit an unconnected-socket batch with exact per-input dispositions.
    pub async fn send_batch_to_with_disposition(
        &self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
    ) -> Result<BatchSendResult, BatchSendError> {
        let input_len = packets.len();
        let payload_bytes =
            UringBatchSender::checked_payload_bytes(packets.iter().map(|(_, payload)| *payload))
                .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        UringBatchSender::validate_batch_admission(packets.len(), payload_bytes)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let mut flat = Vec::with_capacity(payload_bytes);
        let mut spans = Vec::with_capacity(input_len);
        for (addr, payload) in packets {
            let start = flat.len();
            flat.extend_from_slice(payload);
            spans.push((*addr, start, payload.len()));
        }
        self.submit_request(
            WorkerRequest::To { fd, flat, spans, reply: reply_tx },
            reply_rx,
            input_len,
            |error, _request| Err(error),
        )
        .await?
    }

    /// Submit an unconnected batch whose caller already staged the payloads
    /// into owned flat buffers. The worker adopts the buffers in place - no
    /// payload copies on this path - and returns them intact in the reply so
    /// the caller can resend the unsent tail through the per-packet fallback
    /// and reuse the capacity on the next staged burst.
    ///
    /// `spans` carries `(addr, start, len)` per packet. Empty spans return an
    /// all-unsent result without touching the worker. When the request never
    /// reaches the worker (unavailable, queue full, channel closed) the
    /// buffers are recovered from the request and handed back with the error.
    pub async fn send_batch_to_flat_with_disposition(
        &self,
        fd: RawFd,
        flat: Vec<u8>,
        spans: Vec<(SocketAddr, usize, usize)>,
    ) -> FlatToReply {
        let input_len = spans.len();
        if let Err(error) = UringBatchSender::validate_batch_admission(input_len, flat.len()) {
            return FlatToReply {
                result: Err(BatchSendError::not_submitted(error, input_len)),
                flat,
                spans,
            };
        }
        if input_len == 0 {
            return FlatToReply { result: Ok(BatchSendResult::not_submitted(0)), flat, spans };
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        match self
            .submit_request(
                WorkerRequest::ToFlat { fd, flat, spans, reply: reply_tx },
                reply_rx,
                input_len,
                |error, request| match request {
                    WorkerRequest::ToFlat { flat, spans, .. } => {
                        FlatToReply { result: Err(error), flat, spans }
                    }
                    _ => FlatToReply { result: Err(error), flat: Vec::new(), spans: Vec::new() },
                },
            )
            .await
        {
            Ok(reply) => reply,
            // Channel/timeout failures dropped the request buffers with the
            // worker; the caller re-provisions empty buffers.
            Err(error) => FlatToReply { result: Err(error), flat: Vec::new(), spans: Vec::new() },
        }
    }

    /// Submit a connected-socket batch whose caller staged the payloads into
    /// an owned flat buffer - typically a reusable slab whose length exceeds
    /// the used extent. The worker adopts the buffers in place (no payload
    /// copies) and returns them intact so the caller can resend the unsent
    /// tail through the sendmmsg/per-packet fallback and reuse the slab.
    ///
    /// `spans` carries `(start, len)` per packet; every span must stay inside
    /// `flat`. Empty spans return an all-unsent result without touching the
    /// worker. When the request never reaches the worker the buffers are
    /// recovered from the request and handed back with the error.
    pub async fn send_batch_flat_with_disposition(
        &self,
        fd: RawFd,
        flat: Vec<u8>,
        spans: Vec<(usize, usize)>,
    ) -> FlatReply {
        let input_len = spans.len();
        if let Err(error) = UringBatchSender::flat_spans_extent(spans.iter().copied(), flat.len())
            .and_then(|extent| UringBatchSender::validate_batch_admission(input_len, extent))
        {
            return FlatReply {
                result: Err(BatchSendError::not_submitted(error, input_len)),
                flat,
                spans,
            };
        }
        if input_len == 0 {
            return FlatReply { result: Ok(BatchSendResult::not_submitted(0)), flat, spans };
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        match self
            .submit_request(
                WorkerRequest::ConnectedFlat { fd, flat, spans, reply: reply_tx },
                reply_rx,
                input_len,
                |error, request| match request {
                    WorkerRequest::ConnectedFlat { flat, spans, .. } => {
                        FlatReply { result: Err(error), flat, spans }
                    }
                    _ => FlatReply { result: Err(error), flat: Vec::new(), spans: Vec::new() },
                },
            )
            .await
        {
            Ok(reply) => reply,
            Err(error) => FlatReply { result: Err(error), flat: Vec::new(), spans: Vec::new() },
        }
    }

    /// Submit an unconnected-socket batch without blocking the caller's executor.
    pub async fn send_batch_to(
        &self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
    ) -> std::io::Result<usize> {
        self.send_batch_to_with_disposition(fd, packets)
            .await
            .map(|result| result.sent_count())
            .map_err(BatchSendError::into_io_error)
    }

    /// Stop admission and make the owned worker observable to its join owner.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(mut request_tx) = self.request_tx.lock() {
            request_tx.take();
        }
    }

    /// Join the worker after its async callers have stopped submitting.
    pub fn join(&self) -> Result<(), String> {
        self.request_shutdown();
        let join =
            self.join.lock().map_err(|_| "io_uring worker join lock poisoned".to_string())?.take();
        if let Some(join) = join {
            join.join().map_err(|_| "io_uring worker thread panicked".to_string())?;
        }
        Ok(())
    }
}

impl Drop for UringBatchWorker {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Ok(mut join) = self.join.lock() {
            if let Some(join) = join.take() {
                let _ = join.join();
            }
        }
    }
}

fn worker_shutdown_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "io_uring blocking worker is shut down")
}

fn worker_operation_failed(result: &Result<BatchSendResult, BatchSendError>) -> bool {
    match result {
        Ok(_) => false,
        Err(error) => error.kind() != std::io::ErrorKind::WouldBlock,
    }
}
