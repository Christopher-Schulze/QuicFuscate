use super::*;
use std::sync::Mutex;

enum WorkerRequest {
    Connected {
        fd: RawFd,
        payloads: Vec<Vec<u8>>,
        reply: tokio::sync::oneshot::Sender<Result<BatchSendResult, BatchSendError>>,
    },
    To {
        fd: RawFd,
        packets: Vec<(SocketAddr, Vec<u8>)>,
        reply: tokio::sync::oneshot::Sender<Result<BatchSendResult, BatchSendError>>,
    },
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
                        WorkerRequest::Connected { fd, payloads, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(Err(BatchSendError::not_submitted(
                                    worker_shutdown_error(),
                                    payloads.len(),
                                )));
                                continue;
                            }
                            let payload_refs: Vec<&[u8]> =
                                payloads.iter().map(Vec::as_slice).collect();
                            let control = SendControl {
                                shutdown: &shutdown_for_worker,
                                deadline: Instant::now() + BLOCKING_WORKER_OPERATION_TIMEOUT,
                            };
                            let result = sender.send_batch_with_wait(
                                fd,
                                &payload_refs,
                                Some(&control),
                                IovecFailureInjection::none(),
                            );
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(result);
                        }
                        WorkerRequest::To { fd, packets, reply } => {
                            if shutdown_for_worker.load(Ordering::Acquire) {
                                let _ = reply.send(Err(BatchSendError::not_submitted(
                                    worker_shutdown_error(),
                                    packets.len(),
                                )));
                                continue;
                            }
                            let packet_refs: Vec<(SocketAddr, &[u8])> = packets
                                .iter()
                                .map(|(addr, payload)| (*addr, payload.as_slice()))
                                .collect();
                            let control = SendControl {
                                shutdown: &shutdown_for_worker,
                                deadline: Instant::now() + BLOCKING_WORKER_OPERATION_TIMEOUT,
                            };
                            let result = sender.send_batch_to_with_wait(
                                fd,
                                &packet_refs,
                                Some(&control),
                                IovecFailureInjection::none(),
                            );
                            if worker_operation_failed(&result) {
                                failed_for_worker.store(true, Ordering::Release);
                            }
                            let _ = reply.send(result);
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

    async fn submit_request(
        &self,
        request: WorkerRequest,
        reply: tokio::sync::oneshot::Receiver<Result<BatchSendResult, BatchSendError>>,
        input_len: usize,
    ) -> Result<BatchSendResult, BatchSendError> {
        if !self.is_available() {
            return Err(BatchSendError::not_submitted(worker_shutdown_error(), input_len));
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
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                return Err(BatchSendError::not_submitted(
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "io_uring blocking worker queue is full",
                    ),
                    input_len,
                ));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(BatchSendError::not_submitted(worker_shutdown_error(), input_len));
            }
        }
        match tokio::time::timeout(BLOCKING_WORKER_RESPONSE_TIMEOUT, reply).await {
            Ok(Ok(result)) => result,
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
        let owned_payloads = payloads.iter().map(|payload| payload.to_vec()).collect();
        self.submit_request(
            WorkerRequest::Connected { fd, payloads: owned_payloads, reply: reply_tx },
            reply_rx,
            input_len,
        )
        .await
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
        let owned_packets =
            packets.iter().map(|(addr, payload)| (*addr, payload.to_vec())).collect();
        self.submit_request(
            WorkerRequest::To { fd, packets: owned_packets, reply: reply_tx },
            reply_rx,
            input_len,
        )
        .await
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
