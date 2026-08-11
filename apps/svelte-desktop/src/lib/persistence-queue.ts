import { toErrorMessage } from "$lib/format";

export interface PersistenceQueueState {
  dirty: boolean;
  saving: boolean;
  error: string | null;
}

export type PersistenceFlushResult =
  | { status: "saved" }
  | { status: "failed" | "timed-out" | "stopped"; message: string };

interface PersistenceQueueOptions {
  onChange?: (state: PersistenceQueueState) => void;
}

export interface PersistenceQueue {
  queue(): void;
  flush(timeoutMilliseconds: number): Promise<PersistenceFlushResult>;
  stop(): void;
}

export function createPersistenceQueue(
  persist: () => Promise<void>,
  options: PersistenceQueueOptions = {},
): PersistenceQueue {
  let active = true;
  let requestedRevision = 0;
  let persistedRevision = 0;
  let saving = false;
  let error: string | null = null;
  let drainPromise: Promise<void> | null = null;

  function emit(): void {
    options.onChange?.({
      dirty: persistedRevision < requestedRevision,
      saving,
      error,
    });
  }

  async function drain(): Promise<void> {
    try {
      while (active && persistedRevision < requestedRevision) {
        const attemptRevision = requestedRevision;
        saving = true;
        emit();
        try {
          await persist();
          persistedRevision = attemptRevision;
          error = null;
        } catch (cause) {
          error = toErrorMessage(cause, "Native persistence failed");
          if (requestedRevision === attemptRevision) break;
        }
        emit();
      }
    } finally {
      saving = false;
      drainPromise = null;
      emit();
    }
  }

  function enqueue(): number {
    if (!active) return requestedRevision;
    requestedRevision += 1;
    emit();
    if (!drainPromise) drainPromise = drain();
    return requestedRevision;
  }

  async function waitForRevision(targetRevision: number): Promise<PersistenceFlushResult> {
    while (active && persistedRevision < targetRevision && drainPromise) {
      await drainPromise;
    }
    if (persistedRevision >= targetRevision) return { status: "saved" };
    if (!active) {
      return { status: "stopped", message: "Persistence stopped before the native save completed." };
    }
    return { status: "failed", message: error ?? "Native persistence failed." };
  }

  async function flush(timeoutMilliseconds: number): Promise<PersistenceFlushResult> {
    if (!active) {
      return { status: "stopped", message: "Persistence is no longer active." };
    }
    const targetRevision = enqueue();
    const boundedTimeout = Math.max(1, timeoutMilliseconds);
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    const timeoutResult = new Promise<PersistenceFlushResult>((resolve) => {
      timeoutHandle = setTimeout(() => {
        resolve({
          status: "timed-out",
          message: `Native persistence did not complete within ${boundedTimeout} ms.`,
        });
      }, boundedTimeout);
    });
    const result = await Promise.race([waitForRevision(targetRevision), timeoutResult]);
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
    if (result.status === "timed-out") {
      error = result.message;
      emit();
    }
    return result;
  }

  function queue(): void {
    enqueue();
  }

  function stop(): void {
    active = false;
    emit();
  }

  return { queue, flush, stop };
}
