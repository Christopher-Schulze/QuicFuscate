export interface RequestToken {
  readonly generation: number;
}

export interface RequestOptions {
  invalidate?: boolean;
}

export type RequestOperation = (token: RequestToken) => Promise<void>;

export interface RequestCoordinator {
  request(operation: RequestOperation, options?: RequestOptions): Promise<void>;
  invalidate(): void;
  isCurrent(token: RequestToken): boolean;
  dispose(): void;
}

export function createRequestCoordinator(): RequestCoordinator {
  let generation = 0;
  let running = false;
  let disposed = false;
  let queuedOperation: RequestOperation | null = null;
  let queuedPromise: Promise<void> | null = null;
  let resolveQueued: (() => void) | null = null;

  async function execute(operation: RequestOperation, token: RequestToken): Promise<void> {
    try {
      await operation(token);
    } finally {
      const nextOperation = queuedOperation;
      const nextResolve = resolveQueued;
      queuedOperation = null;
      queuedPromise = null;
      resolveQueued = null;
      if (!disposed && nextOperation) {
        const nextPromise = execute(nextOperation, { generation });
        void nextPromise.then(() => nextResolve?.(), () => nextResolve?.());
        return;
      }
      running = false;
      nextResolve?.();
    }
  }

  function request(operation: RequestOperation, options: RequestOptions = {}): Promise<void> {
    if (disposed) return Promise.resolve();
    if (options.invalidate) generation += 1;
    if (running) {
      queuedOperation = operation;
      queuedPromise ??= new Promise<void>((resolve) => { resolveQueued = resolve; });
      return queuedPromise;
    }
    running = true;
    return execute(operation, { generation });
  }

  function invalidate(): void {
    if (!disposed) generation += 1;
  }

  function isCurrent(token: RequestToken): boolean {
    return !disposed && token.generation === generation;
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    generation += 1;
    queuedOperation = null;
    resolveQueued?.();
    queuedPromise = null;
    resolveQueued = null;
  }

  return { request, invalidate, isCurrent, dispose };
}
