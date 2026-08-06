export interface PersistenceQueue {
  queue(): void;
  stop(): void;
}

export function createPersistenceQueue(persist: () => Promise<void>): PersistenceQueue {
  let active = true;
  let inFlight = false;
  let queued = false;

  function queue(): void {
    if (!active) return;
    if (inFlight) {
      queued = true;
      return;
    }
    inFlight = true;
    void persist().catch(() => undefined).finally(() => {
      inFlight = false;
      if (!active || !queued) {
        queued = false;
        return;
      }
      queued = false;
      queue();
    });
  }

  function stop(): void {
    active = false;
    queued = false;
  }

  return { queue, stop };
}
