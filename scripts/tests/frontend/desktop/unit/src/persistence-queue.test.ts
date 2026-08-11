import { describe, expect, test, vi } from "vitest";
import {
  createPersistenceQueue,
  type PersistenceQueueState,
} from "../../../../../../apps/svelte-desktop/src/lib/persistence-queue";

function deferred(): { promise: Promise<void>; resolve: () => void; reject: () => void } {
  let resolve!: () => void;
  let reject!: () => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("desktop persistence queue", () => {
  test("serializes an in-flight save and coalesces later state", async () => {
    const first = deferred();
    const second = deferred();
    const persist = vi.fn()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const queue = createPersistenceQueue(persist);

    queue.queue();
    queue.queue();
    expect(persist).toHaveBeenCalledTimes(1);

    first.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(persist).toHaveBeenCalledTimes(2);

    second.resolve();
    await Promise.resolve();
    expect(persist).toHaveBeenCalledTimes(2);
  });

  test("does not start a queued save after the owner stops", async () => {
    const first = deferred();
    const persist = vi.fn().mockReturnValue(first.promise);
    const queue = createPersistenceQueue(persist);

    queue.queue();
    queue.queue();
    queue.stop();
    first.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(persist).toHaveBeenCalledTimes(1);
  });

  test("continues coalesced persistence after a failed save", async () => {
    const first = deferred();
    const second = deferred();
    const persist = vi.fn()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const queue = createPersistenceQueue(persist);

    queue.queue();
    queue.queue();
    first.reject();
    await Promise.resolve();
    await Promise.resolve();
    expect(persist).toHaveBeenCalledTimes(2);

    second.resolve();
    await Promise.resolve();
  });

  test("retains dirty failure state until a bounded retry succeeds", async () => {
    const states: PersistenceQueueState[] = [];
    const persist = vi.fn()
      .mockRejectedValueOnce(new Error("keychain unavailable"))
      .mockResolvedValueOnce(undefined);
    const queue = createPersistenceQueue(persist, {
      onChange: (state) => states.push(state),
    });

    expect(await queue.flush(100)).toEqual({
      status: "failed",
      message: "keychain unavailable",
    });
    expect(states.at(-1)).toEqual({
      dirty: true,
      saving: false,
      error: "keychain unavailable",
    });

    expect(await queue.flush(100)).toEqual({ status: "saved" });
    expect(states.at(-1)).toEqual({ dirty: false, saving: false, error: null });
    expect(persist).toHaveBeenCalledTimes(2);
  });

  test("reports an interrupted lifecycle flush at its explicit timeout", async () => {
    vi.useFakeTimers();
    const pending = deferred();
    const states: PersistenceQueueState[] = [];
    const queue = createPersistenceQueue(() => pending.promise, {
      onChange: (state) => states.push(state),
    });

    const resultPromise = queue.flush(25);
    await vi.advanceTimersByTimeAsync(25);

    expect(await resultPromise).toEqual({
      status: "timed-out",
      message: "Native persistence did not complete within 25 ms.",
    });
    expect(states.at(-1)).toEqual({
      dirty: true,
      saving: true,
      error: "Native persistence did not complete within 25 ms.",
    });

    pending.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(states.at(-1)).toEqual({ dirty: false, saving: false, error: null });
  });
});
