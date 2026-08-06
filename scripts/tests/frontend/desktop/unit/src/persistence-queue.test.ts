import { describe, expect, test, vi } from "vitest";
import { createPersistenceQueue } from "../../../../../../apps/svelte-desktop/src/lib/persistence-queue";

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
});
