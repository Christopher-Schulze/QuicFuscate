import { afterEach, describe, expect, test } from "vitest";
import {
  cancelConfirmDialog,
  confirmDialog,
  getConfirmDialogRequest,
  resolveConfirmDialog,
} from "../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

const FIRST_REQUEST = {
  title: "First confirmation",
  message: "First message",
  confirmLabel: "First",
  cancelLabel: "Cancel",
};

const SECOND_REQUEST = {
  title: "Second confirmation",
  message: "Second message",
  confirmLabel: "Second",
  cancelLabel: "Cancel",
};

afterEach(() => {
  const request = getConfirmDialogRequest();
  if (request) cancelConfirmDialog(request.id);
});

describe("admin confirmation dialog store", () => {
  test("cancels the superseded caller and renders the latest request identity", async () => {
    const firstPromise = confirmDialog(FIRST_REQUEST);
    const firstId = getConfirmDialogRequest()?.id;
    if (firstId === undefined) throw new Error("first confirmation was not published");

    const secondPromise = confirmDialog(SECOND_REQUEST);
    const secondRequest = getConfirmDialogRequest();
    if (!secondRequest) throw new Error("second confirmation was not published");

    expect(secondRequest.id).toBeGreaterThan(firstId);
    expect(secondRequest.title).toBe(SECOND_REQUEST.title);
    await expect(firstPromise).resolves.toBe(false);

    resolveConfirmDialog(firstId, true);
    expect(getConfirmDialogRequest()?.id).toBe(secondRequest.id);

    resolveConfirmDialog(secondRequest.id, true);
    await expect(secondPromise).resolves.toBe(true);
    expect(getConfirmDialogRequest()).toBeNull();
  });

  test("ignores stale resolution and resolves the active request once", async () => {
    const promise = confirmDialog(FIRST_REQUEST);
    const request = getConfirmDialogRequest();
    if (!request) throw new Error("confirmation was not published");
    let settlementCount = 0;
    void promise.then(() => { settlementCount += 1; });

    resolveConfirmDialog(request.id + 1, true);
    expect(getConfirmDialogRequest()?.id).toBe(request.id);

    resolveConfirmDialog(request.id, false);
    await expect(promise).resolves.toBe(false);
    resolveConfirmDialog(request.id, true);
    await Promise.resolve();
    expect(settlementCount).toBe(1);
    expect(getConfirmDialogRequest()).toBeNull();
  });

  test("cancels an active request during owner teardown", async () => {
    const promise = confirmDialog(FIRST_REQUEST);
    const request = getConfirmDialogRequest();
    if (!request) throw new Error("confirmation was not published");

    cancelConfirmDialog(request.id);

    await expect(promise).resolves.toBe(false);
    expect(getConfirmDialogRequest()).toBeNull();
    cancelConfirmDialog(request.id);
  });
});
