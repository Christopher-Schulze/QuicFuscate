import type { Event, EventCallback, EventName } from "@tauri-apps/api/event";
import { describe, expect, test, vi } from "vitest";
import {
  PERSISTENCE_CLOSE_REQUESTED_EVENT,
  PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS,
  registerPersistenceCloseGuard,
} from "../../../../../../apps/svelte-desktop/src/lib/persistence-lifecycle";

type CloseHandler = EventCallback<void>;

function closeEvent(): Event<void> {
  return {
    event: "tauri://close-requested",
    id: 1,
    payload: undefined,
  };
}

describe("desktop persistence lifecycle", () => {
  test("prevents close until the bounded native flush succeeds", async () => {
    const handlers: CloseHandler[] = [];
    const hide = vi.fn().mockResolvedValue(undefined);
    const unlisten = vi.fn();
    const flush = vi.fn().mockResolvedValue({ status: "saved" });
    const windowError = vi.fn();
    const targetWindow = {
      listen: async (event: EventName, handler: CloseHandler) => {
        expect(event).toBe(PERSISTENCE_CLOSE_REQUESTED_EVENT);
        handlers.push(handler);
        return unlisten;
      },
      hide,
    };

    const stop = await registerPersistenceCloseGuard(flush, windowError, targetWindow);
    const event = closeEvent();
    await handlers[0]?.(event);

    expect(flush).toHaveBeenCalledWith(PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS);
    expect(hide).toHaveBeenCalledOnce();
    expect(windowError).not.toHaveBeenCalled();

    stop();
    expect(unlisten).toHaveBeenCalledOnce();
  });

  test("keeps the window open when persistence fails", async () => {
    const handlers: CloseHandler[] = [];
    const hide = vi.fn().mockResolvedValue(undefined);
    const targetWindow = {
      listen: async (_event: EventName, handler: CloseHandler) => {
        handlers.push(handler);
        return vi.fn();
      },
      hide,
    };
    const flush = vi.fn().mockResolvedValue({
      status: "failed",
      message: "keychain unavailable",
    });

    await registerPersistenceCloseGuard(flush, vi.fn(), targetWindow);
    const event = closeEvent();
    await handlers[0]?.(event);

    expect(hide).not.toHaveBeenCalled();
  });

  test("reports a native window failure after persistence succeeds", async () => {
    const handlers: CloseHandler[] = [];
    const targetWindow = {
      listen: async (_event: EventName, handler: CloseHandler) => {
        handlers.push(handler);
        return vi.fn();
      },
      hide: vi.fn().mockRejectedValue(new Error("window refused hide")),
    };
    const windowError = vi.fn();

    await registerPersistenceCloseGuard(
      async () => ({ status: "saved" }),
      windowError,
      targetWindow,
    );
    await handlers[0]?.(closeEvent());

    expect(windowError).toHaveBeenCalledWith(
      "Desktop window could not hide after persistence succeeded: window refused hide",
    );
  });
});
