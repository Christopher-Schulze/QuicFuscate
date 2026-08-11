import { getCurrentWindow } from "@tauri-apps/api/window";
import type { Event, EventCallback, EventName } from "@tauri-apps/api/event";
import { toErrorMessage } from "$lib/format";
import type { PersistenceFlushResult } from "$lib/persistence-queue";

export const PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS = 5_000;
export const PERSISTENCE_CLOSE_REQUESTED_EVENT = "qf://persistence-close-requested";

interface PersistenceWindow {
  listen(event: EventName, handler: EventCallback<void>): Promise<() => void>;
  hide(): Promise<void>;
}

export async function registerPersistenceCloseGuard(
  flush: (timeoutMilliseconds: number) => Promise<PersistenceFlushResult>,
  onWindowError: (message: string) => void,
  targetWindow: PersistenceWindow = getCurrentWindow(),
): Promise<() => void> {
  let closeInProgress = false;
  return await targetWindow.listen(PERSISTENCE_CLOSE_REQUESTED_EVENT, async (_event: Event<void>) => {
    if (closeInProgress) return;
    closeInProgress = true;
    let result: PersistenceFlushResult;
    try {
      result = await flush(PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS);
    } catch (cause) {
      onWindowError(`Desktop close was blocked: ${toErrorMessage(cause)}`);
      closeInProgress = false;
      return;
    }
    if (result.status !== "saved") {
      closeInProgress = false;
      return;
    }
    try {
      await targetWindow.hide();
    } catch (cause) {
      onWindowError(`Desktop window could not hide after persistence succeeded: ${toErrorMessage(cause)}`);
    } finally {
      closeInProgress = false;
    }
  });
}
