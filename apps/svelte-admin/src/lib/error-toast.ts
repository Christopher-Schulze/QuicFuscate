import { addToast, createOwnedTimeout } from "@quicfuscate/ui";
import { sanitizeErrorMessage } from "$lib/api";

export interface ErrorToastHandler {
  show(e: unknown, fallback: string): void;
  destroy(): void;
}

/**
 * Creates a deduplicating error-toast handler with a 10s reset window.
 * Identical consecutive error messages are suppressed; after the reset
 * window the same message may surface again if the error reoccurs.
 *
 * @param isActive - Called before each toast; returns false to suppress
 *                   (e.g. when the owning component is destroyed).
 */
export function createErrorToastHandler(isActive: () => boolean): ErrorToastHandler {
  let lastMsg = "";
  const resetTimer = createOwnedTimeout();

  return {
    show(e: unknown, fallback: string): void {
      if (!isActive()) return;
      const msg = sanitizeErrorMessage(
        e instanceof Error ? e.message : String(e),
        fallback,
      );
      if (msg === lastMsg) return;
      lastMsg = msg;
      addToast(msg, "error");
      resetTimer.schedule(() => { if (lastMsg === msg) lastMsg = ""; }, 10000);
    },
    destroy(): void {
      resetTimer.destroy();
    },
  };
}
