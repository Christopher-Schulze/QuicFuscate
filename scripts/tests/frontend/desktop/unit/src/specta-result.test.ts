import { describe, expect, test } from "vitest";
import { unwrapSpectaCommand } from "../../../../../../apps/svelte-desktop/src/lib/specta-result";

describe("unwrapSpectaCommand", () => {
  test("returns data from the ok variant", async () => {
    await expect(unwrapSpectaCommand(Promise.resolve({ status: "ok", data: 7 }))).resolves.toBe(7);
  });

  test("throws the native error string", async () => {
    await expect(
      unwrapSpectaCommand(Promise.resolve({ status: "error", error: "keychain storage is unavailable" })),
    ).rejects.toThrow("keychain storage is unavailable");
  });

  test("throws a fallback when the error payload is empty", async () => {
    await expect(
      unwrapSpectaCommand(Promise.resolve({ status: "error", error: "   " })),
    ).rejects.toThrow("Native command failed");
  });
});
