import { describe, expect, test } from "vitest";
import { unwrapSpectaCommand, wrapSpectaInvoke } from "../../../../../../apps/svelte-desktop/src/lib/specta-result";

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

describe("wrapSpectaInvoke", () => {
  test("returns ok data", async () => {
    await expect(wrapSpectaInvoke(Promise.resolve(9))).resolves.toEqual({ status: "ok", data: 9 });
  });

  test("rethrows Error throws from Tauri", async () => {
    await expect(wrapSpectaInvoke(Promise.reject(new Error("boom")))).rejects.toThrow("boom");
  });

  test("captures a string throw as the error variant", async () => {
    await expect(wrapSpectaInvoke(Promise.reject("keychain storage is unavailable"))).resolves.toEqual({
      status: "error",
      error: "keychain storage is unavailable",
    });
  });

  test("rejects untyped non-string throws", async () => {
    await expect(wrapSpectaInvoke(Promise.reject({ code: 1 }))).rejects.toThrow(
      "Native command failed with an untyped error",
    );
  });
});
