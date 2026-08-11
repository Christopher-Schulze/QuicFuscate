import { afterEach, describe, expect, test, vi } from "vitest";

import {
  ApiError,
  createCsrfNonce,
  parseErrorMessageBody,
  postJson,
  sanitizeErrorMessage,
} from "../../../../../apps/svelte-admin/src/lib/api";
import { adminApiSchemas } from "../../../../../apps/svelte-admin/src/lib/admin-api-contracts";

describe("createCsrfNonce", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test("uses the platform UUID capability and adds an owner sequence", () => {
    vi.stubGlobal("crypto", {
      randomUUID: () => "native-uuid",
      getRandomValues: () => {
        throw new Error("byte fallback must not run when UUID is available");
      },
    });

    const result = createCsrfNonce();

    expect(result).toEqual(expect.objectContaining({ ok: true }));
    if (result.ok) expect(result.value).toMatch(/^qf-csrf-\d+-native-uuid$/);
  });

  test("uses secure random bytes when UUID is unavailable", () => {
    vi.stubGlobal("crypto", {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(0xab);
        return bytes;
      },
    });

    const result = createCsrfNonce();

    expect(result).toEqual(expect.objectContaining({ ok: true }));
    if (result.ok) expect(result.value).toMatch(/^qf-csrf-\d-(?:ab){32}$/);
  });

  test("keeps repeated secure bytes distinct without wall-clock or Math entropy", () => {
    vi.setSystemTime(new Date("2026-08-06T12:00:00.000Z"));
    vi.spyOn(Math, "random").mockReturnValue(0);
    vi.stubGlobal("crypto", {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(0xcd);
        return bytes;
      },
    });

    const first = createCsrfNonce();
    const second = createCsrfNonce();

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (first.ok && second.ok) expect(first.value).not.toBe(second.value);
  });

  test("fails closed when no secure browser source is available", () => {
    vi.stubGlobal("crypto", {});

    expect(createCsrfNonce()).toEqual({
      ok: false,
      reason: "secure-randomness-unavailable",
    });
  });

  test("does not dispatch a guarded POST after nonce failure", async () => {
    const fetchMock = vi.fn(async () => new Response(null, {
      status: 200,
      headers: { "X-CSRF-Token": "a".repeat(32) },
    }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", {});

    await expect(postJson("/api/test", {}, adminApiSchemas.logout)).rejects.toMatchObject({
      message: "CSRF nonce unavailable",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/csrf");
  });
});

describe("parseErrorMessageBody", () => {
  test("returns null for empty input", () => {
    expect(parseErrorMessageBody("   ")).toBeNull();
  });

  test("parses JSON message field", () => {
    expect(parseErrorMessageBody('{ "message": "Login failed" }')).toBe("Login failed");
  });

  test("parses JSON error field", () => {
    expect(parseErrorMessageBody('{ "error": "Forbidden" }')).toBe("Forbidden");
  });

  test("parses direct JSON string", () => {
    expect(parseErrorMessageBody('"rate limited"')).toBe("rate limited");
  });

  test("falls back to plain text", () => {
    expect(parseErrorMessageBody("Plain error text")).toBe("Plain error text");
  });

  test("truncates long plain text", () => {
    const long = "x".repeat(260);
    const out = parseErrorMessageBody(long);
    expect(out).not.toBeNull();
    expect(out?.length).toBe(243);
    expect(out?.endsWith("...")).toBe(true);
  });
});

describe("sanitizeErrorMessage", () => {
  test("returns empty string for explicit not found text", () => {
    expect(sanitizeErrorMessage("Not Found", "Fallback")).toBe("");
    expect(sanitizeErrorMessage("404 Not Found", "Fallback")).toBe("");
    expect(sanitizeErrorMessage("endpoint not found", "Fallback")).toBe("");
  });

  test("filters generic failure phrases", () => {
    expect(sanitizeErrorMessage("Failed to load", "Fallback")).toBe("");
  });

  test("keeps meaningful API error text", () => {
    expect(sanitizeErrorMessage("Unauthorized", "Fallback")).toBe("Unauthorized");
  });

  test("masks server errors and empty fallbacks", () => {
    expect(sanitizeErrorMessage(new ApiError("Internal Server Error", 500), "Fallback")).toBe("");
    expect(sanitizeErrorMessage("", "Failed")).toBe("");
  });
});
