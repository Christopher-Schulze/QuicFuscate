import { describe, expect, test, vi } from "vitest";
import { createErrorReporter } from "../../../../../packages/error-reporting";

describe("error reporter", () => {
  test("no-ops when no DSN is configured", () => {
    const fetchImpl = vi.fn();
    const reporter = createErrorReporter({ environment: "test", fetchImpl: fetchImpl as unknown as typeof fetch });
    reporter.capture(new Error("boom"));
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test("rejects a malformed DSN fail-closed", () => {
    expect(() => createErrorReporter({
      dsn: "http://example.invalid",
      environment: "test",
    })).toThrow("Invalid Sentry DSN");
  });

  test("posts a Sentry store event when a valid DSN is present", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({ ok: true });
    const reporter = createErrorReporter({
      dsn: "https://publickey@sentry.example/123",
      environment: "desktop",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    reporter.capture(new Error("sealed"), { source: "test" });
    await Promise.resolve();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [URL, RequestInit];
    expect(url.pathname).toBe("/api/123/store/");
    expect(url.searchParams.get("sentry_key")).toBe("publickey");
    expect(init.method).toBe("POST");
    const body = JSON.parse(String(init.body));
    expect(body.exception.values[0].value).toBe("sealed");
    expect(body.environment).toBe("desktop");
  });
});
