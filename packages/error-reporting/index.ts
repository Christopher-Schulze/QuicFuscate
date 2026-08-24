export interface CapturedErrorEvent {
  message: string;
  stack?: string;
  context?: Record<string, string>;
  timestampMs: number;
}

export interface ErrorReporter {
  capture(error: unknown, context?: Record<string, string>): void;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) return error.message;
  if (typeof error === "string" && error.trim().length > 0) return error;
  return "Unknown UI error";
}

function errorStack(error: unknown): string | undefined {
  return error instanceof Error && typeof error.stack === "string" ? error.stack : undefined;
}

function sentryStoreUrl(dsn: string): URL | null {
  let parsed: URL;
  try {
    parsed = new URL(dsn);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  const publicKey = parsed.username.trim();
  const projectId = parsed.pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!publicKey || !projectId || !/^[A-Za-z0-9._-]+$/.test(publicKey) || !/^\d+$/.test(projectId)) {
    return null;
  }
  return new URL(`https://${parsed.host}/api/${projectId}/store/?sentry_key=${encodeURIComponent(publicKey)}`);
}

function sentryPayload(event: CapturedErrorEvent, environment: string): string {
  return JSON.stringify({
    event_id: crypto.randomUUID().replaceAll("-", ""),
    timestamp: event.timestampMs / 1000,
    platform: "javascript",
    environment,
    exception: {
      values: [
        {
          type: "Error",
          value: event.message,
          stacktrace: event.stack ? { frames: [{ filename: "quicfuscate-ui", function: "capture", abs_path: event.stack }] } : undefined,
        },
      ],
    },
    tags: event.context ?? {},
  });
}

export function createErrorReporter(options: {
  dsn?: string;
  environment: string;
  fetchImpl?: typeof fetch;
}): ErrorReporter {
  const rawDsn = typeof options.dsn === "string" ? options.dsn.trim() : "";
  const storeUrl = rawDsn.length > 0 ? sentryStoreUrl(rawDsn) : null;
  if (rawDsn.length > 0 && storeUrl == null) {
    throw new Error("Invalid Sentry DSN");
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  return {
    capture(error: unknown, context?: Record<string, string>): void {
      const event: CapturedErrorEvent = {
        message: errorMessage(error),
        stack: errorStack(error),
        context,
        timestampMs: Date.now(),
      };
      if (storeUrl == null || typeof fetchImpl !== "function") return;
      void fetchImpl(storeUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: sentryPayload(event, options.environment),
        keepalive: true,
      }).catch(() => {
        // Fail closed on the wire: never throw into the UI from telemetry.
      });
    },
  };
}

export function installWindowErrorReporting(reporter: ErrorReporter): () => void {
  if (typeof window === "undefined") return () => {};
  const onError = (event: ErrorEvent) => {
    reporter.capture(event.error ?? event.message, { source: "window.error" });
  };
  const onRejection = (event: PromiseRejectionEvent) => {
    reporter.capture(event.reason, { source: "window.unhandledrejection" });
  };
  window.addEventListener("error", onError);
  window.addEventListener("unhandledrejection", onRejection);
  return () => {
    window.removeEventListener("error", onError);
    window.removeEventListener("unhandledrejection", onRejection);
  };
}
