import { createErrorReporter, installWindowErrorReporting } from "@quicfuscate/error-reporting";
import { env } from "$env/dynamic/public";

const reporter = createErrorReporter({
  dsn: env.PUBLIC_SENTRY_DSN,
  environment: "admin",
});

installWindowErrorReporting(reporter);

export function reportAdminError(error: unknown, context?: Record<string, string>): void {
  reporter.capture(error, context);
}