/**
 * Shared timestamp boundary types and validation for browser-facing clients.
 *
 * Unix milliseconds and Unix seconds are deliberately branded separately. The
 * runtime validators reject values that are non-finite, fractional, pre-epoch,
 * outside the JavaScript Date range, or clearly expressed in the other unit.
 */

export const MAX_UNIX_DATE_MILLISECONDS = 8_640_000_000_000_000;
export const LIKELY_UNIX_SECONDS_MINIMUM = 1_000_000_000;
export const LIKELY_UNIX_SECONDS_MAXIMUM = 10_000_000_000;

export type TimestampSource =
  | "tauri-persisted-tunnel"
  | "tauri-log"
  | "desktop-created"
  | "admin-qkey"
  | "admin-log";

declare const timestampBrand: unique symbol;

export type UnixMilliseconds<Source extends TimestampSource = TimestampSource> = number & {
  readonly [timestampBrand]: {
    readonly unit: "milliseconds";
    readonly source: Source;
  };
};

export type UnixSeconds<Source extends TimestampSource = TimestampSource> = number & {
  readonly [timestampBrand]: {
    readonly unit: "seconds";
    readonly source: Source;
  };
};

export type TimestampValidationError =
  | "not-a-number"
  | "non-finite"
  | "pre-epoch"
  | "zero"
  | "fractional"
  | "unsafe-integer"
  | "date-range"
  | "unit-mismatch";

export interface ValidTimestamp<T> {
  readonly ok: true;
  readonly value: T;
}

export interface InvalidTimestamp {
  readonly ok: false;
  readonly error: TimestampValidationError;
}

export type TimestampResult<T> = ValidTimestamp<T> | InvalidTimestamp;

export const MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS = 5_000;
export const PASTE_CLICK_SUPPRESSION_MILLISECONDS = 400;

export type ElapsedSampleResetReason =
  | "clock-invalid"
  | "clock-regressed"
  | "gap-too-large"
  | "counter-invalid"
  | "counter-regressed"
  | "no-previous-sample";

export interface ByteCounterSample {
  readonly atMilliseconds: number;
  readonly bytesIn: number;
  readonly bytesOut: number;
}

export interface ByteRateEvaluation {
  readonly nextSample: ByteCounterSample | null;
  readonly inBps: number;
  readonly outBps: number;
  readonly accepted: boolean;
  readonly reason: ElapsedSampleResetReason | null;
}

function rejectNumber(value: unknown): TimestampValidationError | null {
  if (typeof value !== "number") return "not-a-number";
  if (!Number.isFinite(value)) return "non-finite";
  if (!Number.isInteger(value)) return "fractional";
  if (!Number.isSafeInteger(value)) return "unsafe-integer";
  if (value < 0) return "pre-epoch";
  if (value === 0) return "zero";
  return null;
}

function valid<T>(value: T): ValidTimestamp<T> {
  return { ok: true, value };
}

function invalid(error: TimestampValidationError): InvalidTimestamp {
  return { ok: false, error };
}

function isValidElapsedTimestamp(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

function isValidByteCounter(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

function resetByteRate(current: ByteCounterSample | null, reason: ElapsedSampleResetReason): ByteRateEvaluation {
  return {
    nextSample: current,
    inBps: 0,
    outBps: 0,
    accepted: false,
    reason,
  };
}

/** Read the browser's monotonic clock without falling back to wall time. */
export function readBrowserMonotonicMilliseconds(): number {
  const now = globalThis.performance?.now();
  return typeof now === "number" && Number.isFinite(now) ? now : Number.NaN;
}

/** Treat every state except an explicitly hidden document as visible. */
export function isBrowserDocumentVisible(): boolean {
  return typeof document === "undefined" || document.visibilityState !== "hidden";
}

/**
 * Evaluate one byte-counter interval under the shared browser timing policy.
 * A rejected interval rebases on the current sample and emits zero rates.
 */
export function evaluateByteRateSample(
  previous: ByteCounterSample | null,
  current: ByteCounterSample,
): ByteRateEvaluation {
  const currentTimeValid = isValidElapsedTimestamp(current.atMilliseconds);
  const currentCountersValid = isValidByteCounter(current.bytesIn) && isValidByteCounter(current.bytesOut);
  if (!currentTimeValid) return resetByteRate(null, "clock-invalid");
  if (!currentCountersValid) return resetByteRate(null, "counter-invalid");
  if (previous === null) return resetByteRate(current, "no-previous-sample");

  if (!isValidElapsedTimestamp(previous.atMilliseconds)) return resetByteRate(current, "clock-invalid");
  if (!isValidByteCounter(previous.bytesIn) || !isValidByteCounter(previous.bytesOut)) {
    return resetByteRate(current, "counter-invalid");
  }

  const elapsedMilliseconds = current.atMilliseconds - previous.atMilliseconds;
  if (elapsedMilliseconds <= 0) return resetByteRate(current, "clock-regressed");
  if (elapsedMilliseconds > MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS) {
    return resetByteRate(current, "gap-too-large");
  }
  if (current.bytesIn < previous.bytesIn || current.bytesOut < previous.bytesOut) {
    return resetByteRate(current, "counter-regressed");
  }

  const inBps = ((current.bytesIn - previous.bytesIn) * 8 * 1000) / elapsedMilliseconds;
  const outBps = ((current.bytesOut - previous.bytesOut) * 8 * 1000) / elapsedMilliseconds;
  if (!Number.isFinite(inBps) || !Number.isFinite(outBps)) return resetByteRate(current, "counter-invalid");

  return {
    nextSample: current,
    inBps,
    outBps,
    accepted: true,
    reason: null,
  };
}

/** Validate a value received as Unix epoch milliseconds. */
export function parseUnixMilliseconds<Source extends TimestampSource>(
  value: unknown,
  source: Source,
): TimestampResult<UnixMilliseconds<Source>> {
  const numberError = rejectNumber(value);
  if (numberError) return invalid(numberError);
  const numericValue = value as number;
  if (numericValue > MAX_UNIX_DATE_MILLISECONDS) return invalid("date-range");

  if (numericValue >= LIKELY_UNIX_SECONDS_MINIMUM && numericValue <= LIKELY_UNIX_SECONDS_MAXIMUM) {
    return invalid("unit-mismatch");
  }

  return valid(numericValue as UnixMilliseconds<Source>);
}

/** Validate a value received as Unix epoch seconds. */
export function parseUnixSeconds<Source extends TimestampSource>(
  value: unknown,
  source: Source,
): TimestampResult<UnixSeconds<Source>> {
  const numberError = rejectNumber(value);
  if (numberError) return invalid(numberError);
  const numericValue = value as number;

  if (numericValue > MAX_UNIX_DATE_MILLISECONDS / 1000) return invalid("date-range");
  if (numericValue > LIKELY_UNIX_SECONDS_MAXIMUM) return invalid("unit-mismatch");

  return valid(numericValue as UnixSeconds<Source>);
}

/** Convert a previously validated Unix-seconds value into validated milliseconds. */
export function unixSecondsToMilliseconds<Source extends TimestampSource>(
  value: UnixSeconds<Source>,
  source: Source,
): UnixMilliseconds<Source> | null {
  const seconds = parseUnixSeconds(value, source);
  if (!seconds.ok) return null;
  const result = parseUnixMilliseconds(seconds.value * 1000, source);
  return result.ok ? result.value : null;
}

/** Convert a validated Unix-milliseconds value into a Date without reinterpreting its unit. */
export function unixMillisecondsToDate(
  value: UnixMilliseconds | null,
): Date | null {
  if (value === null) return null;
  const result = parseUnixMilliseconds(value, "admin-log");
  return result.ok ? new Date(result.value) : null;
}

export function describeTimestampError(error: TimestampValidationError): string {
  switch (error) {
    case "not-a-number": return "value is not a number";
    case "non-finite": return "value is not finite";
    case "pre-epoch": return "value is before the Unix epoch";
    case "zero": return "zero is reserved for an invalid timestamp";
    case "fractional": return "fractional values are not allowed";
    case "unsafe-integer": return "value is outside the safe integer range";
    case "date-range": return "value is outside the JavaScript Date range";
    case "unit-mismatch": return "value appears to use the other Unix time unit";
  }
}
