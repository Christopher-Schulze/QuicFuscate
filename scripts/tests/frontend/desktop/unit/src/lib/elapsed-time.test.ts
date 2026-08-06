import { describe, expect, test } from "vitest";
import {
  MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS,
  evaluateByteRateSample,
  isBrowserDocumentVisible,
  type ByteCounterSample,
} from "../../../../../../../packages/time/index";

const previous: ByteCounterSample = {
  atMilliseconds: 1_000,
  bytesIn: 100,
  bytesOut: 200,
};

describe("shared browser elapsed-time policy", () => {
  test("rebases the first sample without reporting a rate", () => {
    const current = { atMilliseconds: 2_000, bytesIn: 1_100, bytesOut: 2_200 };
    expect(evaluateByteRateSample(null, current)).toEqual({
      nextSample: current,
      inBps: 0,
      outBps: 0,
      accepted: false,
      reason: "no-previous-sample",
    });
  });

  test("calculates a normal interval in bits per second", () => {
    expect(evaluateByteRateSample(previous, {
      atMilliseconds: 2_000,
      bytesIn: 1_100,
      bytesOut: 2_200,
    })).toMatchObject({
      inBps: 8_000,
      outBps: 16_000,
      accepted: true,
      reason: null,
    });
  });

  test.each([
    ["clock-regressed", { atMilliseconds: 900, bytesIn: 200, bytesOut: 300 }],
    ["gap-too-large", { atMilliseconds: 1_000 + MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS + 1, bytesIn: 200, bytesOut: 300 }],
    ["counter-regressed", { atMilliseconds: 2_000, bytesIn: 99, bytesOut: 300 }],
    ["counter-invalid", { atMilliseconds: 2_000, bytesIn: Number.NaN, bytesOut: 300 }],
    ["clock-invalid", { atMilliseconds: Number.NaN, bytesIn: 200, bytesOut: 300 }],
  ] as const)("rebases and emits zero for %s", (reason, current) => {
    const result = evaluateByteRateSample(previous, current);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe(reason);
    expect(result.inBps).toBe(0);
    expect(result.outBps).toBe(0);
    expect(result.nextSample).toEqual(reason === "clock-invalid" || reason === "counter-invalid" ? null : current);
  });

  test("treats the configured maximum gap as accepted and a larger gap as a rebase", () => {
    const accepted = evaluateByteRateSample(previous, {
      atMilliseconds: previous.atMilliseconds + MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS,
      bytesIn: 200,
      bytesOut: 300,
    });
    const rejected = evaluateByteRateSample(previous, {
      atMilliseconds: previous.atMilliseconds + MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS + 1,
      bytesIn: 200,
      bytesOut: 300,
    });
    expect(accepted.accepted).toBe(true);
    expect(rejected.reason).toBe("gap-too-large");
  });

  test("visibility helper treats only an explicitly hidden document as hidden", () => {
    const original = Object.getOwnPropertyDescriptor(document, "visibilityState");
    try {
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
      expect(isBrowserDocumentVisible()).toBe(false);
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
      expect(isBrowserDocumentVisible()).toBe(true);
    } finally {
      if (original) Object.defineProperty(document, "visibilityState", original);
      else delete (document as Document & { visibilityState?: string }).visibilityState;
    }
  });
});
