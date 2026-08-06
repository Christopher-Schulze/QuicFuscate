import { describe, expect, test } from "vitest";
import {
  MAX_ELAPSED_SAMPLE_GAP_MILLISECONDS,
  evaluateByteRateSample,
  isBrowserDocumentVisible,
  readBrowserMonotonicMilliseconds,
  type ByteCounterSample,
} from "../../../../../../../packages/time/index";
import { getFrontendClockHarness } from "../../../../test-clock";

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

  test("keeps elapsed samples valid across a wall-clock jump", () => {
    const clock = getFrontendClockHarness();
    clock.installClockSources();
    clock.setWallTime(1_710_000_000_000);
    clock.setMonotonicTime(1_000);
    const previousSample = {
      atMilliseconds: readBrowserMonotonicMilliseconds(),
      bytesIn: 100,
      bytesOut: 200,
    };

    clock.advanceWallTime(-86_400_000);
    clock.advanceMonotonicTime(1_000);
    const currentSample = {
      atMilliseconds: readBrowserMonotonicMilliseconds(),
      bytesIn: 1_100,
      bytesOut: 2_200,
    };

    expect(evaluateByteRateSample(previousSample, currentSample)).toMatchObject({
      accepted: true,
      inBps: 8_000,
      outBps: 16_000,
    });
  });

  test("visibility helper treats only an explicitly hidden document as hidden", () => {
    const clock = getFrontendClockHarness();
    clock.setVisibility("hidden");
    expect(isBrowserDocumentVisible()).toBe(false);
    clock.setVisibility("visible");
    expect(isBrowserDocumentVisible()).toBe(true);
  });
});
