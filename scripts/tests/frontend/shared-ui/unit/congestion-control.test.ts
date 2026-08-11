import { describe, expect, test } from "vitest";
import {
  CONGESTION_CONTROL_OPTIONS,
  congestionControlDisplayLabel,
  parseCongestionControlAlgorithm,
} from "../../../../../packages/ui/congestion-control";

describe("congestion-control contract", () => {
  test("owns the exact backend algorithm and label set", () => {
    expect(CONGESTION_CONTROL_OPTIONS).toEqual([
      { value: "reno", label: "Reno", compactLabel: "RENO" },
      { value: "cubic", label: "CUBIC", compactLabel: "CUBIC" },
      { value: "bbr2", label: "BBR2", compactLabel: "BBR2" },
      { value: "bbr3", label: "BBR3", compactLabel: "BBR3" },
    ]);
  });

  test("normalizes every canonical algorithm and rejects unknown values", () => {
    for (const option of CONGESTION_CONTROL_OPTIONS) {
      expect(parseCongestionControlAlgorithm(` ${option.value.toUpperCase()} `)).toBe(option.value);
    }
    expect(parseCongestionControlAlgorithm("bbr")).toBeNull();
    expect(parseCongestionControlAlgorithm("vegas")).toBeNull();
  });

  test("maps canonical compact labels without hiding unknown values", () => {
    for (const option of CONGESTION_CONTROL_OPTIONS) {
      expect(congestionControlDisplayLabel(option.value)).toBe(option.compactLabel);
    }
    expect(congestionControlDisplayLabel("westwood")).toBe("Custom");
  });
});
