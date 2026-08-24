import { describe, expect, test } from "vitest";
import { parsePrometheusText } from "../../../../../apps/svelte-admin/src/lib/prometheus-text";

describe("parsePrometheusText", () => {
  test("returns an empty map for blank input", () => {
    expect(parsePrometheusText("")).toEqual({});
    expect(parsePrometheusText("\n# HELP foo bar\n")).toEqual({});
  });

  test("parses a plain sample", () => {
    expect(parsePrometheusText("quicfuscate_up 1\n")).toEqual({ quicfuscate_up: 1 });
  });

  test("sums labeled series onto the metric name", () => {
    expect(parsePrometheusText(
      "quicfuscate_bytes_in_total{iface=\"a\"} 10\nquicfuscate_bytes_in_total{iface=\"b\"} 7\n",
    )).toEqual({ quicfuscate_bytes_in_total: 17 });
  });

  test("ignores non-finite values and malformed names", () => {
    expect(parsePrometheusText("bad-name 1\nquicfuscate_up NaN\nquicfuscate_up 2\n")).toEqual({
      quicfuscate_up: 2,
    });
  });
});
