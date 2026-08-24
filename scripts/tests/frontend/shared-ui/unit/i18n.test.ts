import { describe, expect, test } from "vitest";
import { ENGLISH_MESSAGES, t, availableLocales } from "../../../../../packages/i18n";

describe("i18n catalogs", () => {
  test("english is the only shipped locale and every key is non-empty", () => {
    expect(availableLocales()).toEqual(["en"]);
    for (const [key, value] of Object.entries(ENGLISH_MESSAGES)) {
      expect(value.length, key).toBeGreaterThan(0);
      expect(t(key as keyof typeof ENGLISH_MESSAGES)).toBe(value);
    }
  });
});
