import { describe, expect, test } from "vitest";
import {
  MAX_PASSWORD_CHARS,
  MAX_USERNAME_CHARS,
  MIN_PASSWORD_CHARS,
  passwordLengthError,
  usernameValidationError,
} from "../../../../../apps/svelte-admin/src/lib/admin-auth-validation";

describe("usernameValidationError", () => {
  test("accepts an empty or whitespace value as untouched", () => {
    expect(usernameValidationError("")).toBeNull();
    expect(usernameValidationError("   ")).toBeNull();
  });

  test("rejects a username that exceeds the character ceiling", () => {
    expect(usernameValidationError("a".repeat(MAX_USERNAME_CHARS + 1))).toBe(
      `Username too long [max ${MAX_USERNAME_CHARS} chars]`,
    );
  });

  test("rejects control characters", () => {
    expect(usernameValidationError("ad\nmin")).toBe("Username contains invalid characters");
  });

  test("accepts a valid username", () => {
    expect(usernameValidationError("admin")).toBeNull();
  });
});

describe("passwordLengthError", () => {
  test("accepts an empty value as untouched", () => {
    expect(passwordLengthError("")).toBeNull();
  });

  test("rejects a password below the minimum", () => {
    expect(passwordLengthError("a".repeat(MIN_PASSWORD_CHARS - 1))).toBe(
      `New password must be at least ${MIN_PASSWORD_CHARS} characters.`,
    );
  });

  test("rejects a password above the maximum", () => {
    expect(passwordLengthError("a".repeat(MAX_PASSWORD_CHARS + 1))).toBe(
      `New password too long [max ${MAX_PASSWORD_CHARS} chars].`,
    );
  });

  test("accepts a valid password", () => {
    expect(passwordLengthError("a".repeat(MIN_PASSWORD_CHARS))).toBeNull();
  });
});
