export const MAX_USERNAME_CHARS = 64;
export const MAX_PASSWORD_CHARS = 256;
export const MIN_PASSWORD_CHARS = 6;

export function usernameValidationError(raw: string): string | null {
  const value = raw.trim();
  if (!value) return null;
  if (value.length > MAX_USERNAME_CHARS) return `Username too long [max ${MAX_USERNAME_CHARS} chars]`;
  if ([...value].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Username contains invalid characters";
  return null;
}

export function passwordLengthError(raw: string): string | null {
  if (!raw) return null;
  if (raw.length < MIN_PASSWORD_CHARS) return `New password must be at least ${MIN_PASSWORD_CHARS} characters.`;
  if (raw.length > MAX_PASSWORD_CHARS) return `New password too long [max ${MAX_PASSWORD_CHARS} chars].`;
  return null;
}
