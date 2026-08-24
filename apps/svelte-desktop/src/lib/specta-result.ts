/**
 * tauri-specta wraps invoke in `{ status: "ok", data } | { status: "error", error }`.
 * Tauri still throws `Error` for most `Result::Err` strings; that path is rethrown
 * by the generated helper and never becomes the error variant.
 */
export type SpectaCommandResult<T, E = string> =
  | { status: "ok"; data: T }
  | { status: "error"; error: E };

export async function wrapSpectaInvoke<T, E>(
  result: Promise<T>,
): Promise<SpectaCommandResult<T, E>> {
  try {
    return { status: "ok", data: await result };
  } catch (error) {
    if (error instanceof Error) throw error;
    if (typeof error === "string") {
      return { status: "error", error: error as E };
    }
    throw new Error("Native command failed with an untyped error");
  }
}

export async function unwrapSpectaCommand<T>(
  result: Promise<SpectaCommandResult<T>>,
): Promise<T> {
  const resolved = await result;
  if (resolved.status === "error") {
    const message =
      typeof resolved.error === "string" && resolved.error.trim().length > 0
        ? resolved.error
        : "Native command failed";
    throw new Error(message);
  }
  return resolved.data;
}
