export function resolveCoverSniDisplay(
  extra: string | null | undefined,
  fallbackSni: string,
): string {
  const fallback = fallbackSni.trim() || "QKey Policy";
  const raw = (extra ?? "").trim();
  if (!raw) return fallback;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return fallback;
    const obj = parsed as Record<string, unknown>;
    const mode = typeof obj.df_sni_mode === "string" ? obj.df_sni_mode.trim().toLowerCase() : "";
    if (mode === "auto_rotating") return "Auto [Rotating]";
    if (mode === "fixed") {
      const fixed = typeof obj.df_sni_domain === "string" ? obj.df_sni_domain.trim() : "";
      return fixed || fallback;
    }
    return fallback;
  } catch { return fallback; }
}
