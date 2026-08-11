export const CONGESTION_CONTROL_OPTIONS = [
  { value: "reno", label: "Reno", compactLabel: "RENO" },
  { value: "cubic", label: "CUBIC", compactLabel: "CUBIC" },
  { value: "bbr2", label: "BBR2", compactLabel: "BBR2" },
  { value: "bbr3", label: "BBR3", compactLabel: "BBR3" },
] as const;

export type CongestionControlAlgorithm = (typeof CONGESTION_CONTROL_OPTIONS)[number]["value"];

export function parseCongestionControlAlgorithm(
  raw: string | null | undefined,
): CongestionControlAlgorithm | null {
  const normalized = (raw ?? "").trim().toLowerCase();
  return CONGESTION_CONTROL_OPTIONS.find((option) => option.value === normalized)?.value ?? null;
}

export function congestionControlDisplayLabel(raw: string): string {
  const normalized = parseCongestionControlAlgorithm(raw);
  return normalized === null
    ? "Custom"
    : CONGESTION_CONTROL_OPTIONS.find((option) => option.value === normalized)?.compactLabel ?? "Custom";
}
