import { describe, expect, test } from "vitest";
import { normalizePersistedCircuit } from "../../../../../../apps/svelte-desktop/src/lib/circuit-persist";

function hop(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "hop-exit",
    label: "Exit",
    remote: "203.0.113.10:4433",
    sni: "cdn.example.com",
    qkeyId: "0123456789ab",
    qkey: "QKey-test",
    role: "exit",
    hasToken: true,
    ...overrides,
  };
}

describe("normalizePersistedCircuit diversity roundtrip", () => {
  test("hydrates camelCase failureDomain from a signed persist payload", () => {
    const circuit = normalizePersistedCircuit({
      hops: [hop()],
      maxHops: 3,
      maxParallelCircuits: 2,
      allowSingleHopFallback: false,
      diversity: {
        provider: true,
        region: false,
        jurisdiction: false,
        failureDomain: true,
      },
    });
    expect(circuit?.diversity.failureDomain).toBe(true);
    expect(circuit?.hops[0]?.failureDomain).toBeUndefined();
  });

  test("hydrates snake_case failure_domain from Specta serialize output", () => {
    const circuit = normalizePersistedCircuit({
      hops: [hop({ failure_domain: "omega", qkey_id: "0123456789ab", qkeyId: undefined })],
      max_hops: 3,
      max_parallel_circuits: 2,
      allow_single_hop_fallback: true,
      diversity: {
        provider: false,
        region: true,
        jurisdiction: false,
        failure_domain: true,
      },
    });
    expect(circuit).not.toBeNull();
    expect(circuit?.diversity).toEqual({
      provider: false,
      region: true,
      jurisdiction: false,
      failureDomain: true,
    });
    expect(circuit?.allowSingleHopFallback).toBe(true);
    expect(circuit?.hops[0]?.failureDomain).toBe("omega");
    expect(circuit?.hops[0]?.qkeyId).toBe("0123456789ab");
  });

  test("hydrates hop policy snake_case overrides", () => {
    const circuit = normalizePersistedCircuit({
      hops: [hop({
        policy: {
          fec_mode: "off",
          enable_traffic_padding: true,
          enable_timing_obfuscation: false,
          enable_cover_ping: true,
        },
      })],
      diversity: { failure_domain: false },
    });
    expect(circuit?.hops[0]?.policy).toEqual({
      persona: undefined,
      fecMode: "off",
      enableTrafficPadding: true,
      enableTimingObfuscation: false,
      enableCoverPing: true,
    });
  });
});
