import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

import {
  parseArguments,
  runBoundedPreview,
  type BoundedPreviewConfig,
  type BoundedPreviewResult,
} from "./run-bounded-preview";

const HOST = "127.0.0.1";
const fixture = fileURLToPath(new URL("./fixtures/bounded-preview-server.ts", import.meta.url));

interface PortReservation {
  close: () => Promise<void>;
  port: number;
}

function reservePort(): PortReservation {
  const server = Bun.serve({
    hostname: HOST,
    port: 0,
    fetch(): Response {
      return new Response("reserved");
    },
  });
  return {
    close: () => server.stop(true),
    port: server.port,
  };
}

async function freePort(): Promise<number> {
  const reservation = reservePort();
  await reservation.close();
  return reservation.port;
}

function fixtureConfig(
  port: number,
  mode: "ignore-term" | "ready" | "unready",
  overrides: Partial<BoundedPreviewConfig> = {},
): BoundedPreviewConfig {
  return {
    cleanupTimeoutMs: 500,
    command: [process.execPath, fixture, HOST, String(port), mode],
    host: HOST,
    port,
    serveDurationMs: 100,
    startupTimeoutMs: 1_500,
    workingDirectory: process.cwd(),
    ...overrides,
  };
}

function processIsAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch {
    return false;
  }
}

async function expectStopped(result: BoundedPreviewResult): Promise<void> {
  if (result.processId === null) {
    return;
  }
  await Bun.sleep(25);
  expect(processIsAlive(result.processId)).toBe(false);
}

test("accepts only explicit loopback host and valid port arguments", () => {
  expect(parseArguments(["--host=127.0.0.1", "--port=1430"])).toEqual({ host: HOST, port: 1430 });
  expect(parseArguments(["--host=::1", "--port=4173"])).toEqual({ host: "::1", port: 4173 });

  for (const arguments_ of [
    [],
    ["--host=0.0.0.0", "--port=1430"],
    ["--host=127.0.0.1", "--port=0"],
    ["--host=127.0.0.1", "--port=65536"],
    ["--host=127.0.0.1", "--port=abc"],
    ["--host=127.0.0.1", "--port=1430", "--extra"],
  ]) {
    expect(() => parseArguments(arguments_)).toThrow();
  }
});

test("probes a ready server, bounds its lifetime, and reaps it", async () => {
  const result = await runBoundedPreview(fixtureConfig(await freePort(), "ready"));

  expect(result.exitCode).toBe(0);
  expect(result.phase).toBe("serving");
  expect(result.cleanup).toBe("sigterm");
  await expectStopped(result);
});

test("returns 124 when readiness never succeeds and reaps the server", async () => {
  const result = await runBoundedPreview(fixtureConfig(await freePort(), "unready", {
    startupTimeoutMs: 250,
  }));

  expect(result.exitCode).toBe(124);
  expect(result.phase).toBe("startup");
  expect(result.cleanup).toBe("sigterm");
  await expectStopped(result);
});

test("returns deterministic failure on a port collision without stopping the owner", async () => {
  const reservation = reservePort();
  try {
    const result = await runBoundedPreview(fixtureConfig(reservation.port, "ready"));

    expect(result.exitCode).toBe(1);
    expect(result.phase).toBe("startup");
    const response = await fetch(`http://${HOST}:${reservation.port}/`);
    expect(await response.text()).toBe("reserved");
    await expectStopped(result);
  } finally {
    await reservation.close();
  }
});

test("escalates a SIGTERM-resistant server to SIGKILL and reaps it", async () => {
  const result = await runBoundedPreview(fixtureConfig(await freePort(), "ignore-term", {
    cleanupTimeoutMs: 100,
    serveDurationMs: 50,
  }));

  expect(result.exitCode).toBe(0);
  expect(result.phase).toBe("serving");
  expect(result.cleanup).toBe("sigkill");
  await expectStopped(result);
});
