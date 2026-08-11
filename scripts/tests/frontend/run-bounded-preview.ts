import { existsSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_SERVE_DURATION_MS = 30_000;
const DEFAULT_STARTUP_TIMEOUT_MS = 15_000;
const DEFAULT_CLEANUP_TIMEOUT_MS = 2_000;
const READINESS_POLL_INTERVAL_MS = 100;
const READINESS_REQUEST_TIMEOUT_MS = 1_000;
const READINESS_STABILITY_MS = 100;

const EXIT_SERVER_FAILURE = 1;
const EXIT_ARGUMENT_FAILURE = 2;
const EXIT_READINESS_TIMEOUT = 124;
const EXIT_CLEANUP_FAILURE = 125;

type ForwardedSignal = "SIGINT" | "SIGTERM";
type CleanupMethod = "not-needed" | "sigterm" | "sigkill" | "failed";
type FixturePhase = "startup" | "serving" | "signal";

interface RunnerArguments {
  host: string;
  port: number;
}

interface OwnedProcess {
  readonly exited: Promise<number>;
  readonly pid: number;
  kill(signal?: string | number): void;
}

export interface BoundedPreviewConfig {
  cleanupTimeoutMs: number;
  command: string[];
  host: string;
  port: number;
  serveDurationMs: number;
  startupTimeoutMs: number;
  workingDirectory: string;
}

export interface BoundedPreviewResult {
  childExitCode: number | null;
  cleanup: CleanupMethod;
  exitCode: number;
  phase: FixturePhase;
  processId: number | null;
}

interface ExitOutcome {
  exitCode: number;
  kind: "exit";
}

interface ReadyOutcome {
  kind: "ready";
}

interface SignalOutcome {
  kind: "signal";
  signal: ForwardedSignal;
}

interface TimeoutOutcome {
  kind: "timeout";
}

type ReadinessOutcome = ExitOutcome | ReadyOutcome | SignalOutcome | TimeoutOutcome;
type ReadinessFailure = ExitOutcome | SignalOutcome | TimeoutOutcome;
type LifetimeOutcome = ExitOutcome | SignalOutcome | TimeoutOutcome;

interface StoppedProcess {
  childExitCode: number | null;
  cleanup: CleanupMethod;
}

function parsePort(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error(`--port must be an integer from 1 through 65535, received ${JSON.stringify(value)}`);
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`--port must be an integer from 1 through 65535, received ${JSON.stringify(value)}`);
  }
  return port;
}

function parseHost(value: string): string {
  if (value !== "127.0.0.1" && value !== "::1") {
    throw new Error(
      `--host must be an explicit loopback address (127.0.0.1 or ::1), received ${JSON.stringify(value)}`,
    );
  }
  return value;
}

export function parseArguments(arguments_: string[]): RunnerArguments {
  let host: string | null = null;
  let port: number | null = null;

  for (const argument of arguments_) {
    if (argument.startsWith("--host=")) {
      if (host !== null) {
        throw new Error("--host must be provided exactly once");
      }
      host = parseHost(argument.slice("--host=".length));
      continue;
    }
    if (argument.startsWith("--port=")) {
      if (port !== null) {
        throw new Error("--port must be provided exactly once");
      }
      port = parsePort(argument.slice("--port=".length));
      continue;
    }
    throw new Error(`unknown argument ${JSON.stringify(argument)}`);
  }

  if (host === null || port === null) {
    throw new Error("exactly one --host and one --port are required");
  }
  return { host, port };
}

function validateDuration(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
}

function validateConfig(config: BoundedPreviewConfig): void {
  parseHost(config.host);
  parsePort(String(config.port));
  validateDuration(config.startupTimeoutMs, "startupTimeoutMs");
  validateDuration(config.serveDurationMs, "serveDurationMs");
  validateDuration(config.cleanupTimeoutMs, "cleanupTimeoutMs");
  if (config.command.length === 0 || config.command.some((part) => part.length === 0)) {
    throw new Error("command must contain at least one non-empty part");
  }
}

function loopbackUrl(host: string, port: number): string {
  const urlHost = host === "::1" ? `[${host}]` : host;
  return `http://${urlHost}:${port}/`;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function waitForExit(exited: Promise<number>, timeoutMs: number): Promise<number | null> {
  return new Promise((resolveExit) => {
    let settled = false;
    const timeout = setTimeout(() => {
      settled = true;
      resolveExit(null);
    }, timeoutMs);

    const observeExit = async (): Promise<void> => {
      const exitCode = await exited;
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        resolveExit(exitCode);
      }
    };
    void observeExit();
  });
}

async function exitOutcome(exited: Promise<number>): Promise<ExitOutcome> {
  return { kind: "exit", exitCode: await exited };
}

async function timeoutOutcome(durationMs: number): Promise<TimeoutOutcome> {
  await delay(durationMs);
  return { kind: "timeout" };
}

async function isReady(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(READINESS_REQUEST_TIMEOUT_MS),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function readinessProbe(url: string): Promise<ReadyOutcome | null> {
  return (await isReady(url)) ? { kind: "ready" } : null;
}

function signalExitCode(signal: ForwardedSignal): number {
  return signal === "SIGINT" ? 130 : 143;
}

function registerSignalCapture(): {
  current: () => ForwardedSignal | null;
  remove: () => void;
  signal: Promise<SignalOutcome>;
} {
  let currentSignal: ForwardedSignal | null = null;
  let resolveSignal: (outcome: SignalOutcome) => void = () => {};
  const signal = new Promise<SignalOutcome>((resolveOutcome) => {
    resolveSignal = resolveOutcome;
  });
  const capture = (captured: ForwardedSignal): void => {
    if (currentSignal !== null) {
      return;
    }
    currentSignal = captured;
    resolveSignal({ kind: "signal", signal: captured });
  };
  const interrupt = (): void => capture("SIGINT");
  const terminate = (): void => capture("SIGTERM");
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", terminate);

  return {
    current: () => currentSignal,
    remove: () => {
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", terminate);
    },
    signal,
  };
}

async function portIsAvailable(host: string, port: number): Promise<boolean> {
  try {
    const reservation = Bun.serve({
      hostname: host,
      port,
      fetch(): Response {
        return new Response(null, { status: 204 });
      },
    });
    await reservation.stop(true);
    return true;
  } catch {
    return false;
  }
}

async function waitForReadiness(
  child: OwnedProcess,
  url: string,
  timeoutMs: number,
  capturedSignal: Promise<SignalOutcome>,
): Promise<ReadinessOutcome> {
  const deadline = Date.now() + timeoutMs;
  const childExit = exitOutcome(child.exited);

  while (Date.now() < deadline) {
    const outcome = await Promise.race([readinessProbe(url), childExit, capturedSignal]);
    if (outcome?.kind === "ready") {
      const earlyExit = await waitForExit(child.exited, READINESS_STABILITY_MS);
      return earlyExit === null ? outcome : { kind: "exit", exitCode: earlyExit };
    }
    if (outcome !== null) {
      return outcome;
    }
    const remaining = deadline - Date.now();
    if (remaining > 0) {
      await delay(Math.min(READINESS_POLL_INTERVAL_MS, remaining));
    }
  }
  return { kind: "timeout" };
}

async function waitForLifetime(
  child: OwnedProcess,
  durationMs: number,
  capturedSignal: Promise<SignalOutcome>,
): Promise<LifetimeOutcome> {
  return Promise.race([exitOutcome(child.exited), capturedSignal, timeoutOutcome(durationMs)]);
}

async function signalAndWait(
  child: OwnedProcess,
  signal: ForwardedSignal | "SIGKILL",
  timeoutMs: number,
): Promise<number | null> {
  try {
    child.kill(signal);
  } catch {
    // The process may have exited between the preceding state check and this signal.
  }
  return waitForExit(child.exited, timeoutMs);
}

async function stopChild(child: OwnedProcess, timeoutMs: number): Promise<StoppedProcess> {
  const alreadyExited = await waitForExit(child.exited, 1);
  if (alreadyExited !== null) {
    return { childExitCode: alreadyExited, cleanup: "not-needed" };
  }

  const gracefulExit = await signalAndWait(child, "SIGTERM", timeoutMs);
  if (gracefulExit !== null) {
    return { childExitCode: gracefulExit, cleanup: "sigterm" };
  }

  const forcedExit = await signalAndWait(child, "SIGKILL", timeoutMs);
  return forcedExit === null
    ? { childExitCode: null, cleanup: "failed" }
    : { childExitCode: forcedExit, cleanup: "sigkill" };
}

function spawnOwnedProcess(config: BoundedPreviewConfig): OwnedProcess {
  return Bun.spawn({
    cmd: config.command,
    cwd: config.workingDirectory,
    env: process.env,
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
}

function processlessResult(exitCode: number, phase: FixturePhase): BoundedPreviewResult {
  return { childExitCode: null, cleanup: "not-needed", exitCode, phase, processId: null };
}

function stoppedResult(
  child: OwnedProcess,
  stopped: StoppedProcess,
  exitCode: number,
  phase: FixturePhase,
): BoundedPreviewResult {
  return { ...stopped, exitCode, phase, processId: child.pid };
}

async function finishReadinessFailure(
  child: OwnedProcess,
  config: BoundedPreviewConfig,
  outcome: ReadinessFailure,
): Promise<BoundedPreviewResult> {
  const stopped = await stopChild(child, config.cleanupTimeoutMs);
  if (stopped.cleanup === "failed") {
    return stoppedResult(child, stopped, EXIT_CLEANUP_FAILURE, "startup");
  }
  if (outcome.kind === "signal") {
    return stoppedResult(child, stopped, signalExitCode(outcome.signal), "signal");
  }
  const exitCode = outcome.kind === "timeout" ? EXIT_READINESS_TIMEOUT : EXIT_SERVER_FAILURE;
  return stoppedResult(child, stopped, exitCode, "startup");
}

async function finishLifetime(
  child: OwnedProcess,
  config: BoundedPreviewConfig,
  outcome: LifetimeOutcome,
): Promise<BoundedPreviewResult> {
  const stopped = await stopChild(child, config.cleanupTimeoutMs);
  if (stopped.cleanup === "failed") {
    return stoppedResult(child, stopped, EXIT_CLEANUP_FAILURE, "serving");
  }
  if (outcome.kind === "signal") {
    return stoppedResult(child, stopped, signalExitCode(outcome.signal), "signal");
  }
  if (outcome.kind === "exit") {
    return stoppedResult(child, stopped, EXIT_SERVER_FAILURE, "serving");
  }
  console.log(`[preview-runner] bounded lifetime complete; cleanup=${stopped.cleanup}`);
  return stoppedResult(child, stopped, 0, "serving");
}

async function runChildLifecycle(
  child: OwnedProcess,
  config: BoundedPreviewConfig,
  url: string,
  capturedSignal: Promise<SignalOutcome>,
): Promise<BoundedPreviewResult> {
  const readiness = await waitForReadiness(child, url, config.startupTimeoutMs, capturedSignal);
  if (readiness.kind !== "ready") {
    return finishReadinessFailure(child, config, readiness);
  }
  console.log(`[preview-runner] readiness PASS: ${url}`);
  const lifetime = await waitForLifetime(child, config.serveDurationMs, capturedSignal);
  return finishLifetime(child, config, lifetime);
}

async function recoverLifecycleFailure(
  child: OwnedProcess,
  config: BoundedPreviewConfig,
  error: unknown,
): Promise<BoundedPreviewResult> {
  console.error(`[preview-runner] ERROR: ${error instanceof Error ? error.message : String(error)}`);
  const stopped = await stopChild(child, config.cleanupTimeoutMs);
  const exitCode = stopped.cleanup === "failed" ? EXIT_CLEANUP_FAILURE : EXIT_SERVER_FAILURE;
  return stoppedResult(child, stopped, exitCode, "serving");
}

async function startBoundedPreview(
  config: BoundedPreviewConfig,
  url: string,
  signalCapture: ReturnType<typeof registerSignalCapture>,
): Promise<BoundedPreviewResult> {
  if (!(await portIsAvailable(config.host, config.port))) {
    return processlessResult(EXIT_SERVER_FAILURE, "startup");
  }
  const preSpawnSignal = signalCapture.current();
  if (preSpawnSignal !== null) {
    return processlessResult(signalExitCode(preSpawnSignal), "signal");
  }
  let child: OwnedProcess;
  try {
    child = spawnOwnedProcess(config);
  } catch {
    return processlessResult(EXIT_SERVER_FAILURE, "startup");
  }
  console.log(
    `[preview-runner] pid=${child.pid} url=${url} startup=${config.startupTimeoutMs}ms ` +
      `lifetime=${config.serveDurationMs}ms cleanup=${config.cleanupTimeoutMs}ms`,
  );
  try {
    return await runChildLifecycle(child, config, url, signalCapture.signal);
  } catch (error) {
    return recoverLifecycleFailure(child, config, error);
  }
}

export async function runBoundedPreview(config: BoundedPreviewConfig): Promise<BoundedPreviewResult> {
  validateConfig(config);
  const signalCapture = registerSignalCapture();
  try {
    return await startBoundedPreview(config, loopbackUrl(config.host, config.port), signalCapture);
  } finally {
    signalCapture.remove();
  }
}

function viteExecutable(workingDirectory: string): string {
  const executable = resolve(workingDirectory, "node_modules", ".bin", "vite");
  if (!existsSync(executable)) {
    throw new Error(`Vite executable is missing at ${executable}; run bun install first`);
  }
  return executable;
}

function viteConfig(arguments_: RunnerArguments): BoundedPreviewConfig {
  const workingDirectory = process.cwd();
  return {
    cleanupTimeoutMs: DEFAULT_CLEANUP_TIMEOUT_MS,
    command: [
      viteExecutable(workingDirectory),
      "preview",
      "--host",
      arguments_.host,
      "--port",
      String(arguments_.port),
      "--strictPort",
    ],
    host: arguments_.host,
    port: arguments_.port,
    serveDurationMs: DEFAULT_SERVE_DURATION_MS,
    startupTimeoutMs: DEFAULT_STARTUP_TIMEOUT_MS,
    workingDirectory,
  };
}

async function main(): Promise<number> {
  try {
    const result = await runBoundedPreview(viteConfig(parseArguments(process.argv.slice(2))));
    if (result.exitCode !== 0) {
      console.error(
        `[preview-runner] ERROR: phase=${result.phase} exit=${result.exitCode} ` +
          `child_exit=${result.childExitCode ?? "none"} cleanup=${result.cleanup}`,
      );
    }
    return result.exitCode;
  } catch (error) {
    console.error(`[preview-runner] ERROR: ${error instanceof Error ? error.message : String(error)}`);
    return EXIT_ARGUMENT_FAILURE;
  }
}

if (import.meta.main) {
  process.exitCode = await main();
}
