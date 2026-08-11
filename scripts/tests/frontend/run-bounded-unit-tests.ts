import { existsSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_TIMEOUT_MS = 600_000;
const MAX_TIMEOUT_MS = 3_600_000;
const HEARTBEAT_INTERVAL_MS = 60_000;
const MAX_TRANSCRIPT_BYTES = 1_048_576;
const TIMEOUT_ENVIRONMENT_VARIABLE = "QF_FRONTEND_UNIT_TIMEOUT_MS";

interface RunnerArguments {
  minimumFiles: number;
  minimumTests: number;
  vitestArguments: string[];
}

interface TestInventory {
  files: number;
  tests: number;
}

type ForwardedSignal = "SIGINT" | "SIGTERM";

interface ProcessState {
  finished: boolean;
  timedOut: boolean;
  forwardedSignal: ForwardedSignal | null;
}

interface KillableProcess {
  kill(signal?: string | number): void;
}

function parsePositiveInteger(value: string, name: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be a positive integer, received ${JSON.stringify(value)}`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive safe integer, received ${JSON.stringify(value)}`);
  }
  return parsed;
}

function parseArguments(arguments_: string[]): RunnerArguments {
  let minimumFiles: number | null = null;
  let minimumTests: number | null = null;
  const vitestArguments: string[] = [];

  for (const argument of arguments_) {
    if (argument.startsWith("--minimum-files=")) {
      minimumFiles = parsePositiveInteger(argument.slice("--minimum-files=".length), "--minimum-files");
      continue;
    }
    if (argument.startsWith("--minimum-tests=")) {
      minimumTests = parsePositiveInteger(argument.slice("--minimum-tests=".length), "--minimum-tests");
      continue;
    }
    vitestArguments.push(argument);
  }

  if (minimumFiles === null || minimumTests === null) {
    throw new Error("both --minimum-files and --minimum-tests are required");
  }

  return { minimumFiles, minimumTests, vitestArguments };
}

function configuredTimeout(): number {
  const configured = process.env[TIMEOUT_ENVIRONMENT_VARIABLE];
  const timeout = configured === undefined
    ? DEFAULT_TIMEOUT_MS
    : parsePositiveInteger(configured, TIMEOUT_ENVIRONMENT_VARIABLE);
  if (timeout > MAX_TIMEOUT_MS) {
    throw new Error(`${TIMEOUT_ENVIRONMENT_VARIABLE} must not exceed ${MAX_TIMEOUT_MS}`);
  }
  return timeout;
}

function appendBounded(transcript: string, chunk: Uint8Array): string {
  const updated = transcript + new TextDecoder().decode(chunk);
  return updated.length <= MAX_TRANSCRIPT_BYTES
    ? updated
    : updated.slice(updated.length - MAX_TRANSCRIPT_BYTES);
}

async function forwardOutput(
  stream: ReadableStream<Uint8Array>,
  destination: typeof process.stdout,
): Promise<string> {
  const reader = stream.getReader();
  let transcript = "";

  while (true) {
    const result = await reader.read();
    if (result.done) {
      return transcript;
    }
    destination.write(result.value);
    transcript = appendBounded(transcript, result.value);
  }
}

function lastSummaryCount(transcript: string, label: "Test Files" | "Tests"): number | null {
  const withoutAnsi = transcript.replace(/\u001B\[[0-9;]*m/g, "");
  const pattern = new RegExp(`${label}\\s+(\\d+)\\s+passed(?:\\s+\\((\\d+)\\))?`, "g");
  let count: number | null = null;

  for (const match of withoutAnsi.matchAll(pattern)) {
    count = Number(match[2] ?? match[1]);
  }
  return count;
}

function parseInventory(transcript: string): TestInventory | null {
  const files = lastSummaryCount(transcript, "Test Files");
  const tests = lastSummaryCount(transcript, "Tests");
  return files === null || tests === null ? null : { files, tests };
}

function verifyInventory(inventory: TestInventory, expected: RunnerArguments): string | null {
  if (inventory.files < expected.minimumFiles || inventory.tests < expected.minimumTests) {
    return `test inventory shrank to ${inventory.files} files/${inventory.tests} tests; expected at least ${expected.minimumFiles}/${expected.minimumTests}`;
  }
  return null;
}

function vitestExecutable(): string {
  const executable = resolve(process.cwd(), "node_modules", ".bin", "vitest");
  if (!existsSync(executable)) {
    throw new Error(`Vitest executable is missing at ${executable}; run bun install first`);
  }
  return executable;
}

function registerSignalForwarding(child: KillableProcess, state: ProcessState): () => void {
  const forward = (signal: ForwardedSignal): void => {
    state.forwardedSignal = signal;
    if (!state.finished) {
      child.kill(signal);
    }
  };
  const interrupt = (): void => forward("SIGINT");
  const terminate = (): void => forward("SIGTERM");
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", terminate);
  return () => {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", terminate);
  };
}

function startDeadline(
  child: KillableProcess,
  state: ProcessState,
  command: string[],
  timeoutMs: number,
): ReturnType<typeof setTimeout> {
  return setTimeout(() => {
    if (state.finished) {
      return;
    }
    state.timedOut = true;
    console.error(
      `\n[unit-runner] ERROR: Vitest exceeded ${timeoutMs}ms and will be killed. ` +
        "A worker startup, open handle, or teardown path did not terminate.",
    );
    console.error(`[unit-runner] command: ${command.join(" ")}`);
    console.error(
      "[unit-runner] diagnostic rerun: vitest run --config vitest.config.ts " +
        "--reporter=default --reporter=hanging-process",
    );
    child.kill("SIGKILL");
  }, timeoutMs);
}

function startHeartbeat(state: ProcessState, startedAt: number, timeoutMs: number): ReturnType<typeof setInterval> {
  return setInterval(() => {
    if (!state.finished) {
      const elapsedSeconds = Math.floor((Date.now() - startedAt) / 1_000);
      console.error(`[unit-runner] still running after ${elapsedSeconds}s; hard limit is ${timeoutMs / 1_000}s`);
    }
  }, HEARTBEAT_INTERVAL_MS);
}

function successfulResult(transcript: string, arguments_: RunnerArguments): number {
  if (arguments_.vitestArguments.length > 0) {
    console.log("[unit-runner] filtered/overridden invocation completed; full-inventory check skipped");
    return 0;
  }

  const inventory = parseInventory(transcript);
  if (inventory === null) {
    console.error("[unit-runner] ERROR: Vitest exited successfully without a parseable test inventory");
    return 1;
  }

  const inventoryFailure = verifyInventory(inventory, arguments_);
  if (inventoryFailure !== null) {
    console.error(`[unit-runner] ERROR: ${inventoryFailure}`);
    return 1;
  }

  console.log(`[unit-runner] inventory verified: ${inventory.files} files/${inventory.tests} tests`);
  return 0;
}

function processResult(exitCode: number, state: ProcessState): number | null {
  if (state.timedOut) {
    return 124;
  }
  if (state.forwardedSignal !== null) {
    return state.forwardedSignal === "SIGINT" ? 130 : 143;
  }
  return exitCode === 0 ? null : exitCode;
}

function spawnVitest(command: string[], state: ProcessState) {
  return Bun.spawn({
    cmd: command,
    cwd: process.cwd(),
    env: process.env,
    stdin: "inherit",
    stdout: "pipe",
    stderr: "pipe",
    onExit() {
      state.finished = true;
    },
  });
}

function stopProcessOwners(
  timeout: ReturnType<typeof setTimeout>,
  heartbeat: ReturnType<typeof setInterval>,
  removeSignalHandlers: () => void,
): void {
  clearTimeout(timeout);
  clearInterval(heartbeat);
  removeSignalHandlers();
}

async function run(): Promise<number> {
  const arguments_ = parseArguments(process.argv.slice(2));
  const timeoutMs = configuredTimeout();
  const command = [vitestExecutable(), "run", "--config", "vitest.config.ts", ...arguments_.vitestArguments];
  const state: ProcessState = { finished: false, timedOut: false, forwardedSignal: null };

  console.log(
    `[unit-runner] pool=threads workers=1 timeout=${timeoutMs}ms inventory>=${arguments_.minimumFiles}/${arguments_.minimumTests}`,
  );

  const child = spawnVitest(command, state);
  const removeSignalHandlers = registerSignalForwarding(child, state);
  const timeout = startDeadline(child, state, command, timeoutMs);
  const heartbeat = startHeartbeat(state, Date.now(), timeoutMs);

  const stdout = forwardOutput(child.stdout, process.stdout);
  const stderr = forwardOutput(child.stderr, process.stderr);
  const exitCode = await child.exited;
  const [stdoutTranscript, stderrTranscript] = await Promise.all([stdout, stderr]);

  stopProcessOwners(timeout, heartbeat, removeSignalHandlers);

  const terminalResult = processResult(exitCode, state);
  return terminalResult ?? successfulResult(stdoutTranscript + stderrTranscript, arguments_);
}

try {
  process.exitCode = await run();
} catch (error) {
  console.error(`[unit-runner] ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
