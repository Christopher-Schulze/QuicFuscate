type FixtureMode = "ignore-term" | "ready" | "unready";

interface FixtureArguments {
  host: string;
  mode: FixtureMode;
  port: number;
}

function parseArguments(arguments_: string[]): FixtureArguments {
  const [host, portText, modeText] = arguments_;
  const port = Number(portText);
  if (
    arguments_.length !== 3 ||
    (host !== "127.0.0.1" && host !== "::1") ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    (modeText !== "ready" && modeText !== "unready" && modeText !== "ignore-term")
  ) {
    throw new Error("usage: bounded-preview-server.ts <127.0.0.1|::1> <port> <ready|unready|ignore-term>");
  }
  return { host, mode: modeText, port };
}

async function run(): Promise<void> {
  const arguments_ = parseArguments(process.argv.slice(2));
  const server = Bun.serve({
    hostname: arguments_.host,
    port: arguments_.port,
    fetch(): Response {
      return arguments_.mode === "unready"
        ? new Response("not ready", { status: 503 })
        : new Response("ready", { status: 200 });
    },
  });

  if (arguments_.mode === "ignore-term") {
    process.on("SIGTERM", () => {});
    return;
  }

  const stop = async (): Promise<void> => {
    await server.stop(true);
    process.exitCode = 0;
  };
  process.on("SIGTERM", () => {
    void stop();
  });
}

try {
  await run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
