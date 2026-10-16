/**
 * Node module customization hooks that replace `@anthropic-ai/sandbox-runtime` with a stub, but
 * only for the import inside `dist/pi/sandbox.js`. The stub runs commands unwrapped and, like the
 * real network bridge, holds the event loop open from `initialize()` until `reset()`, so a CLI
 * command that never resets the sandbox never exits.
 *
 * Preload from a child process with:
 *
 *   node --import <data URL that calls register(<this file>)> dist/index.js env exec --backend sandbox-runtime -- true
 *
 * The stub appends `initialize` and `reset` lines to the path in
 * `GRCLANKER_TEST_SANDBOX_RUNTIME_RECORD`. When `GRCLANKER_TEST_SANDBOX_RUNTIME_RESET_ERROR` is set,
 * `reset()` releases the bridge and then rejects with that message.
 */
const SANDBOX_RUNTIME_SPECIFIER = "@anthropic-ai/sandbox-runtime";
const MOCK_URL = "grclanker-sandbox-runtime-mock:index";

const MOCK_SOURCE = [
  'import { appendFileSync } from "node:fs";',
  "let bridge;",
  "const record = (event) => appendFileSync(process.env.GRCLANKER_TEST_SANDBOX_RUNTIME_RECORD, `${event}\\n`);",
  "export const SandboxManager = {",
  "  async initialize() {",
  '    record("initialize");',
  "    bridge = setInterval(() => {}, 60_000);",
  "  },",
  "  async wrapWithSandbox(command) {",
  "    return command;",
  "  },",
  "  cleanupAfterCommand() {},",
  "  async reset() {",
  '    record("reset");',
  "    clearInterval(bridge);",
  "    const resetError = process.env.GRCLANKER_TEST_SANDBOX_RUNTIME_RESET_ERROR;",
  "    if (resetError) throw new Error(resetError);",
  "  },",
  "};",
  "",
].join("\n");

export async function resolve(specifier, context, nextResolve) {
  if (specifier === SANDBOX_RUNTIME_SPECIFIER && context.parentURL?.endsWith("/dist/pi/sandbox.js")) {
    return { url: MOCK_URL, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url !== MOCK_URL) {
    return nextLoad(url, context);
  }
  return { format: "module", shortCircuit: true, source: MOCK_SOURCE };
}
