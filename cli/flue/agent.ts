'use agent';
/**
 * The grclanker Flue agent module.
 *
 * Run it with the official CLI from the `cli/` directory:
 *
 *   npx flue run flue/agent.ts --message "Is BoringCrypto FIPS validated?"
 *
 * or through the bundled runner (`grclanker flue run ...`), which boots the
 * same function with Flue's `start()` API. Every exported capitalized function
 * in a `'use agent'` module is an agent, so this module exports exactly one.
 */
import { fileURLToPath } from "node:url";
import { useModel, useSandbox, useSkill, useSubagent, useTool } from "@flue/runtime";
import { local } from "@flue/runtime/node";
import { loadGrclankerFlueAgentOptions, renderGrclankerAgent, type GrclankerFlueAgentOptions } from "./render.js";

let cachedOptions: GrclankerFlueAgentOptions | undefined;

function getAgentOptions(): GrclankerFlueAgentOptions {
  cachedOptions ??= loadGrclankerFlueAgentOptions({
    currentDir: fileURLToPath(new URL(".", import.meta.url)),
    env: process.env,
    cwd: process.cwd(),
    createLocalSandbox: local,
  });
  return cachedOptions;
}

/** Load and validate the agent configuration eagerly (used by the runner to fail before the runtime starts). */
export function prepareGrclankerAgent(): GrclankerFlueAgentOptions {
  return getAgentOptions();
}

export function Grclanker(): string {
  return renderGrclankerAgent({ useModel, useSandbox, useSkill, useSubagent, useTool }, getAgentOptions());
}

Grclanker.agentName = "grclanker";
