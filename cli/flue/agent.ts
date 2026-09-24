'use agent';
/**
 * The grclanker Flue agent module.
 *
 * Run it with the official CLI from the `cli/` directory (the `@flue/cli`
 * devDependency must be installed next to `@flue/runtime`):
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
import { registerGrclankerProviders } from "./providers.js";
import { loadGrclankerFlueAgentOptions, renderGrclankerAgent, type GrclankerFlueAgentOptions } from "./render.js";

// Custom providers (the local-first Ollama entry from `grclanker setup`) must
// be registered at module scope so `flue run`, which loads only this module,
// resolves them too. The Flue Models guide prescribes exactly this placement.
const customProviders = registerGrclankerProviders({ env: process.env });
for (const warning of customProviders.warnings) console.warn(`grclanker flue: ${warning}`);

let cachedOptions: GrclankerFlueAgentOptions | undefined;

function getAgentOptions(): GrclankerFlueAgentOptions {
  cachedOptions ??= loadGrclankerFlueAgentOptions({
    currentDir: fileURLToPath(new URL(".", import.meta.url)),
    env: process.env,
    cwd: process.cwd(),
    createLocalSandbox: local,
    customProviderIds: customProviders.providerIds,
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
