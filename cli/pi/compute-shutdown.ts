import { resolveComputeBackend } from "./compute.js";
import { teardownComputeSessions } from "./compute-sessions.js";
import { resetSandboxRuntime } from "./sandbox.js";
import type { GrclankerSettings } from "./settings.js";

export type ComputeShutdownHooks = {
  resetSandboxRuntime?: () => Promise<void>;
};

// Runs on session_shutdown. The registry teardown is unconditional because the preferred
// backend in settings can differ from the backend a session actually staged (per-run
// --compute override), and process.on("exit") never fires on SIGTERM or SIGINT.
export async function shutdownComputeSessions(
  settings: GrclankerSettings,
  hooks: ComputeShutdownHooks = {},
): Promise<void> {
  try {
    if (resolveComputeBackend(settings) === "sandbox-runtime") {
      await (hooks.resetSandboxRuntime ?? resetSandboxRuntime)();
    }
  } finally {
    await teardownComputeSessions();
  }
}
