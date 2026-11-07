import { MissingAuthenticationError } from "../dist/extensions/grc-tools/auth-errors.js";

/**
 * Resolve exactly the same credential sources as a real tool call. Only absent
 * authentication skips an optional smoke; invalid configuration still fails it.
 * @template T
 * @param {string} label
 * @param {() => T | Promise<T>} resolveConfig
 * @returns {Promise<{kind: 'ready', config: T} | {kind: 'unconfigured'}>}
 */
export async function resolveLiveSmokeConfiguration(label, resolveConfig) {
  try {
    return { kind: "ready", config: await resolveConfig() };
  } catch (error) {
    if (!(error instanceof MissingAuthenticationError)) throw error;
    console.log(`Skipping live ${label} smoke test: ${error.message}`);
    return { kind: "unconfigured" };
  }
}
