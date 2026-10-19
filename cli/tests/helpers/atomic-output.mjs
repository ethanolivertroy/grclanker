import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";

const fsPromises = createRequire(import.meta.url)("node:fs/promises");

export const SIMULATED_CRASH = "simulated crash mid-write";

/**
 * Fails the `failAt`-th node:fs/promises writeFile call while `run` executes, the way a full disk or a
 * crash partway through a bundle would. syncBuiltinESMExports makes the dist modules' named imports see
 * the stub, and the original is restored whether or not `run` throws. Resolves to the number of calls.
 */
export async function withWriteFailure(run, { failAt = 3 } = {}) {
  const original = fsPromises.writeFile;
  let calls = 0;
  fsPromises.writeFile = (...args) => {
    calls += 1;
    if (calls === failAt) return Promise.reject(Object.assign(new Error(SIMULATED_CRASH), { code: "EIO" }));
    return original(...args);
  };
  syncBuiltinESMExports();
  try {
    await run();
  } finally {
    fsPromises.writeFile = original;
    syncBuiltinESMExports();
  }
  return calls;
}

/** The entries under `root` that were not there before, so a test can assert a failed write added none. */
export function newEntries(root, before) {
  return readdirSync(root).filter((name) => !before.has(name)).sort();
}

/**
 * Runs an export with a write failing partway through and asserts the export rejects and leaves nothing
 * under the output root: no bundle directory, no archive, and no staging directory.
 */
export async function assertNoPartialBundleOnWriteFailure(root, runExport, { failAt = 3 } = {}) {
  const before = new Set(readdirSync(root));
  let rejection;
  const calls = await withWriteFailure(async () => {
    try {
      await runExport();
    } catch (error) {
      rejection = error;
    }
  }, { failAt });
  assert.ok(calls >= failAt, `the export reached the failing write (${calls} writeFile calls, failing call ${failAt})`);
  assert.ok(rejection instanceof Error, "the export rejects when a write fails");
  assert.deepEqual(newEntries(root, before), [], "a failed export leaves nothing under the output root");
}
