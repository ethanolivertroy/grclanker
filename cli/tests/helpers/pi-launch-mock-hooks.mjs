/**
 * Node module customization hooks that replace the embedded Pi entry point with
 * a recording stub, but only for the dynamic import inside `dist/pi/launch.js`.
 * Other modules keep the real package, so `dist/index.js` can run its normal
 * command dispatch end to end without starting an interactive Pi session.
 *
 * Preload from a child process with:
 *
 *   node --import <data URL that calls register(<this file>)> dist/index.js audit --compute docker
 *
 * The stub's `main(args)` writes `{ args, computeBackend, computeOverride }` as
 * JSON to the path in `GRCLANKER_TEST_PI_LAUNCH_RECORD`.
 */
const PI_SPECIFIER = "@earendil-works/pi-coding-agent";
const MOCK_URL = "grclanker-pi-launch-mock:main";

const MOCK_SOURCE = [
  'import { writeFileSync } from "node:fs";',
  "export async function main(args) {",
  "  writeFileSync(process.env.GRCLANKER_TEST_PI_LAUNCH_RECORD, JSON.stringify({",
  "    args,",
  "    computeBackend: process.env.GRCLANKER_COMPUTE_BACKEND ?? null,",
  "    computeOverride: process.env.GRCLANKER_COMPUTE_BACKEND_OVERRIDE ?? null,",
  "  }));",
  "}",
  "",
].join("\n");

export async function resolve(specifier, context, nextResolve) {
  if (specifier === PI_SPECIFIER && context.parentURL?.endsWith("/dist/pi/launch.js")) {
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
