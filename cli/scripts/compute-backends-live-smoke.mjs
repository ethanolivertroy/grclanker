import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { detectComputeBackendStatuses, getComputeBackendShipState } from "../dist/pi/compute.js";

const cliEntrypoint = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

function log(message) {
  process.stdout.write(`${message}\n`);
}

function runCli(args) {
  const result = spawnSync(process.execPath, [cliEntrypoint, ...args], {
    encoding: "utf8",
    env: process.env,
    timeout: 10 * 60 * 1000,
  });
  return {
    status: result.status,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
  };
}

const requested = process.env.GRCLANKER_LIVE_BACKENDS
  ?.split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const candidates = detectComputeBackendStatuses()
  .filter((status) => status.kind !== "host")
  .filter((status) => status.kind !== "sandbox-runtime" || requested?.includes("sandbox-runtime"))
  .filter((status) => getComputeBackendShipState(status.kind) !== "stub")
  .filter((status) => status.available)
  .filter((status) => !requested || requested.includes(status.kind));

if (candidates.length === 0) {
  log(
    "Skipping live compute backend smoke test: no non-host backend has its binaries or credentials present (docker daemon, prlctl, modal + MODAL_TOKEN_*, RUNPOD_API_KEY + RUNPOD_ENDPOINT_ID or RUNPOD_POD_ID). Set GRCLANKER_LIVE_BACKENDS=sandbox-runtime to include the local sandbox.",
  );
  process.exit(0);
}

const doctor = runCli(["env", "doctor"]);
log(doctor.output.trimEnd());
if (doctor.status !== 0) {
  process.stderr.write("grclanker env doctor failed.\n");
  process.exit(1);
}

let failures = 0;
for (const candidate of candidates) {
  log(`\n=== env smoke-test --backend ${candidate.kind} ===`);
  const smoke = runCli(["env", "smoke-test", "--backend", candidate.kind, "--timeout", "600"]);
  log(smoke.output.trimEnd());
  if (smoke.status !== 0) {
    failures += 1;
    process.stderr.write(`Live smoke test failed for ${candidate.kind}.\n`);
  }
}

if (failures > 0) {
  process.exit(1);
}

log(`\nLive compute backend smoke test passed for: ${candidates.map((candidate) => candidate.kind).join(", ")}.`);
