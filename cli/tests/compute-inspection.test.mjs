import test from "node:test";
import assert from "node:assert/strict";
import { detectComputeBackendStatuses, inspectComputeBackend, isComputeBackendAvailable } from "../dist/pi/compute.js";

test("selected backend inspection never probes unrelated providers", async () => {
  const seen = [];
  await inspectComputeBackend("modal", { toolExists(command) { seen.push(command); return false; }, probe: async () => assert.fail("no daemon probe needed") });
  assert.deepEqual(seen, ["modal"]);
  assert.equal(await isComputeBackendAvailable("host", { probe: async () => assert.fail("host needs no executable") }), true);
});

test("Docker inspection is limited to its binary and daemon and propagates the deadline", async () => {
  const seen = [];
  const status = await inspectComputeBackend("docker", {
    timeoutMs: 123,
    toolExists(command) { assert.equal(command, "docker"); return true; },
    async probe(executable, args, timeout) { seen.push([executable, args, timeout]); return true; },
  });
  assert.equal(status.available, true);
  assert.deepEqual(seen, [["docker", ["info"], 123]]);
});

test("a stuck backend probe returns an unavailable status at its deadline", { timeout: 1_000 }, async () => {
  const status = await inspectComputeBackend("docker", { timeoutMs: 20, toolExists: () => true, probe: () => new Promise(() => {}) });
  assert.equal(status.available, false);
  assert.match(status.detail, /timed out after 20ms/);
});

test("backend listing starts independent probes concurrently", { timeout: 1_000 }, async () => {
  let releaseDocker;
  const docker = new Promise((resolve) => { releaseDocker = resolve; });
  const statuses = await detectComputeBackendStatuses({ timeoutMs: 500, async probe(executable, args) {
    if ((executable === "which" || executable === "where") && args[0] === "docker") await docker;
    if ((executable === "which" || executable === "where") && args[0] === "modal") releaseDocker();
    return true;
  } });
  assert.equal(statuses.find((status) => status.kind === "docker").available, true);
});
