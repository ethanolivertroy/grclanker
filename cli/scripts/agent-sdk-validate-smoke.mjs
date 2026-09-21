import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listRegisteredGrcToolNames } from "../dist/agent-sdk/lib/registry.js";
import { BUNDLED_SKILL_NAMES, WORKFLOW_NAMES } from "../dist/agent-sdk/lib/skills.js";
import { PERSONA_NAMES } from "../dist/agent-sdk/lib/personas.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const agentSdkDir = resolve(scriptDir, "../agent-sdk");
const require = createRequire(import.meta.url);

function resolveAgentSdkBin() {
  try {
    const packageJsonPath = require.resolve("@cursor/july/package.json");
    const manifest = require(packageJsonPath);
    return { version: manifest.version, bin: resolve(dirname(packageJsonPath), manifest.bin["agent-sdk"]) };
  } catch {
    return undefined;
  }
}

/**
 * Run an `agent-sdk` command and return its stdout.
 *
 * The child's stdout is a temp file, not a pipe: `agent-sdk info --json`
 * writes with a bare `process.stdout.write` and then calls `process.exit`,
 * so with a pipe only the first 64 KiB survives and the 107-tool payload is
 * truncated mid-JSON. Writes to a file descriptor complete synchronously.
 */
function runAgentSdk(bin, args) {
  const captureDir = mkdtempSync(join(tmpdir(), "grclanker-agent-sdk-smoke-"));
  const stdoutPath = join(captureDir, "stdout.txt");
  const stdoutFd = openSync(stdoutPath, "w");
  try {
    execFileSync(process.execPath, [bin, ...args, "--dir", agentSdkDir], {
      stdio: ["ignore", stdoutFd, "inherit"],
    });
    return readFileSync(stdoutPath, "utf8");
  } finally {
    closeSync(stdoutFd);
    rmSync(captureDir, { recursive: true, force: true });
  }
}

const sdk = resolveAgentSdkBin();
if (!sdk) {
  console.log("Skipping Agent SDK discovery smoke: @cursor/july is not installed (run npm --prefix cli install).");
  process.exit(0);
}

console.log(`Using @cursor/july ${sdk.version}`);
process.stdout.write(runAgentSdk(sdk.bin, ["validate"]));

const info = JSON.parse(runAgentSdk(sdk.bin, ["info", "--json"]));
const agent = Array.isArray(info.agents) ? info.agents[0] : info;
const expectedTools = [...listRegisteredGrcToolNames()].sort();
const discoveredTools = agent.tools.map((tool) => tool.name).sort();

assert.equal(agent.name, "grclanker");
assert.equal(agent.runtime, "local");
assert.deepEqual(agent.diagnostics ?? [], []);
assert.deepEqual(discoveredTools, expectedTools);
assert.ok(agent.tools.every((tool) => tool.execution === "server"));
assert.ok(agent.tools.every((tool) => tool.inputSchema?.type === "object"));
assert.deepEqual(
  agent.skills.map((skill) => skill.name).sort(),
  [...WORKFLOW_NAMES, ...BUNDLED_SKILL_NAMES].sort(),
);
assert.deepEqual(agent.subagents.map((subagent) => subagent.name).sort(), [...PERSONA_NAMES].sort());
assert.ok(agent.instructions?.chars > 0, "instructions must be discovered");

const readTools = agent.tools.filter((tool) => tool.effect === "read");
const approvalTools = agent.tools.filter((tool) => tool.needsApproval === true);
assert.ok(readTools.every((tool) => tool.needsApproval === false), "read-only tools must not require approval");
assert.equal(approvalTools.length, agent.tools.length - readTools.length, "every writer must require approval");

console.log(
  `ok: discovered ${agent.tools.length} server tools (${readTools.length} read-only, ${approvalTools.length} approval-gated writers), ${agent.skills.length} skills, ${agent.subagents.length} subagents, ${agent.instructions.chars} instruction chars`,
);
