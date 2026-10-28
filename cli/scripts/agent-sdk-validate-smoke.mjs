import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listRegisteredGrcToolNames } from "../dist/agent-sdk/lib/registry.js";
import { classifyGrcToolEffect, isGrcWriteTool } from "../dist/agent-sdk/lib/effects.js";
import { BUNDLED_SKILL_NAMES, WORKFLOW_NAMES } from "../dist/agent-sdk/lib/skills.js";
import { PERSONA_NAMES } from "../dist/agent-sdk/lib/personas.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const agentSdkDir = resolve(scriptDir, "../agent-sdk");
const require = createRequire(import.meta.url);

function resolveAgentSdkBin() {
  try {
    const packageJsonPath = require.resolve("@grok/agent-sdk/package.json");
    const manifest = require(packageJsonPath);
    return { version: manifest.version, bin: resolve(dirname(packageJsonPath), manifest.bin["agent-sdk"]) };
  } catch {
    return undefined;
  }
}

/**
 * Run an `agent-sdk` command and return its stdout.
 *
 * The child's stdout is a temp file, not a pipe: releases before 0.3.0 wrote
 * `info --json` with a bare `process.stdout.write` and then called
 * `process.exit`, so a pipe kept only the first 64 KiB of the tool payload.
 * Writes to a file descriptor complete synchronously on every release.
 */
function runAgentSdk(bin, args, { expectedStatus = 0, env = process.env } = {}) {
  const captureDir = mkdtempSync(join(tmpdir(), "grclanker-agent-sdk-smoke-"));
  const stdoutPath = join(captureDir, "stdout.txt");
  const stdoutFd = openSync(stdoutPath, "w");
  try {
    const result = spawnSync(process.execPath, [bin, ...args, "--dir", agentSdkDir], {
      env,
      stdio: ["ignore", stdoutFd, "inherit"],
      timeout: 60_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, expectedStatus, `agent-sdk ${args[0]} must exit ${expectedStatus}`);
    return readFileSync(stdoutPath, "utf8");
  } finally {
    closeSync(stdoutFd);
    rmSync(captureDir, { recursive: true, force: true });
  }
}

const sdk = resolveAgentSdkBin();
if (!sdk) {
  console.log("Skipping Agent SDK discovery smoke: @grok/agent-sdk is not installed (run npm --prefix cli install).");
  process.exit(0);
}

console.log(`Using @grok/agent-sdk ${sdk.version}`);
assert.equal(sdk.version, require("../package.json").devDependencies["@grok/agent-sdk"], "smoke must use the pinned project SDK");
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
for (const tool of agent.tools) {
  assert.equal(tool.effect, classifyGrcToolEffect(tool.name), `${tool.name} must preserve its declared effect`);
  assert.equal(tool.needsApproval, isGrcWriteTool(tool.name), `${tool.name} must preserve its approval gate`);
}
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

// Exercise the actual SDK request boundary without a model, provider, or installed
// Trestle dependency. A missing executable is a normal read-only check result.
const toolDir = mkdtempSync(join(tmpdir(), "grclanker-agent-sdk-tool-smoke-"));
try {
  const workspace = join(toolDir, "workspace");
  const stateRoot = join(toolDir, "state");
  const grclankerHome = join(toolDir, "grclanker-home");
  mkdirSync(join(workspace, ".trestle"), { recursive: true });
  mkdirSync(join(workspace, "catalogs", "synthetic"), { recursive: true });
  const originalWorkspace = readdirSync(workspace, { recursive: true }).sort();
  const env = {
    // Do not inherit provider credentials or discover an ambient gh login.
    PATH: dirname(process.execPath),
    TMPDIR: tmpdir(),
    GH_CONFIG_DIR: join(toolDir, "gh-config"),
    GRCLANKER_HOME: grclankerHome,
    GRCLANKER_TRESTLE_BIN: join(toolDir, "missing-trestle"),
  };
  const args = ["tool", "call", "oscal_check_trestle", "--input", JSON.stringify({ workspace_dir: workspace }), "--state-root", stateRoot, "--json"];
  const preview = JSON.parse(runAgentSdk(sdk.bin, [...args, "--dry-run"], { env }));
  assert.equal(preview.dryRun, true);
  assert.equal(preview.request.method, "POST");
  assert.deepEqual(preview.request.body.input, { workspace_dir: workspace });
  assert.equal(existsSync(stateRoot), false, "request preview must not create SDK state");

  const called = JSON.parse(runAgentSdk(sdk.bin, args, { env }));
  assert.equal(called.ok, true);
  assert.equal(called.toolName, "oscal_check_trestle");
  assert.equal(called.isError, false);
  const text = called.result.content.filter((part) => part.type === "text").map((part) => part.text).join("\n");
  assert.match(text, /Trestle is not available yet\./);
  assert.match(text, /Workspace:\s+initialized/);
  assert.match(text, /catalog\s+│\s+1/);

  const rejected = JSON.parse(runAgentSdk(sdk.bin, [
    "tool", "call", "oscal_check_trestle", "--input", JSON.stringify({ workspace_dir: [] }), "--state-root", stateRoot, "--json",
  ], { env, expectedStatus: 1 }));
  assert.equal(rejected.ok, false);
  assert.equal(rejected.error, "invalid_tool_input");
  assert.match(rejected.message, /workspace_dir: expected string/);
  assert.deepEqual(readdirSync(workspace, { recursive: true }).sort(), originalWorkspace, "local read must leave workspace unchanged");
  assert.equal(existsSync(grclankerHome), false, "local read must not create persistent grclanker state");
  console.log("ok: local OSCAL tool preview, execution, and schema rejection (no model or provider calls)");
} finally {
  rmSync(toolDir, { recursive: true, force: true });
}
