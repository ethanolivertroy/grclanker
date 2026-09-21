import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
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

function runAgentSdk(bin, args) {
  return execFileSync(process.execPath, [bin, ...args, "--dir", agentSdkDir], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
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

const readTools = agent.tools.filter((tool) => tool.effect === "read").length;
console.log(
  `ok: discovered ${agent.tools.length} server tools (${readTools} read-only), ${agent.skills.length} skills, ${agent.subagents.length} subagents, ${agent.instructions.chars} instruction chars`,
);
