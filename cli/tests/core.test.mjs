import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Type } from "typebox";
import { disableArgumentCoercion } from "../dist/core/domain-tools.js";
import { buildGrclankerInstructions } from "../dist/core/instructions.js";
import { listRegisteredGrcToolNames } from "../dist/core/registry.js";
import { executeGrcTool, executeRegisteredGrcTool } from "../dist/core/tools.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const runner = resolve(cliRoot, "dist/core/cli.js");

function invoke(args, input = "", cwd = cliRoot, env = process.env) {
  return spawnSync(process.execPath, [runner, ...args], { cwd, input, env, encoding: "utf8" });
}

test("shared runtime loads transitively when provider adapters and SDKs are unavailable", () => {
  const probe = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import assert from "node:assert/strict";
    import { registerHooks } from "node:module";
    import { pathToFileURL } from "node:url";
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (/^@(?:grok\\/agent-sdk|cursor\\/bdk|openai\\/agents)(?:$|\\/)/.test(specifier)) {
          throw new Error("Provider SDK must not load: " + specifier);
        }
        const resolved = nextResolve(specifier, context);
        if (/\\/dist\\/(?:adapters|agent-sdk|openai-agents)\\//.test(resolved.url)) {
          throw new Error("Provider adapter must not load: " + resolved.url);
        }
        return resolved;
      },
    });
    // Verify the loader is active before importing the runtime's complete graph.
    await assert.rejects(import("@grok/agent-sdk"), /Provider SDK must not load/);
    const runtimeRoot = pathToFileURL(process.cwd() + "/dist/core/");
    for (const name of ["registry", "tools", "schema", "effects", "results", "instructions", "skills", "personas", "redact", "cli"]) {
      await import(new URL(name + ".js", runtimeRoot));
    }
    const { collectRegisteredGrcTools } = await import(new URL("registry.js", runtimeRoot));
    assert.ok(collectRegisteredGrcTools().length > 0);
    process.stdout.write("neutral runtime loaded");
  `], { cwd: cliRoot, encoding: "utf8" });
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout, "neutral runtime loaded");
  assert.deepEqual(listRegisteredGrcToolNames(), getRegisteredToolSummaries().filter((tool) => tool.kind === "domain").map((tool) => tool.name));
  const prompt = buildGrclankerInstructions("Only the host's allowlisted tools are available.");
  assert.match(prompt, /Governance, Risk, and Compliance/);
  assert.match(prompt, /host's allowlisted tools/);
  assert.doesNotMatch(prompt, /Cursor|agent-sdk/);
});

test("shared executor validates before execution, redacts failures, and drops internal details", async () => {
  let executions = 0;
  const tool = disableArgumentCoercion({
    name: "sample_check_access",
    label: "Sample",
    description: "A detached tool.",
    parameters: Type.Object({ count: Type.Integer(), api_token: Type.String() }),
    async execute(_id, input) {
      executions += 1;
      return { content: [{ type: "text", text: `Rejected ${input.api_token}` }], isError: true, details: { api_token: input.api_token } };
    },
  });
  const invalid = await executeGrcTool(tool, { count: "4", api_token: "sensitive-test-token" });
  assert.equal(invalid.isError, true);
  assert.equal(executions, 0);
  assert.doesNotMatch(JSON.stringify(invalid), /sensitive-test-token/);
  const result = await executeGrcTool(tool, { count: 4, api_token: "sensitive-test-token" });
  assert.equal(executions, 1);
  assert.equal(result.isError, true);
  assert.doesNotMatch(JSON.stringify(result), /sensitive-test-token/);
  assert.equal("details" in result, false);
});

test("cancelled execution starts neither argument preparation nor tool effects", async () => {
  const controller = new AbortController();
  controller.abort(new Error("Cancelled request for sensitive-test-token"));
  let preparations = 0;
  let effects = 0;
  const tool = {
    name: "sample_search_items",
    label: "Sample",
    description: "A cancellable tool.",
    parameters: Type.Object({ api_token: Type.String() }),
    prepareArguments(input) {
      preparations += 1;
      return input;
    },
    async execute() {
      effects += 1;
      return { content: [{ type: "text", text: "An effect occurred." }] };
    },
  };
  const result = await executeGrcTool(tool, { api_token: "sensitive-test-token" }, { signal: controller.signal });
  assert.equal(result.isError, true);
  assert.equal(preparations, 0);
  assert.equal(effects, 0);
  assert.match(result.content[0].text, /Cancelled request/);
  assert.doesNotMatch(result.content[0].text, /sensitive-test-token/);

  // Cancellation raised by synchronous preparation must also stop the effect.
  const preparingController = new AbortController();
  tool.prepareArguments = (input) => {
    preparingController.abort(new Error("Stopped during argument preparation"));
    return input;
  };
  const stopped = await executeGrcTool(tool, { api_token: "sensitive-test-token" }, { signal: preparingController.signal });
  assert.equal(stopped.isError, true);
  assert.equal(effects, 0);
  assert.match(stopped.content[0].text, /Stopped during argument preparation/);
});

test("JSON subprocess runner executes a real offline setup check without changing the workspace", () => {
  const cwd = mkdtempSync(resolve(tmpdir(), "grclanker-offline-tool-"));
  try {
    const result = invoke(["call", "oscal_check_trestle"], JSON.stringify({ workspace_dir: cwd }), cwd, {
      ...process.env,
      GRCLANKER_TRESTLE_BIN: resolve(cwd, "trestle-deliberately-absent"),
    });
    assert.equal(result.status, 0, result.stderr);
    const envelope = JSON.parse(result.stdout);
    assert.equal(envelope.isError, undefined);
    assert.equal("details" in envelope, false);
    assert.match(envelope.content[0].text, /Trestle is not available yet/);
    assert.match(envelope.content[0].text, /Workspace: +not initialized/);
    assert.deepEqual(readdirSync(cwd), []);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("JSON subprocess runner enforces its stdin byte limit without echoing sensitive input", () => {
  const limit = 1024 * 1024;
  const prefix = '{"api_token":"sensitive-test-token","padding":"';
  const suffix = '"}';
  const atLimit = prefix + "x".repeat(limit - Buffer.byteLength(prefix + suffix)) + suffix;
  const accepted = invoke(["call", "oscal_init_workspace"], atLimit);
  assert.equal(accepted.status, 1);
  assert.match(JSON.parse(accepted.stdout).content[0].text, /requires explicit host authorization/);

  // A UTF-8 payload below one million characters still exceeds the byte limit.
  const overLimit = JSON.stringify({ api_token: "sensitive-test-token", padding: "\u{1F512}".repeat(limit / 4) });
  assert.ok(overLimit.length < limit);
  assert.ok(Buffer.byteLength(overLimit) > limit);
  const rejected = invoke(["call", "oscal_init_workspace"], overLimit);
  assert.equal(rejected.status, 1);
  assert.match(JSON.parse(rejected.stdout).content[0].text, /exceeds the 1 MiB limit/);
  assert.doesNotMatch(accepted.stdout + accepted.stderr + rejected.stdout + rejected.stderr, /sensitive-test-token/);
});

test("named execution denies writers before parameter validation or filesystem effects", async () => {
  const result = await executeRegisteredGrcTool("oscal_init_workspace", {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /requires explicit host authorization/);
  const unknown = await executeRegisteredGrcTool("missing_tool", {});
  assert.equal(unknown.isError, true);
  assert.match(unknown.content[0].text, /Unknown grclanker tool/);
});

test("JSON subprocess runner lists schemas and refuses writes and malformed input", () => {
  const list = invoke(["list", "cmvp_search_modules", "oscal_init_workspace"]);
  assert.equal(list.status, 0, list.stderr);
  const tools = JSON.parse(list.stdout);
  assert.equal(tools.length, 2);
  assert.equal(tools[0].name, "cmvp_search_modules");
  assert.equal(tools[0].inputSchema.type, "object");
  assert.equal(tools[0].needsApproval, false);
  assert.equal(tools[1].needsApproval, true);

  const cwd = mkdtempSync(resolve(tmpdir(), "grclanker-runtime-"));
  try {
    const denied = invoke(["call", "oscal_init_workspace"], "{}", cwd);
    assert.equal(denied.status, 1);
    assert.match(JSON.parse(denied.stdout).content[0].text, /requires explicit host authorization/);
    assert.deepEqual(readdirSync(cwd), []);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }

  const invalid = invoke(["call", "cmvp_search_modules"], '{"api_token":"sensitive-test-token"');
  assert.equal(invalid.status, 1);
  assert.doesNotMatch(invalid.stdout + invalid.stderr, /sensitive-test-token/);
  assert.match(JSON.parse(invalid.stdout).content[0].text, /Invalid JSON/);
  const nonObject = invoke(["call", "cmvp_search_modules"], "[]");
  assert.equal(nonObject.status, 1);
  assert.match(JSON.parse(nonObject.stdout).content[0].text, /must be a JSON object/);
});
