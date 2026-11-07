import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_TOOLS, parseServerArgs, selectTools } from "./tools.mjs";

const LOADERS = ["grclanker_load_instructions", "grclanker_load_workflow", "grclanker_load_skill", "grclanker_load_reviewer"];

// Argument parsing and selection.
assert.deepEqual(parseServerArgs([], {}), { names: DEFAULT_TOOLS, allowWrites: false });
assert.deepEqual(parseServerArgs([], { GRCLANKER_TOOLS: "kevs_search, kevs_get_epss" }).names, ["kevs_search", "kevs_get_epss"]);
assert.deepEqual(parseServerArgs(["--allow-writes", "a,b", "c"], {}), { names: ["a", "b", "c"], allowWrites: true });
assert.throws(() => parseServerArgs(["--nope"], {}), /Unknown option/);
assert.throws(() => selectTools([]), /at least one/);
assert.throws(() => selectTools(["missing_tool"]), /Unknown grclanker tool/);
assert.throws(() => selectTools(["github_export_audit_bundle"]), /--allow-writes/);
assert.throws(() => selectTools(["nomatch_*"]), /No grclanker tools match/);
const githubReads = selectTools(["github_*"]).map((tool) => tool.name);
assert.ok(githubReads.includes("github_check_access"));
assert.ok(!githubReads.includes("github_export_audit_bundle"));
assert.ok(selectTools(["github_*"], { allowWrites: true }).some((tool) => tool.name === "github_export_audit_bundle"));

/** @param {string[]} args @param {Record<string, string>} [env] */
async function connect(args, env) {
  const client = new Client({ name: "grclanker-claude-code-check", version: "0.1.0" });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./mcp-server.mjs", import.meta.url)), ...args],
    ...(env ? { env: { PATH: process.env.PATH ?? "", ...env } } : {}),
  }));
  return client;
}

function textResult(result) {
  const parsed = CallToolResultSchema.parse(result);
  return { ...parsed, text: parsed.content.filter((item) => item.type === "text").map((item) => item.text).join("\n") };
}

const client = await connect([]);
try {
  assert.match(client.getInstructions() ?? "", /grclanker_load_instructions/);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name), [...DEFAULT_TOOLS, ...LOADERS]);
  assert.equal(tools[0].inputSchema.type, "object");
  assert.equal(tools[0].annotations?.readOnlyHint, true);

  const invalid = textResult(await client.callTool({ name: "kevs_get_epss", arguments: { cve_ids: [] } }));
  assert.equal(invalid.isError, true);
  assert.match(invalid.text, /requires at least one CVE ID/);
  for (const name of ["github_export_audit_bundle", "oscal_check_trestle", "missing_tool"]) {
    const denied = textResult(await client.callTool({ name, arguments: {} }));
    assert.equal(denied.isError, true);
    assert.match(denied.text, /not enabled/);
  }

  const role = textResult(await client.callTool({ name: "grclanker_load_instructions", arguments: {} }));
  assert.match(role.text, /Claude Code runtime/);
  assert.match(textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "audit" } })).text, /Compliance Audit/);
  assert.equal(textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "nope" } })).isError, true);
  assert.notEqual(textResult(await client.callTool({ name: "grclanker_load_skill", arguments: {} })).isError, true);
  assert.notEqual(textResult(await client.callTool({ name: "grclanker_load_reviewer", arguments: { name: "verifier" } })).isError, true);

  const { prompts } = await client.listPrompts();
  assert.deepEqual(prompts.map((prompt) => prompt.name), ["investigate", "audit", "assess", "validate"]);
  const audit = await client.getPrompt({ name: "audit", arguments: { subject: "Example SaaS against SOC 2" } });
  const auditText = audit.messages[0].content.text;
  assert.match(auditText, /Subject: Example SaaS against SOC 2/);
  assert.match(auditText, /Claude Code runtime/);
  assert.doesNotMatch(auditText, /\$ARGUMENTS/);
} finally {
  await client.close();
}

const fixture = await mkdtemp(join(tmpdir(), "grclanker-claude-code-check-"));
try {
  const workspace = join(fixture, "workspace");
  await mkdir(join(workspace, ".trestle"), { recursive: true });
  await mkdir(join(workspace, "catalogs", "sample-catalog"), { recursive: true });
  const inspector = await connect(["oscal_check_trestle"], { GRCLANKER_TRESTLE_BIN: join(fixture, "unavailable-trestle") });
  try {
    const result = textResult(await inspector.callTool({ name: "oscal_check_trestle", arguments: { workspace_dir: workspace } }));
    assert.notEqual(result.isError, true);
    assert.ok(result.text.includes(`Workspace dir: ${workspace}`));
    assert.match(result.text, /Trestle is not available yet/);
    const denied = textResult(await inspector.callTool({ name: "oscal_init_workspace", arguments: { workspace_dir: join(fixture, "forbidden") } }));
    assert.equal(denied.isError, true);
    await assert.rejects(stat(join(fixture, "forbidden")), { code: "ENOENT" });
  } finally {
    await inspector.close();
  }

  const writer = await connect(["--allow-writes", "oscal_check_trestle,oscal_init_workspace"]);
  try {
    const { tools } = await writer.listTools();
    const init = tools.find((tool) => tool.name === "oscal_init_workspace");
    assert.ok(init, "--allow-writes exposes the named writer");
    assert.equal(init.annotations?.readOnlyHint, false);
  } finally {
    await writer.close();
  }
  console.log("Claude Code MCP server: selection and patterns, write opt-in, discovery, instructions, loaders, workflow prompts, input validation, allowlist, and an OSCAL inspection passed. No credentials or network calls used.");
} finally {
  await rm(fixture, { recursive: true, force: true });
}
